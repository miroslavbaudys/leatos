//! virtio-blk (PCI) driver on top of `virtio_drivers::VirtIOBlk`: the
//! store disk in QEMU (docs/config-and-storage.md §7).
//!
//! **One request in flight, owned by the driver.** A request's buffers
//! (request header, data, status byte) are heap allocations moved into
//! [`VirtioBlk::inflight`] when the request is submitted and moved out only
//! when the device reports it done. Moving the driver or dropping an async
//! caller mid-request therefore never frees or moves memory the device may
//! still access; the next submit returns [`Error::Busy`] until that request
//! completed ([`VirtioBlk::poll`]). The `unsafe` in this file is exactly
//! the submit/complete pairs of that protocol.
//!
//! **Never blocks the datapath:** callers submit, then wait with
//! [`VirtioBlk::wait`], which yields to the executor between polls (the
//! store runs in the services task, `Priority::Service`). Exception:
//! `virtio-drivers` offers flush only as a blocking call, so
//! [`VirtioBlk::flush`] spins until the device answers (one per record
//! header/payload; QEMU answers in milliseconds).
//!
//! No interrupts: completions are polled.

use crate::mm::dma::DmaHal;
use crate::pci::{Pci, PciDevice};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use virtio_drivers::device::blk::{BlkReq, BlkResp, RespStatus, SECTOR_SIZE, VirtIOBlk};
use virtio_drivers::transport::pci::PciTransport;

type Raw = VirtIOBlk<DmaHal, PciTransport>;

/// Largest single request, in sectors (64 KiB). Callers split larger I/O.
pub const MAX_REQUEST_SECTORS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Transport,
    Device,
    /// A previous request has not completed yet.
    Busy,
    /// Request outside the disk, empty, larger than
    /// [`MAX_REQUEST_SECTORS`], or not whole sectors.
    BadRequest,
    ReadOnly,
    /// The device reported an error status.
    Io,
}

struct Inflight {
    token: u16,
    write: bool,
    req: Box<BlkReq>,
    resp: Box<BlkResp>,
    buf: Vec<u8>,
}

pub struct VirtioBlk {
    // Declared first: dropped first. `VirtIOBlk`'s drop unsets the queue,
    // so the device stops using `inflight`'s buffers before they are freed.
    raw: Raw,
    inflight: Option<Inflight>,
}

impl VirtioBlk {
    pub fn new(pci: &mut Pci, dev: &PciDevice) -> Result<Self, Error> {
        let transport =
            PciTransport::new::<DmaHal, _>(&mut pci.root, dev.df).map_err(|_| Error::Transport)?;
        let mut raw = Raw::new(transport).map_err(|_| Error::Device)?;
        raw.disable_interrupts();
        Ok(Self {
            raw,
            inflight: None,
        })
    }

    /// Disk size in 512-byte sectors.
    pub fn capacity(&self) -> u64 {
        self.raw.capacity()
    }

    pub fn readonly(&self) -> bool {
        self.raw.readonly()
    }

    fn check(&self, lba: u64, len: usize) -> Result<(), Error> {
        let sectors = len / SECTOR_SIZE;
        let ok = len > 0
            && len.is_multiple_of(SECTOR_SIZE)
            && sectors <= MAX_REQUEST_SECTORS
            && lba
                .checked_add(sectors as u64)
                .is_some_and(|end| end <= self.capacity());
        if !ok {
            return Err(Error::BadRequest);
        }
        if self.inflight.is_some() {
            return Err(Error::Busy);
        }
        Ok(())
    }

    /// Start reading `sectors` sectors at `lba`.
    pub fn submit_read(&mut self, lba: u64, sectors: usize) -> Result<(), Error> {
        self.check(lba, sectors * SECTOR_SIZE)?;
        let mut f = Inflight {
            token: 0,
            write: false,
            req: Box::default(),
            resp: Box::default(),
            buf: vec![0; sectors * SECTOR_SIZE],
        };
        // SAFETY: `req`, `buf` and `resp` are heap allocations moved into
        // `self.inflight` right below; nothing touches them until `poll`
        // sees this token in the used ring and completes it.
        let token = unsafe {
            self.raw
                .read_blocks_nb(lba as usize, &mut f.req, &mut f.buf, &mut f.resp)
        }
        .map_err(|_| Error::Device)?;
        f.token = token;
        self.inflight = Some(f);
        Ok(())
    }

    /// Start writing `data` (whole sectors) at `lba`.
    pub fn submit_write(&mut self, lba: u64, data: Vec<u8>) -> Result<(), Error> {
        if self.readonly() {
            return Err(Error::ReadOnly);
        }
        self.check(lba, data.len())?;
        let mut f = Inflight {
            token: 0,
            write: true,
            req: Box::default(),
            resp: Box::default(),
            buf: data,
        };
        // SAFETY: as in `submit_read`: the buffers move into
        // `self.inflight` and stay untouched until completed in `poll`.
        let token = unsafe {
            self.raw
                .write_blocks_nb(lba as usize, &mut f.req, &f.buf, &mut f.resp)
        }
        .map_err(|_| Error::Device)?;
        f.token = token;
        self.inflight = Some(f);
        Ok(())
    }

    /// The submitted request's result once the device finished it: the
    /// data read (or the written buffer, handed back).
    pub fn poll(&mut self) -> Option<Result<Vec<u8>, Error>> {
        let token = self.inflight.as_ref()?.token;
        if self.raw.peek_used() != Some(token) {
            return None;
        }
        let mut f = self.inflight.take()?;
        let done = if f.write {
            // SAFETY: the same `req`, `buf` and `resp` as passed to
            // `write_blocks_nb` for this token.
            unsafe {
                self.raw
                    .complete_write_blocks(token, &f.req, &f.buf, &mut f.resp)
            }
        } else {
            // SAFETY: the same `req`, `buf` and `resp` as passed to
            // `read_blocks_nb` for this token.
            unsafe {
                self.raw
                    .complete_read_blocks(token, &f.req, &mut f.buf, &mut f.resp)
            }
        };
        Some(match done {
            Ok(()) if f.resp.status() == RespStatus::OK => Ok(f.buf),
            _ => Err(Error::Io),
        })
    }

    /// Wait for the submitted request, yielding to other tasks in between.
    pub async fn wait(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            if let Some(r) = self.poll() {
                return r;
            }
            if self.inflight.is_none() {
                return Err(Error::BadRequest); // nothing submitted
            }
            crate::executor::yield_now().await;
        }
    }

    pub async fn read(&mut self, lba: u64, sectors: usize) -> Result<Vec<u8>, Error> {
        self.submit_read(lba, sectors)?;
        self.wait().await
    }

    pub async fn write(&mut self, lba: u64, data: Vec<u8>) -> Result<(), Error> {
        self.submit_write(lba, data)?;
        self.wait().await.map(drop)
    }

    /// Make completed writes durable (blocking, see the module docs).
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.inflight.is_some() {
            return Err(Error::Busy);
        }
        self.raw.flush().map_err(|_| Error::Io)
    }
}
