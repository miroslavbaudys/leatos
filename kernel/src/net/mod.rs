//! Networking: packet buffers, network interfaces, the router's own IP
//! stack (smoltcp) for local services.

pub mod datapath;
pub mod device;
pub mod dns_tcp;
pub mod dot;
pub mod mdns;
pub mod mgmt;
pub mod ntp;
pub mod packet;
pub mod pppoe;
pub mod services;
pub mod shared;
pub mod stack;
pub mod svc;
pub mod wan6;
