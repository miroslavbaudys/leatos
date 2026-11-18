#!/usr/bin/busybox sh
# udhcpc event script: configure eth0 and record the lease for /init.
bb=/usr/bin/busybox
case "$1" in
  bound|renew)
    $bb ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}" up
    [ -n "$router" ] && $bb route add default gw "${router%% *}" dev "$interface" 2>/dev/null
    : > /etc/resolv.conf
    for d in $dns; do echo "nameserver $d" >> /etc/resolv.conf; done
    echo "ip=$ip router=${router%% *} dns=\"$dns\" domain=$domain staticroutes=\"$staticroutes\"" > /tmp/lease
    ;;
esac
exit 0
