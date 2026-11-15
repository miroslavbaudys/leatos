#!/usr/bin/busybox sh
# udhcpc event script for the guest VLAN (eth0.20): address only, no default
# route or resolver (the main LAN keeps those); /init routes guest-sourced
# traffic through the VLAN by policy routing.
bb=/usr/bin/busybox
case "$1" in
  bound|renew)
    $bb ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}" up
    echo "gip=$ip grouter=${router%% *} gdns=\"$dns\" gdomain=$domain" > /tmp/glease
    ;;
esac
exit 0
