#!/usr/bin/busybox sh
# udhcpc event script for the second NIC (eth1, in its own network
# namespace: scripts/lab-test.sh LAB_PORTS): address and default route.
bb=/usr/bin/busybox
case "$1" in
  bound|renew)
    $bb ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}" up
    $bb route add default gw "${router%% *}" dev "$interface" 2>/dev/null
    echo "pip=$ip prouter=${router%% *}" > /tmp/plese
    ;;
esac
exit 0
