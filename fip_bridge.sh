#!/bin/bash
# fip_bridge.sh — Set up or tear down a bridge+veth topology for FIP testing
#
# Topology:
#
#   fipin  <──veth──>  fipin-br ─┐
#                                              br-fiptest
#   fipmn  <──veth──>  fipmn-br ─┘
#
# Usage:
#   sudo ./fip_bridge.sh up      # create bridge and veth pairs
#   sudo ./fip_bridge.sh down    # tear everything down

set -eu

BRIDGE="br-fiptest"
VETH_INJ="fipin"
VETH_INJ_BR="fipin-br"
VETH_MON="fipmn"
VETH_MON_BR="fipmn-br"

do_up() {
    # Clean any leftovers first
    do_down 2>/dev/null || true

    ip link add "$BRIDGE" type bridge
    ip link set "$BRIDGE" up

    ip link add "$VETH_INJ" type veth peer name "$VETH_INJ_BR"
    ip link set "$VETH_INJ" up
    ip link set "$VETH_INJ_BR" master "$BRIDGE"
    ip link set "$VETH_INJ_BR" up

    ip link add "$VETH_MON" type veth peer name "$VETH_MON_BR"
    ip link set "$VETH_MON" up
    ip link set "$VETH_MON_BR" master "$BRIDGE"
    ip link set "$VETH_MON_BR" up

    echo "Bridge topology is up:"
    echo "  inject:  $VETH_INJ ($(cat /sys/class/net/$VETH_INJ/address))"
    echo "  monitor: $VETH_MON ($(cat /sys/class/net/$VETH_MON/address))"
    echo "  bridge:  $BRIDGE"
    echo ""
    echo "Example:"
    echo "  ./fip_inject $VETH_INJ 1 $VETH_MON"
}

do_down() {
    ip link del "$VETH_INJ" 2>/dev/null || true
    ip link del "$VETH_MON" 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
    echo "Bridge topology torn down."
}

case "${1:-}" in
    up)   do_up ;;
    down) do_down ;;
    *)
        echo "Usage: $0 {up|down}" >&2
        exit 1
        ;;
esac
