#!/bin/bash
# test_fip_tlv.sh — Test FIP TLV parsing: fcoemon infinite-loop + fipvlan overflow
#
# 1. Compile fip_inject
# 2. Set up bridge topology via fip_bridge.sh
# 3. Start fcoemon directly in foreground mode
# 4. Inject mode 1 (valid), mode 2 (zero-len mid-stream), mode 0 (zero-len)
# 5. Check fcoemon is still alive and not spinning after each
# 6. Test fipvlan stack overflow via 372-VLAN-TLV injection
#
# Usage:  sudo ./test_fip_tlv.sh

set -eu

TMPDIR_BASE=$(mktemp -d /tmp/fip_tlv_test.XXXXXX)
PROBE_BIN="$TMPDIR_BASE/fip_inject"
FCOEMON="${1:-${FCOEMON:-fcoemon}}"
FIPVLAN_ASAN="$TMPDIR_BASE/fipvlan-asan"
VETH_INJ="fipin"
VETH_INJ_BR="fipin-br"
VETH_MON="fipmn"
BRIDGE="br-fiptest"
VLAN_COUNT=10
FCOEMON_PID=""
FIPVLAN_PID=""
FCOEMON_LOG="$TMPDIR_BASE/fcoemon.log"
FIPVLAN_LOG="$TMPDIR_BASE/fipvlan.log"
PASS=0
FAIL=0

cleanup() {
    [ -n "$FCOEMON_PID" ] && kill -9 "$FCOEMON_PID" 2>/dev/null && wait "$FCOEMON_PID" 2>/dev/null
    [ -n "$FIPVLAN_PID" ] && kill -9 "$FIPVLAN_PID" 2>/dev/null && wait "$FIPVLAN_PID" 2>/dev/null
    rm -f "/etc/fcoe/cfg-$VETH_MON"*
    ./fip_bridge.sh down 2>/dev/null || true
    rm -rf "$TMPDIR_BASE"
}
trap cleanup EXIT

log_pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
log_fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

[ "$(id -u)" -ne 0 ] && echo "ERROR: must be root" && exit 1

echo "=== FIP TLV parsing test ==="

# ── Build ──────────────────────────────────────────────────────────────
echo "Building fip_inject..."
gcc -Wall -Wextra -o "$PROBE_BIN" fip_inject.c
echo "fip_inject compiled"

echo "Building fipvlan-asan..."
gcc -g -O0 -fsanitize=address \
    -DPACKAGE_VERSION=\"1.0.34\" -DSYSCONFDIR=\"/usr/local/etc\" \
    -I. -I./include \
    -o "$FIPVLAN_ASAN" \
    fipvlan.c lib/sa_log.c lib/sa_select.c lib/sa_timer.c lib/sa_other.c \
    lib/fip.c lib/rtnetlink.c lib/sa_sys.c lib/sysfs_hba.c lib/fcoe_utils.c \
    -lasan -lpciaccess
echo "fipvlan-asan compiled"


# ── Bridge ─────────────────────────────────────────────────────────────
echo "Setting up bridge..."
./fip_bridge.sh up

# ── Helpers ───────────────────────────────────────────────────────────
write_fcoe_cfg() {
    local ifname=$1 mode=${2:-fabric}
    mkdir -p /etc/fcoe
    cat > "/etc/fcoe/cfg-$ifname" <<EOF
FCOE_ENABLE="yes"
DCB_REQUIRED="no"
AUTO_VLAN="yes"
MODE="$mode"
FIP_RESP="yes"
EOF
}

start_fcoemon() {
    MALLOC_CHECK_=3 "$FCOEMON" -f -d yes &>"$FCOEMON_LOG" &
    FCOEMON_PID=$!
    sleep 2
    if ! kill -0 "$FCOEMON_PID" 2>/dev/null; then
        echo "ERROR: fcoemon failed to start"
        cat "$FCOEMON_LOG"
        exit 1
    fi
    echo "  fcoemon running (pid $FCOEMON_PID)"
}

stop_fcoemon() {
    if [ -n "$FCOEMON_PID" ]; then
        kill -9 "$FCOEMON_PID" 2>/dev/null || true
        wait "$FCOEMON_PID" 2>/dev/null || true
        FCOEMON_PID=""
    fi
}

setup_vn2vn_vlans() {
    echo "Creating $VLAN_COUNT VLAN interfaces..."
    write_fcoe_cfg "$VETH_MON" vn2vn

    for i in $(seq 2 "$VLAN_COUNT"); do
        ip link add link "$VETH_MON" name "$VETH_MON.$i" type vlan id "$i"
        ip link set "$VETH_MON.$i" name "$VETH_MON.$i-fcoe"
        ip link set "$VETH_MON.$i-fcoe" up
        write_fcoe_cfg "$VETH_MON.$i-fcoe" vn2vn
    done
}

test_mode() {
    local mode=$1 label=$2 expect=$3
    local line_before new_lines
    echo "--- $label (mode $mode) ---"

    start_fcoemon

    line_before=$(wc -l < "$FCOEMON_LOG")

    "$PROBE_BIN" "$VETH_INJ" "$mode" "$VETH_MON"

    sleep 3

    if ! kill -0 "$FCOEMON_PID" 2>/dev/null; then
        log_fail "$label — fcoemon crashed"
        stop_fcoemon
        return
    fi

    new_lines=$(tail -n +"$((line_before + 1))" "$FCOEMON_LOG")

    echo "$new_lines" | grep -m 1 -B 3 -A 5 "$expect" && log_pass "$label" || log_fail "$label"

    stop_fcoemon
}

write_fcoe_cfg "$VETH_MON" fabric

test_mode 1 "Valid FIP VLAN notification" "OP: ENABLE $VETH_MON"
test_mode 2 "Zero-length TLV after valid TLV" "aborting parse"
test_mode 0 "Zero-length TLV at start" "aborting parse"

# ── VN2VN VLAN request test (mode 3) ─────────────────────────────────
setup_vn2vn_vlans

test_mode 3 "FIP VLAN Request" "vlans found"

# ── fipvlan stack buffer overflow test ─────────────────────────────────
echo ""
echo "--- fipvlan stack overflow (372 VLAN TLVs via fip_inject mode 4) ---"
ip link del "$BRIDGE" 2>/dev/null || true

timeout 30 "$FIPVLAN_ASAN" -m fabric "$VETH_INJ_BR" &>"$FIPVLAN_LOG" &
FIPVLAN_PID=$!
sleep 2

"$PROBE_BIN" "$VETH_INJ" 4 "$VETH_INJ_BR" || true
sleep 2
if kill -0 "$FIPVLAN_PID" 2>/dev/null; then
    log_pass "fipvlan stack overflow — survived 372 VLAN TLVs"
else
    if grep -q "AddressSanitizer" "$FIPVLAN_LOG" 2>/dev/null; then
       log_fail "fipvlan stack overflow — ASAN detected overflow"
       grep "SUMMARY:" "$FIPVLAN_LOG"
    else
        log_fail "fipvlan stack overflow — fipvlan crashed"
    fi
fi

kill "$FIPVLAN_PID" 2>/dev/null || true
wait "$FIPVLAN_PID" 2>/dev/null || true
FIPVLAN_PID=""

echo ""
echo "============================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
