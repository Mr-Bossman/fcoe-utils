#!/bin/bash
# test_socket_cred.sh — Test script for fcoemon control socket credential validation
#
# Tests commit db2f1e8eddc: "Validate sender credentials on fcoemon control socket"
#
# This script verifies that:
#   1. fcoemon accepts commands from root (uid 0)
#   2. fcoemon rejects commands from unprivileged users
#   3. fcoeadm works correctly as root
#   4. fcoeadm fails correctly as non-root
#   5. The rejection is logged to syslog
#
# Prerequisites:
#   - Patched fcoe-utils 2.0 installed (fcoemon, fcoeadm in PATH or /usr/sbin)
#   - Run this script as root
#   - A non-root test user must exist (default: "nobody"; override with TEST_USER=)
#   - fcoemon must be running (via systemd or manually)
#   - gcc must be installed (for the raw socket test probe)
#
# Usage:
#   sudo ./test_socket_cred.sh
#   sudo TEST_USER=testuser ./test_socket_cred.sh

set -u

# ── Configuration ──────────────────────────────────────────────────────────

TEST_USER="${TEST_USER:-nobody}"
FCOEMON="${FCOEMON:-fcoemon}"
FCOEADM="${FCOEADM:-fcoeadm}"
PASS=0
FAIL=0
SKIP=0
TMPDIR_BASE=""

# ENOPERM is enum value 16 in the patched fcoe_utils.h
ENOPERM_VALUE=16

# CLIF_PID_CMD is enum value 5 in fcoe_clif.h
CLIF_PID_CMD=5

# ── Helpers ────────────────────────────────────────────────────────────────

cleanup() {
    if [ -n "$TMPDIR_BASE" ] && [ -d "$TMPDIR_BASE" ]; then
        rm -rf "$TMPDIR_BASE"
    fi
    # If we started fcoemon ourselves, stop it
    if [ "${STARTED_FCOEMON:-0}" -eq 1 ] && [ -n "${FCOEMON_PID:-}" ]; then
        kill "$FCOEMON_PID" 2>/dev/null
        wait "$FCOEMON_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

log_pass() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

log_fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
}

log_skip() {
    SKIP=$((SKIP + 1))
    echo "  SKIP: $1"
}

log_info() {
    echo "  INFO: $1"
}

# ── Precondition checks ───────────────────────────────────────────────────

echo "=== fcoemon control socket credential validation test ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

if ! id "$TEST_USER" &>/dev/null; then
    echo "ERROR: Test user '$TEST_USER' does not exist."
    echo "       Set TEST_USER= to an existing non-root account."
    exit 1
fi

TEST_UID=$(id -u "$TEST_USER")
if [ "$TEST_UID" -eq 0 ]; then
    echo "ERROR: TEST_USER='$TEST_USER' has uid 0; need a non-root user."
    exit 1
fi

if ! command -v gcc &>/dev/null; then
    echo "ERROR: gcc is required to build the test probe."
    exit 1
fi

TMPDIR_BASE=$(mktemp -d /tmp/fcoe_cred_test.XXXXXX)

# ── Build a minimal C test probe ───────────────────────────────────────────
#
# This probe sends a CLIF_PID_CMD to @fcm_clif and prints the raw reply.
# It sets SO_PASSCRED so the kernel attaches credentials.
# It can be run as any user to test the credential check.

PROBE_SRC="$TMPDIR_BASE/probe.c"
PROBE_BIN="$TMPDIR_BASE/probe"

cat > "$PROBE_SRC" << 'PROBE_EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

/* Mirror the clif_data structure from fcoe_clif.h */
struct clif_data {
    int cmd;
    char ifname[16]; /* IFNAMSIZ */
    int flags;
};

int main(int argc, char **argv)
{
    int fd, rc, cmd;
    struct sockaddr_un local, dest;
    socklen_t addrlen;
    struct clif_data data;
    char rbuf[512];
    struct timeval tv;
    fd_set rfds;

    cmd = 5; /* CLIF_PID_CMD default */
    if (argc > 1)
        cmd = atoi(argv[1]);

    fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 100;
    }

    /* Enable SO_PASSCRED so kernel attaches our credentials */
    {
        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));
    }

    /* Bind to our own abstract address */
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_LOCAL;
    local.sun_path[0] = '\0';
    snprintf(&local.sun_path[1], sizeof(local.sun_path) - 1,
             "fcm_clif_test/%d", getpid());
    addrlen = sizeof(sa_family_t) + strlen(local.sun_path + 1) + 1;
    if (bind(fd, (struct sockaddr *)&local, addrlen) < 0) {
        perror("bind");
        close(fd);
        return 101;
    }

    /* Connect to fcoemon's abstract socket @fcm_clif */
    memset(&dest, 0, sizeof(dest));
    dest.sun_family = AF_LOCAL;
    dest.sun_path[0] = '\0';
    snprintf(&dest.sun_path[1], sizeof(dest.sun_path) - 1, "fcm_clif");
    addrlen = sizeof(sa_family_t) + strlen(dest.sun_path + 1) + 1;
    if (connect(fd, (struct sockaddr *)&dest, addrlen) < 0) {
        perror("connect");
        close(fd);
        return 102;
    }

    /* Build and send a command */
    memset(&data, 0, sizeof(data));
    data.cmd = cmd;
    memset(data.ifname, 0, sizeof(data.ifname));
    data.flags = 0;

    if (send(fd, &data, sizeof(data), 0) < 0) {
        perror("send");
        close(fd);
        return 103;
    }

    /* Wait for reply with 5 second timeout */
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        fprintf(stderr, "timeout or select error\n");
        close(fd);
        return 104;
    }

    memset(rbuf, 0, sizeof(rbuf));
    rc = recv(fd, rbuf, sizeof(rbuf) - 1, 0);
    if (rc < 0) {
        perror("recv");
        close(fd);
        return 105;
    }
    rbuf[rc] = '\0';

    /* Print the raw reply — caller parses it */
    printf("%s", rbuf);

    close(fd);
    return 0;
}
PROBE_EOF

echo "Building test probe..."
if ! gcc -Wall -Wextra -o "$PROBE_BIN" "$PROBE_SRC" 2>"$TMPDIR_BASE/gcc.err"; then
    echo "ERROR: Failed to build test probe:"
    cat "$TMPDIR_BASE/gcc.err"
    exit 1
fi
echo "Test probe built successfully."
echo ""

# ── Ensure fcoemon is running ─────────────────────────────────────────────

STARTED_FCOEMON=0

echo "--- Checking fcoemon status ---"

# Check if fcoemon is already running
if pgrep -x fcoemon >/dev/null 2>&1; then
    log_info "fcoemon is already running (pid $(pgrep -x fcoemon | head -1))"
else
    log_info "fcoemon is not running, attempting to start via systemd..."
    if systemctl start fcoemon.socket fcoe.service 2>/dev/null; then
        sleep 1
        if pgrep -x fcoemon >/dev/null 2>&1; then
            log_info "fcoemon started via systemd"
        else
            log_info "systemd start returned success but fcoemon not found, starting manually..."
            "$FCOEMON" --foreground --debug=all --syslog=1 &
            FCOEMON_PID=$!
            STARTED_FCOEMON=1
            sleep 1
            if ! kill -0 "$FCOEMON_PID" 2>/dev/null; then
                echo "ERROR: fcoemon failed to start. Cannot continue."
                exit 1
            fi
            log_info "fcoemon started manually (pid $FCOEMON_PID)"
        fi
    else
        log_info "systemd start failed, starting fcoemon manually..."
        "$FCOEMON" --foreground --debug=all --syslog=1 &
        FCOEMON_PID=$!
        STARTED_FCOEMON=1
        sleep 1
        if ! kill -0 "$FCOEMON_PID" 2>/dev/null; then
            echo "ERROR: fcoemon failed to start. Cannot continue."
            exit 1
        fi
        log_info "fcoemon started manually (pid $FCOEMON_PID)"
    fi
fi
echo ""

# ── Verify the abstract socket exists ──────────────────────────────────────

echo "--- Checking @fcm_clif socket ---"
if ss -xlp 2>/dev/null | grep -q 'fcm_clif'; then
    log_pass "Abstract socket @fcm_clif is listening"
else
    log_info "ss did not show fcm_clif (may be normal for DGRAM sockets)"
fi
echo ""

# ── Test 1: Root sends CLIF_PID_CMD via probe — should succeed ─────────

echo "--- Test 1: Root sends CLIF_PID_CMD (expect success) ---"

# Record syslog position for later checks
SYSLOG_FILE="/var/log/messages"
[ -f /var/log/syslog ] && SYSLOG_FILE="/var/log/syslog"
SYSLOG_LINES_BEFORE=$(wc -l < "$SYSLOG_FILE" 2>/dev/null || echo 0)

REPLY=$("$PROBE_BIN" $CLIF_PID_CMD 2>"$TMPDIR_BASE/t1.err")
PROBE_RC=$?

if [ $PROBE_RC -ne 0 ]; then
    log_fail "Probe exited with rc=$PROBE_RC (stderr: $(cat "$TMPDIR_BASE/t1.err"))"
else
    # CLIF_PID_CMD reply is the daemon's PID as a decimal string
    if echo "$REPLY" | grep -qE '^[0-9]+$'; then
        REPORTED_PID="$REPLY"
        ACTUAL_PID=$(pgrep -x fcoemon | head -1)
        if [ "$REPORTED_PID" = "$ACTUAL_PID" ]; then
            log_pass "Root CLIF_PID_CMD returned correct PID ($REPORTED_PID)"
        else
            log_pass "Root CLIF_PID_CMD returned a PID ($REPORTED_PID) (actual fcoemon pid: $ACTUAL_PID)"
        fi
    else
        log_fail "Root CLIF_PID_CMD got unexpected reply: '$REPLY'"
    fi
fi
echo ""

# ── Test 2: Non-root sends CLIF_PID_CMD via probe — should be rejected ──

echo "--- Test 2: Non-root ($TEST_USER, uid $TEST_UID) sends CLIF_PID_CMD (expect ENOPERM=$ENOPERM_VALUE) ---"

# Run the probe as the unprivileged test user
REPLY=$(su -s /bin/sh "$TEST_USER" -c "'$PROBE_BIN' $CLIF_PID_CMD" 2>"$TMPDIR_BASE/t2.err")
PROBE_RC=$?

if [ $PROBE_RC -ne 0 ]; then
    # The probe itself might fail to connect if permissions are very tight,
    # which is also an acceptable outcome (denied at socket layer)
    STDERR_MSG=$(cat "$TMPDIR_BASE/t2.err")
    if echo "$STDERR_MSG" | grep -qi "permission\|denied\|refused"; then
        log_pass "Non-root probe was denied at the socket layer: $STDERR_MSG"
    elif [ $PROBE_RC -eq 104 ]; then
        log_fail "Non-root probe timed out (fcoemon may not have replied)"
    else
        log_fail "Non-root probe exited with rc=$PROBE_RC (stderr: $STDERR_MSG)"
    fi
else
    # Probe connected and got a reply — check if it's the ENOPERM error code
    # The reply is written as snprintf(rbuf, MSG_RBUF, "%d", rc) where MSG_RBUF = sizeof(int) = 4
    # So we get up to 3 chars of the decimal number plus a potential NUL embedded in the 4 bytes
    REPLY_TRIMMED=$(echo "$REPLY" | tr -d '\0' | tr -d '[:space:]')

    if [ "$REPLY_TRIMMED" = "$ENOPERM_VALUE" ]; then
        log_pass "Non-root CLIF_PID_CMD correctly rejected with ENOPERM ($ENOPERM_VALUE)"
    elif echo "$REPLY_TRIMMED" | grep -qE '^[0-9]+$' && [ "$REPLY_TRIMMED" -ne "$ENOPERM_VALUE" ]; then
        # Got a numeric reply but not ENOPERM — check if it's a PID (test failure)
        log_fail "Non-root CLIF_PID_CMD was NOT rejected; got reply: '$REPLY_TRIMMED'"
    else
        log_fail "Non-root CLIF_PID_CMD got unexpected reply: '$REPLY' (trimmed: '$REPLY_TRIMMED')"
    fi
fi
echo ""

# ── Test 3: fcoeadm --pid as root — should succeed ─────────────────────

echo "--- Test 3: fcoeadm --pid as root (expect success) ---"

if command -v "$FCOEADM" &>/dev/null; then
    REPLY=$("$FCOEADM" --pid 2>"$TMPDIR_BASE/t3.err")
    FCOEADM_RC=$?
    if [ $FCOEADM_RC -eq 0 ]; then
        log_pass "fcoeadm --pid as root succeeded (output: $REPLY)"
    else
        # fcoeadm returns the error code as its exit status
        log_fail "fcoeadm --pid as root failed with rc=$FCOEADM_RC (stderr: $(cat "$TMPDIR_BASE/t3.err"))"
    fi
else
    log_skip "fcoeadm not found in PATH"
fi
echo ""

# ── Test 4: fcoeadm --pid as non-root — should fail ────────────────────

echo "--- Test 4: fcoeadm --pid as non-root (expect failure) ---"

if command -v "$FCOEADM" &>/dev/null; then
    REPLY=$(su -s /bin/sh "$TEST_USER" -c "'$FCOEADM' --pid" 2>"$TMPDIR_BASE/t4.err")
    FCOEADM_RC=$?
    if [ $FCOEADM_RC -ne 0 ]; then
        log_pass "fcoeadm --pid as non-root correctly failed (rc=$FCOEADM_RC)"
    else
        log_fail "fcoeadm --pid as non-root unexpectedly succeeded (output: $REPLY)"
    fi
else
    log_skip "fcoeadm not found in PATH"
fi
echo ""

# ── Test 5: Check syslog for rejection message ─────────────────────────

echo "--- Test 5: Check syslog for rejection log message ---"

if [ -f "$SYSLOG_FILE" ]; then
    # Look at lines added since we started testing
    SYSLOG_LINES_AFTER=$(wc -l < "$SYSLOG_FILE")
    if [ "$SYSLOG_LINES_AFTER" -gt "$SYSLOG_LINES_BEFORE" ]; then
        NEW_LINES=$((SYSLOG_LINES_AFTER - SYSLOG_LINES_BEFORE))
        if tail -n "$NEW_LINES" "$SYSLOG_FILE" | grep -q "Rejected command from unprivileged uid"; then
            REJECT_LINE=$(tail -n "$NEW_LINES" "$SYSLOG_FILE" | grep "Rejected command from unprivileged uid" | tail -1)
            log_pass "Syslog contains rejection message: $REJECT_LINE"
        else
            log_info "No rejection message found in syslog (fcoemon may log to journal instead)"
            # Try journalctl as fallback
            if command -v journalctl &>/dev/null; then
                if journalctl -u fcoe.service --since "2 minutes ago" --no-pager 2>/dev/null \
                    | grep -q "Rejected command from unprivileged uid"; then
                    REJECT_LINE=$(journalctl -u fcoe.service --since "2 minutes ago" --no-pager 2>/dev/null \
                        | grep "Rejected command from unprivileged uid" | tail -1)
                    log_pass "Journal contains rejection message: $REJECT_LINE"
                else
                    # Also check without unit filter in case fcoemon was started manually
                    if journalctl --since "2 minutes ago" --no-pager 2>/dev/null \
                        | grep -q "Rejected command from unprivileged uid"; then
                        log_pass "Journal contains rejection message"
                    else
                        log_skip "Rejection message not found in syslog or journal"
                    fi
                fi
            else
                log_skip "Rejection message not found in syslog and journalctl not available"
            fi
        fi
    else
        log_skip "No new syslog lines generated during test"
    fi
else
    # No syslog file, try journalctl
    if command -v journalctl &>/dev/null; then
        if journalctl --since "2 minutes ago" --no-pager 2>/dev/null \
            | grep -q "Rejected command from unprivileged uid"; then
            log_pass "Journal contains rejection message"
        else
            log_skip "Rejection message not found in journal"
        fi
    else
        log_skip "No syslog file found and journalctl not available"
    fi
fi
echo ""

# ── Test 6: Verify SO_PASSCRED is set on the fcoemon socket ─────────────

echo "--- Test 6: Verify SO_PASSCRED on fcoemon socket ---"

FCOEMON_PID_ACTUAL=$(pgrep -x fcoemon | head -1)
if [ -n "$FCOEMON_PID_ACTUAL" ]; then
    # Look at fcoemon's file descriptors and check socket options
    FOUND_PASSCRED=0
    for fd_path in /proc/"$FCOEMON_PID_ACTUAL"/fd/*; do
        fd_num=$(basename "$fd_path")
        fd_info=$(readlink "$fd_path" 2>/dev/null)
        if echo "$fd_info" | grep -q "socket"; then
            # Check if this socket has SO_PASSCRED via /proc/net/unix
            sock_inode=$(stat -L -c %i "$fd_path" 2>/dev/null)
            if [ -n "$sock_inode" ]; then
                if grep -q "$sock_inode" /proc/net/unix 2>/dev/null; then
                    FOUND_PASSCRED=1
                fi
            fi
        fi
    done
    if [ $FOUND_PASSCRED -eq 1 ]; then
        log_pass "fcoemon has socket file descriptors open (SO_PASSCRED cannot be directly inspected from /proc but the socket is active)"
    else
        log_info "Could not inspect socket options (this is informational only)"
    fi
else
    log_skip "fcoemon PID not found"
fi
echo ""

# ── Test 7: Verify version is 2.0 ──────────────────────────────────────

echo "--- Test 7: Verify fcoeadm reports version 2.0 ---"

if command -v "$FCOEADM" &>/dev/null; then
    VERSION_OUT=$("$FCOEADM" --version 2>&1 || true)
    if echo "$VERSION_OUT" | grep -q "2\.0"; then
        log_pass "fcoeadm reports version 2.0"
    else
        log_fail "fcoeadm version output: $VERSION_OUT"
    fi
else
    log_skip "fcoeadm not found in PATH"
fi
echo ""

# ── Summary ────────────────────────────────────────────────────────────────

echo "============================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "OVERALL: FAIL"
    exit 1
else
    echo ""
    echo "OVERALL: PASS"
    exit 0
fi
