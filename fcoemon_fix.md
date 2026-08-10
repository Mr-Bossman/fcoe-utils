# Fix: Validate sender credentials on `fcoemon` control socket

## Vulnerability

The `fcoemon` daemon accepts administrative commands (create/destroy/reset/scan
FCoE interfaces) over the abstract UNIX datagram socket `@fcm_clif`. Any local
user could send datagrams to this socket and trigger privileged storage
management actions — no root check, no credential validation at all.

The systemd socket unit already set `PassCredentials=true`, which causes the
kernel to attach `SCM_CREDENTIALS` ancillary data to every received datagram.
However, `fcm_srv_receive()` used plain `recvfrom()` and never extracted or
checked these credentials.

## Fix applied

### 1. Added `ENOPERM` to `enum fcoe_status`

**File:** `include/fcoe_utils.h`

Added `ENOPERM` (permission denied) after `EBADCLIFMSG` in the enum so the
daemon returns a meaningful error code to unauthorized callers.

### 2. Enabled `SO_PASSCRED` on the manually-created socket

**File:** `fcoemon.c`, in `fcm_srv_create()`

After `socket()` succeeds in the non-systemd fallback path, `SO_PASSCRED` is
now set via `setsockopt()`. The systemd path already has `PassCredentials=true`
in `fcoemon.socket`, so no change was needed there.

### 3. Replaced `recvfrom()` with `recvmsg()` and validated UID == 0

**File:** `fcoemon.c`, in `fcm_srv_receive()`

Replaced the `recvfrom()` call with `recvmsg()` that receives both the
datagram payload and `SCM_CREDENTIALS` ancillary data. The `cmsg` chain is
walked with `CMSG_FIRSTHDR`/`CMSG_NXTHDR` to extract `struct ucred`. If
credentials are missing or `uid != 0`, the request is rejected with `ENOPERM`
and a log message is emitted.

Added `#define _GNU_SOURCE` before all includes to expose `struct ucred` and
`SCM_CREDENTIALS` definitions.

### 4. Set `SO_PASSCRED` on the client socket (`fcoeadm`)

**File:** `fcoeadm.c`, in `fcoeadm_open_cli()`

After the client creates its socket, `SO_PASSCRED` is set so the kernel
attaches credentials to outgoing datagrams.

### 5. Bumped version to 2.0

**File:** `configure.ac`

Updated `AC_INIT` version from `1.0.34` to `2.0`.

## Files modified

| File | Change |
|---|---|
| `configure.ac` | Version bump from 1.0.34 to 2.0 |
| `include/fcoe_utils.h` | Added `ENOPERM` to `enum fcoe_status` |
| `fcoemon.c` | `_GNU_SOURCE` define; `SO_PASSCRED` on manual socket; `recvmsg()` + credential check in `fcm_srv_receive()` |
| `fcoeadm.c` | `SO_PASSCRED` on client socket |

## Build verification

Full clean build completed successfully with **zero errors and zero warnings**
under `-Wall -Wformat=2 -Werror -Wextra -Wmissing-prototypes -Wstrict-prototypes`:

```
$ make clean && autoreconf -i && ./configure && make
```

All binaries built: `fcoeadm`, `fcoemon`, `fcping`, `fipvlan`, `fcnsq`, `fcrls`.

## Commit

```
commit b9d63bd5b14 (bug_fixes)
Author: John Meneghini
Subject: Validate sender credentials on fcoemon control socket
```

## Test script

A standalone test script `test_socket_cred.sh` is provided to verify this
patch on an FCoE test bed. It compiles a small C probe that mirrors the
`clif_data` wire format, connects to the abstract socket `@fcm_clif`, sets
`SO_PASSCRED`, sends a command, and reads the reply. The probe is run once
as root and once via `su` as an unprivileged user.

### Test coverage

| Test | What it checks |
|---|---|
| 1 | Root sends `CLIF_PID_CMD` via compiled C probe — expects the daemon's PID back |
| 2 | Non-root (`nobody` by default) sends the same command — expects `ENOPERM` (16) reply |
| 3 | `fcoeadm --pid` as root — expects success |
| 4 | `fcoeadm --pid` as non-root — expects failure |
| 5 | Syslog/journal contains "Rejected command from unprivileged uid" |
| 6 | Confirms fcoemon has active socket fds |
| 7 | `fcoeadm --version` reports 2.0 |

### Usage

```bash
sudo ./test_socket_cred.sh                        # uses "nobody" as test user
sudo TEST_USER=testuser ./test_socket_cred.sh     # use a specific user
sudo FCOEADM=/usr/local/sbin/fcoeadm ./test_socket_cred.sh  # custom path
```

### Prerequisites

- Root access
- gcc (to compile the test probe)
- A running `fcoemon` (the script will attempt to start it if not running)
- A non-root user account (default: `nobody`; override with `TEST_USER=`)
