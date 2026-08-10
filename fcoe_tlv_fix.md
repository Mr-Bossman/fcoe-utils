# Fix: Reject zero-length TLVs in FIP VLAN notification parsing and heap buffer overflow in VN2VN VLAN request handling

## Vulnerability

### 1. Zero-length TLV infinite loop (denial of service)

An adjacent attacker can send a malformed FIP VLAN notification containing a
TLV descriptor with `tlv_len == 0` and drive `fcoemon` (or `fipvlan`) into
an infinite loop during VLAN discovery, causing a denial of service.

The root cause is in the two TLV parsing loops that iterate over FIP
descriptors. Both loops advance the pointer and decrement the remaining
length by `tlv->tlv_len` quad-words per iteration:

```c
len -= tlv->tlv_len;
tlv = ((void *) tlv) + (tlv->tlv_len << 2);
```

When `tlv_len == 0`, the pointer never advances, `len` never decreases,
and the `while (len > 0)` loop spins forever on the same TLV.

### 2. Heap buffer overflow in `fip_recv_vlan_req()` realloc

An adjacent attacker can send a FIP VLAN request (`FIP_VLAN_REQ`) to a host
running `fcoemon` with two or more VN2VN VLAN ports on the same real
interface, causing a heap buffer overflow.

The root cause is in `fip_recv_vlan_req()` which builds an array of
`fip_tlv_vlan` descriptors by calling `realloc()` once per discovered VLAN
port. The original code always allocated space for a single struct:

```c
vtp = realloc(vlan_tlvs, sizeof(*vlan_tlvs));
```

On the second and subsequent iterations, this does not grow the buffer — it
allocates the same `sizeof(*vlan_tlvs)` bytes each time. The subsequent
`memset(&vtp[vlan_count], ...)` and field writes then write past the end of
the allocated buffer, corrupting heap metadata. Depending on the allocator
and heap layout, this can cause crashes, memory corruption, or potentially
arbitrary code execution.

### Affected code paths

| File | Function | Vulnerability | Lines |
|---|---|---|---|
| `fcoemon.c` | `fcm_vlan_disc_handler()` | Zero-length TLV infinite loop | TLV loop at ~line 1010 |
| `fipvlan.c` | `fip_parse_tlvs()` | Zero-length TLV infinite loop | TLV loop at ~line 250 |
| `fcoemon.c` | `fip_recv_vlan_req()` | Heap buffer overflow in `realloc()` | `realloc` at ~line 1466 |

The first two are reached from `fip_recv()` (`lib/fip.c`) which validates
the outer packet length but does not inspect individual TLV `tlv_len` fields.

`fip_recv_vlan_req()` is reached from `fip_vlan_disc_handler()` when
`fcoemon` receives a `FIP_VLAN_REQ` subcode on an interface with VN2VN
FCoE ports configured. It iterates all FCoE ports matching the real
interface name, and for each VN2VN port with a valid VLAN ID, grows a
`fip_tlv_vlan` array via `realloc()` — the call that contained the
undersized allocation.

### Attack requirements

**Zero-length TLV (infinite loop):**

- Layer 2 adjacency to the target host (same broadcast domain)
- `fcoemon` running with active VLAN discovery, or `fipvlan` running
- No authentication or privileges required
- Single malformed FIP frame is sufficient

**Heap buffer overflow (`fip_recv_vlan_req`):**

- Layer 2 adjacency to the target host (same broadcast domain)
- `fcoemon` running with FIP VLAN responder active (`FIP_RESP="yes"`)
- Two or more VN2VN VLAN ports configured on the same real interface
- No authentication or privileges required
- Single FIP VLAN request frame is sufficient

## Fix applied

### 1. `fcoemon.c` — `fcm_vlan_disc_handler()`

Added a check for `tlv_len == 0` after the `switch` block and before the
pointer-advance step. On encountering a zero-length TLV, the function logs
an error via `FCM_LOG_ERR` and returns `-1`, aborting the parse of the
malformed frame.

### 2. `fipvlan.c` — `fip_parse_tlvs()`

Added the same check. On encountering a zero-length TLV, the function logs
via `FIP_LOG` and breaks out of the loop, returning whatever bitmap has been
accumulated so far.

### 3. `fcoemon.c` — `fip_recv_vlan_req()`

Fixed the `realloc()` call to allocate space for all accumulated entries
rather than always allocating space for a single `struct fip_tlv_vlan`:

```c
// Before (broken):
vtp = realloc(vlan_tlvs, sizeof(*vlan_tlvs));

// After (fixed):
vtp = realloc(vlan_tlvs, (vlan_count + 1) * sizeof(*vlan_tlvs));
```

This ensures the buffer grows correctly as each new VN2VN VLAN port is
discovered, preventing the out-of-bounds heap write on the second and
subsequent iterations.

## Files modified

| File | Change |
|---|---|
| `fcoemon.c` | Zero-length TLV guard in `fcm_vlan_disc_handler()` |
| `fcoemon.c` | Fixed `realloc()` size calculation in `fip_recv_vlan_req()` |
| `fipvlan.c` | Zero-length TLV guard in `fip_parse_tlvs()` |

## Build verification

Full clean build completed successfully with **zero errors and zero warnings**
under `-Wall -Wformat=2 -Werror -Wextra -Wmissing-prototypes -Wstrict-prototypes`:

```
$ make clean && make
```

All binaries built: `fcoeadm`, `fcoemon`, `fcping`, `fipvlan`, `fcnsq`, `fcrls`.

## Commits

- `615114a` — Reject zero-length TLVs in FIP VLAN notification parsing
- `6db7087` — Fix heap buffer overflow in fip_recv_vlan_req realloc

## Test script

A standalone test script `test_fip_tlv.sh` is provided to verify this fix.
It sets up an isolated veth bridge topology via `fip_bridge.sh`, compiles a
C probe (`fip_inject`) that injects crafted FIP frames via a raw packet
socket (`AF_PACKET`, `SOCK_RAW`, `ETH_P_FIP`), then starts `fcoemon` in
foreground mode (with `MALLOC_CHECK_=3`) and verifies it handles each
injected frame without crashing or hanging.

The script runs four tests sequentially. For each test it starts a fresh
`fcoemon` instance, injects a frame, waits, checks that `fcoemon` is still
alive, and searches its log output for the expected message.

### Test coverage

| Test | Mode | What it checks |
|---|---|---|
| 1 | 1 | `fcoemon` receives a valid FIP VLAN notification — expects `OP: ENABLE` on the monitored interface (regression check) |
| 2 | 2 | `fcoemon` receives a valid MAC TLV followed by a zero-length VLAN TLV — expects "aborting parse", must not hang |
| 3 | 0 | `fcoemon` receives a zero-length TLV at the start of the descriptor list — expects "aborting parse", must not hang |
| 4 | 3 | `fcoemon` handles a FIP VLAN request in VN2VN mode with 10 VLAN sub-interfaces — expects "vlans found" |

Test 4 additionally creates 10 VLAN sub-interfaces on the monitored veth
and writes VN2VN FCoE config files for each before starting `fcoemon`.

### Injection modes

The C probe (`fip_inject`) supports four frame types:

- **Mode 0**: Single zero-length TLV (`tlv_type=MAC_ADDR`, `tlv_len=0`) — the
  attack frame that triggers the infinite loop on unpatched code
- **Mode 1**: Valid FIP VLAN notification with MAC_ADDR + VLAN TLVs — for
  regression testing
- **Mode 2**: Valid MAC_ADDR TLV followed by a zero-length VLAN TLV — tests
  the mid-stream zero-length case
- **Mode 3**: FIP VLAN request (`fip_subcode = FIP_VLAN_REQ`) with a single
  valid MAC_ADDR TLV (`tlv_type=MAC_ADDR`, `tlv_len=2`, containing the
  source MAC of the injection interface). This triggers the
  `fip_recv_vlan_req()` VN2VN responder path in `fcoemon`. That function
  iterates all FCoE ports whose `real_ifname` matches the receiving
  interface, collects the VLAN IDs of any ports configured in `VN2VN` mode,
  builds an array of `fip_tlv_vlan` descriptors via `realloc()`, and replies
  with a FIP VLAN notification containing the discovered VLANs. The test
  sets up 10 VLAN sub-interfaces (VLAN IDs 2–10) on the monitored veth,
  each with a VN2VN FCoE config (`cfg-fipmn.<id>-fcoe`), so `fcoemon` must
  successfully `realloc()` the VLAN TLV array 9 times and log
  "vlans found" with a count reflecting all configured VLANs. This exercises
  the `realloc()` growth path that was previously vulnerable to a heap
  buffer overflow when processing VLAN requests

### Usage

```bash
sudo ./test_fip_tlv.sh
# Or specify a custom fcoemon binary:
sudo ./test_fip_tlv.sh /path/to/fcoemon
```

### Prerequisites

- Root access (raw sockets require `CAP_NET_RAW`)
- gcc (to compile `fip_inject.c`)
- `fip_bridge.sh` in the same directory (sets up/tears down the veth bridge)
- `fcoemon` binary (defaults to `fcoemon` in `$PATH`; override via first
  argument or `$FCOEMON` environment variable)
