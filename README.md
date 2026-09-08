# kohunt 🐛🔫

Drives **real** Linux `.ko` drivers inside [mwemu](../mwemu) in kernel mode
and pulls memory bugs out of the *slab ledger*: use-after-free, double-free,
slab-out-of-bounds, and leaks.

The idea: mwemu owns the slab, so a freed chunk gets quarantined and
poisoned, and **every access is checked**. Failing the N-th `kmalloc`
(fault-injection) drives the error/cleanup paths, where most driver
double-frees and UAFs live.

```
kohunt <mode> <file.ko | dir> [cap]
```

- **`<mode>`** — one of the modes in the table below (`init`, `probe`, `wps`, …).
- **`<file.ko | dir>`** — a `.ko`/`.ko.zst` (decompressed on the fly) or a
  directory: walked recursively, running the mode over each module.
- **`[cap]`** — cap on allocs to fault-inject per function (default **48**).

### The `cap` parameter

The generic modes do *allocation-failure injection*: for each `kmalloc`
in the module, the function is re-run making that one alloc (and only that
one) fail, to walk the error/cleanup branch hanging off it. `cap` limits how
many distinct allocs are walked this way: `min(observed_allocs, cap)`
indices are tried (0, 1, 2, …). Raising it covers more cleanup paths at the
cost of more time; lowering it speeds up a broad sweep. **Only applies to
`init` and `probe`**; the parser modes (`wps`, `loop`, `uvc`, `hid`,
`l2cap`) ignore it.

### Examples

```sh
kohunt init  /lib/modules/$(uname -r)/kernel   # mass sweep, cap 48
kohunt probe ~/lab/ko/r8723bs.ko               # drives the real captured probe
kohunt init  ~/lab/ko/fnic.ko 200              # deep cleanup: up to 200 allocs
kohunt wps   ~/lab/ko/r8723bs.ko               # WPS overflow PoC (ignores cap)
```

## Modes

| Mode    | Generic | What it does |
|---------|:-------:|----------|
| `init`  | ✅ | Runs `init`+`exit` and fault-injects every alloc to force cleanup. |
| `probe` | ✅ | Captures the driver's real registered `.probe` + `id_table` and drives it with fault-injection. |
| `wps`   | ❌ | Fires `rtw_get_wps_attr_content` (rtl8723bs) with a crafted WPS IE → remote stack overflow. |
| `loop`  | ❌ | Checks the `u16` wrap in the WPS attribute walker (infinite loop). |
| `uvc`   | ❌ | Drives `uvc_parse_standard_control` with crafted USB-video descriptors. |
| `hid`   | ❌ | Drives `hid_open_report` with crafted HID report descriptors. |
| `l2cap` | ❌ | Drives `l2cap_parse_conf_req/rsp` with crafted Bluetooth config options. |

The generic modes work on any `.ko`. The rest are targeted *parser
fuzzing* templates: they hard-code the signature and offsets of a specific
function.

## Functions (`src/main.rs`)

- `is_interesting` — filters ledger reports down to real bugs (UAF, double-free, OOB, poison).
- `fresh` — creates an emulator, loads the `.ko`, and makes it ready (limits, banzai, skipping unimplemented APIs).
- `probe_symbols` — name-based heuristic to find `probe`/`init_one`/`_attach`-style entry points when there was no capture.
- `run_probe` — runs one probe call under a given fault index; returns findings and alloc count.
- `probe_entries` — prefers the real probe captured in `*_register_driver`; falls back to the name heuristic if no capture exists.
- `drive_probe` — `probe` mode: sweeps baseline + fault-injection over each entry point.
- `report` — prints a formatted finding and bumps the hit counter.
- `indent` — indents multi-line text (presentation helper).
- `drive_init` — `init` mode: clean load + teardown, plus fault-injection over the init's cleanup path.
- `collect_ko` — recursively collects `.ko`/`.ko.zst` files under a file or directory.
- `materialize` — returns a real `.ko`, decompressing a `.ko.zst` to a temp file first if needed.
- `drive_wps` — `wps` mode: WPS IE with a 100-byte attribute against a 1-byte destination → slab-out-of-bounds.
- `drive_loop` — `loop` mode: attribute with `data_len=0xFFFC` that wraps the `u16` → detects the infinite loop by measuring instructions.
- `run_uvc_case` — builds a deref-safe `uvc_device` and drives `uvc_parse_standard_control` with a descriptor.
- `drive_uvc` — `uvc` mode: runs several cases (input-terminal, extension-unit) against the UVC parser.
- `run_hid_case` — builds a `hid_device` and drives `hid_open_report` with a report descriptor.
- `drive_hid` — `hid` mode: battery of report descriptors (bisection, large counts/sizes, nested collections).
- `run_l2cap_case` — builds an `l2cap_chan` and drives `l2cap_parse_conf_req` with config options.
- `drive_l2cap` — `l2cap` mode: `parse_conf_req` and `parse_conf_rsp` cases (MTU, oversized len, multi-option).
- `run_l2cap_rsp_case` — drives `l2cap_parse_conf_rsp` with a crafted config response.
- `main` — parses args, collects modules, and dispatches to the chosen mode (with `catch_unwind` per module).

## Hunt status

See the progress notes in the project's memory. Confirmed finding to
date: **remote stack overflow in `rtw_get_wps_attr_content` (rtl8723bs)** via
a "Selected Registrar" WPS attribute — reproducible with `kohunt wps r8723bs.ko`.
