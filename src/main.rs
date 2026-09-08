//! kohunt — drive real Linux .ko drivers inside mwemu and report memory-safety
//! findings from the slab ledger.
//!
//!   kohunt init  <file.ko|dir> [cap]   run module init+exit, fault-inject allocs
//!   kohunt probe <file.ko|dir> [cap]   drive probe()/open() entry points with a
//!                                       synthetic device + allocation-failure sweep
//!
//! Technique: mwemu owns the slab, so a freed chunk is quarantined + poisoned
//! and every access is checked. Failing the Nth kmalloc (fault injection) drives
//! the driver's error/cleanup path, where most driver double-frees / UAFs live.

use libmwemu::emu64;
use libmwemu::maps::mem64::Permission;
use libmwemu::kernel::heap::Region;
use std::path::{Path, PathBuf};

const DEV_BASE: u64 = 0xffffd00000000000;

fn is_interesting(report: &str) -> bool {
    let r = report.to_lowercase();
    r.contains("use-after-free")
        || r.contains("double-free")
        || r.contains("double free")
        || r.contains("out-of-bounds")
        || r.contains("out of bounds")
        || r.contains("poison")
        || r.contains("freed function")
}

fn fresh(path: &str, banzai: bool) -> Option<libmwemu::emu::Emu> {
    let mut emu = emu64();
    emu.cfg.verbose = 0;
    emu.cfg.max_instructions = Some(20_000_000);
    emu.cfg.timeout_secs = Some(3.0);
    emu.cfg.max_faults = Some(3);
    if banzai {
        emu.maps.set_banzai(true);
        emu.cfg.skip_unimplemented = true;
    }
    if emu.load_kernel_module(path).is_err() {
        return None;
    }
    Some(emu)
}

fn probe_symbols(emu: &libmwemu::emu::Emu) -> Vec<(String, u64)> {
    let known = ["probe", "_probe", "open"];
    let mut out = Vec::new();
    if let Some(k) = emu.kernel.as_ref() {
        for s in &k.module.symbols {
            if !s.is_func || s.addr == 0 {
                continue;
            }
            if s.name.ends_with(".cold") || s.name.starts_with("__pfx") {
                continue;
            }
            let n = s.name.to_lowercase();
            let hit = n.contains("probe")
                || n.ends_with("init_one")
                || n.ends_with("_attach")
                || known.iter().any(|k| n == *k);
            if hit {
                out.push((s.name.clone(), s.addr));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Run one probe call under a given fault index. Returns interesting findings
/// and the number of allocations attempted.
fn run_probe(path: &str, addr: u64, id_table: u64, fail: Option<u64>) -> (Vec<String>, u64) {
    let Some(mut emu) = fresh(path, true) else {
        return (vec![], 0);
    };
    // init first (registers the bus driver; mostly stubbed)
    let _ = emu.run_module_init();
    // synthetic device + id argument region
    let _ = emu
        .maps
        .create_map("probe.dev", DEV_BASE, 0x8000, Permission::READ_WRITE);
    if let Some(n) = fail {
        emu.kernel_set_fail_alloc(Some(n));
    }
    let base = emu.kernel_alloc_count();
    // Pass the driver's real id_table entry when we captured one, so the
    // probe's `id->driver_info` and id fields read real values; otherwise a
    // zeroed synthetic id region.
    let id = if id_table != 0 { id_table } else { DEV_BASE + 0x4000 };
    let _ = emu.kernel_call(addr, &[DEV_BASE, id]);
    let _ = emu.kernel_run_deferred();
    let allocs = emu.kernel_alloc_count().saturating_sub(base);
    let findings: Vec<String> = emu
        .kernel_findings()
        .iter()
        .map(|f| f.report())
        .filter(|r| is_interesting(r))
        .collect();
    (findings, allocs)
}

/// Entry points to drive: prefer the drivers captured at `*_register_driver`
/// time (real `.probe` + real `id_table`), falling back to name heuristics
/// (with no id_table) only when the module registered nothing we caught.
fn probe_entries(path: &str) -> Vec<(String, u64, u64)> {
    let Some(mut emu) = fresh(path, true) else { return vec![] };
    let _ = emu.run_module_init();
    let mut out: Vec<(String, u64, u64)> = emu
        .kernel_registered_drivers()
        .into_iter()
        .filter(|d| d.probe != 0)
        .map(|d| {
            let label = if d.probe_name.is_empty() {
                format!("{}:probe", d.bus)
            } else {
                d.probe_name.clone()
            };
            (label, d.probe, d.id_table)
        })
        .collect();
    if out.is_empty() {
        out = probe_symbols(&emu)
            .into_iter()
            .map(|(sym, addr)| (sym, addr, 0u64))
            .collect();
    }
    out
}

fn drive_probe(display: &str, path: &str, cap: u64) {
    let name = display.to_string();
    let syms = probe_entries(path);
    if syms.is_empty() {
        println!("[{}] no probe entry found", name);
        return;
    }
    let mut hits = 0;
    for (sym, addr, id_table) in &syms {
        // baseline (no fault injection) to size the allocation count
        let (base_f, allocs) = run_probe(path, *addr, *id_table, None);
        eprintln!("    probe {} -> {} allocs during probe", sym, allocs);
        report(&name, sym, "baseline", &base_f, &mut hits);
        let n = allocs.max(1).min(cap);
        for i in 0..n {
            let (f, _) = run_probe(path, *addr, *id_table, Some(i));
            report(&name, sym, &format!("fail-alloc#{}", i), &f, &mut hits);
        }
    }
    if hits == 0 {
        println!(
            "[{}] clean ({} probe entry point(s) driven)",
            name,
            syms.len()
        );
    }
}

fn report(mod_name: &str, sym: &str, cfg: &str, findings: &[String], hits: &mut u32) {
    for f in findings {
        *hits += 1;
        println!(
            "\n*** [{}] {} @ {} ***\n{}",
            mod_name,
            sym,
            cfg,
            indent(f)
        );
    }
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("    {}", l))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- init sweep (kept from the first pass) --------------------------------

fn drive_init(display: &str, path: &str, cap: u64) {
    // One run: optionally fail the Nth alloc; optionally run exit only if init
    // succeeded (the kernel never calls a module's exit after a failed init —
    // doing so ourselves would manufacture double-frees).
    let run = |fail: Option<u64>, exit_if_ok: bool| -> (i64, Vec<String>, u64, bool) {
        let Some(mut emu) = fresh(path, false) else {
            return (0, vec![], 0, true);
        };
        if let Some(n) = fail {
            emu.kernel_set_fail_alloc(Some(n));
        }
        let ret = emu.run_module_init().map(|r| r as i64).unwrap_or(-9999);
        if exit_if_ok && ret == 0 {
            let _ = emu.run_module_exit();
        }
        let _ = emu.kernel_run_deferred();
        let f: Vec<String> = emu
            .kernel_findings()
            .iter()
            .map(|x| x.report())
            .filter(|r| is_interesting(r))
            .collect();
        (ret, f, emu.kernel_alloc_count(), false)
    };

    let mut hits = 0u32;

    // (1) clean load + teardown: init, then exit only if init succeeded.
    let (ret0, f_teardown, ac, loadfail) = run(None, true);
    if loadfail {
        return;
    }
    report(display, "init+exit", "baseline", &f_teardown, &mut hits);

    // (2) fault-injection on init's own error/cleanup path (init only, no exit).
    let n = ac.max(1).min(cap);
    for i in 0..n {
        let (_ret, f, _ac, _) = run(Some(i), false);
        report(display, "init", &format!("fail-alloc#{}", i), &f, &mut hits);
    }

    if hits == 0 {
        println!("[{}] init clean (ret {}, {} allocs)", display, ret0, ac);
    }
}

fn collect_ko(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            // DirEntry::file_type() does NOT follow symlinks (unlike
            // Path::is_dir()), so a symlinked directory that cycles back to
            // an ancestor is treated as a leaf here instead of recursed into
            // forever.
            let is_real_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_real_dir {
                collect_ko(&p, out);
            } else {
                let n = p.to_string_lossy();
                if n.ends_with(".ko") || n.ends_with(".ko.zst") {
                    out.push(p);
                }
            }
        }
    }
}

/// Return a real .ko path, decompressing a .ko.zst into a temp file first.
fn materialize(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy();
    if s.ends_with(".ko.zst") {
        let data = std::fs::read(path).ok()?;
        let raw = zstd::stream::decode_all(&data[..]).ok()?;
        let tmp = std::env::temp_dir().join("kohunt_work.ko");
        std::fs::write(&tmp, raw).ok()?;
        Some(tmp)
    } else {
        Some(path.to_path_buf())
    }
}


/// Drive the real rtw_get_wps_attr_content() from r8723bs with a crafted WPS IE
/// whose attribute data-length is 200, into a 16-byte ledger buffer. The function
/// does memcpy(buf_content, attr_ptr+4, attr_len-4) with no bound on the
/// destination, so this must overflow the 16-byte chunk -> slab-out-of-bounds.
fn drive_wps(display: &str, path: &str) {
    let Some(mut emu) = fresh(path, false) else {
        println!("[{}] load failed", display);
        return;
    };
    let sym = "rtw_get_wps_attr_content";
    let Some(addr) = emu.module_symbol(sym) else {
        println!("[{}] no symbol {}", display, sym);
        return;
    };

    // crafted WPS IE: DD | len | 00 50 F2 04 | attr_id(BE) | data_len(BE)=200 | data...
    const IE: u64 = 0xffffe00000000000;
    const LEN_OUT: u64 = 0xffffe00000010000;
    let _ = emu.maps.create_map("poc.ie", IE, 0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.len", LEN_OUT, 0x100, Permission::READ_WRITE);
    let target_id: u16 = 0x1041; // WPS_ATTR_SELECTED_REGISTRAR
    let data_len: u16 = 100; // malicious attr length (attribute is legitimately 1 byte)
    let mut ie = vec![0u8; 0x400];
    ie[0] = 0xDD;                 // WLAN_EID_VENDOR_SPECIFIC
    ie[1] = 0xFF;                 // element length (unchecked beyond wps_ielen)
    ie[2] = 0x00; ie[3] = 0x50; ie[4] = 0xF2; ie[5] = 0x04; // WPS OUI
    ie[6] = (target_id >> 8) as u8; ie[7] = target_id as u8; // attr_id BE16
    ie[8] = (data_len >> 8) as u8; ie[9] = data_len as u8;   // attr_data_len BE16
    emu.maps.write_bytes(IE, &ie);

    // destination buffer: a real 16-byte slab chunk tracked by the ledger.
    let buf = emu.kernel_alloc(Region::Slab, 1, "u8 sr (stack var in real caller)", "poc", true); // real dest is `u8 sr`
    println!("[{}] {} @ 0x{:x}: dest = 1-byte `u8 sr`, attacker WPS attr copies {} bytes", display, sym, addr, data_len);

    let wps_ielen: u64 = 0x100;
    // REAL upstream signature (5 args): (wps_ie, wps_ielen, target_attr_id, buf_content, len_content).
    // rcx=buf_content, r8=len_content. The function does memcpy(buf_content, attr+4, attr_len-4)
    // with NO destination-size arg -> the 1-byte `buf` overflows.
    let r = emu.kernel_call(addr, &[IE, wps_ielen, target_id as u64, buf, LEN_OUT]);
    eprintln!("    kernel_call ret = {:?}", r.map(|v| format!("0x{:x}", v)));
    let lc = emu.maps.read_dword(LEN_OUT);
    eprintln!("    *len_content = {:?}", lc);

    let findings = emu.kernel_findings();
    if findings.is_empty() {
        println!("[{}] NO findings (unexpected)", display);
    } else {
        for f in findings {
            println!("\n*** [{}] {} ***\n{}", display, sym, indent(&f.report()));
        }
    }
}

/// Drive rtw_get_wps_attr_content() with a WPS IE whose FIRST attribute declares
/// data_len = 0xFFFC and a NON-matching attr_id. In the vulnerable code
/// `u16 attr_len = attr_data_len + 4` wraps to 0, so rtw_get_wps_attr() does
/// `attr_ptr += 0` forever. Measure instructions executed by the call: a huge
/// delta (hits the 20M cap / 3s timeout) == endless loop; a tiny delta == fixed.
fn drive_loop(display: &str, path: &str) {
    let Some(mut emu) = fresh(path, false) else {
        println!("[{}] load failed", display);
        return;
    };
    let sym = "rtw_get_wps_attr_content";
    let Some(addr) = emu.module_symbol(sym) else {
        println!("[{}] no symbol {}", display, sym);
        return;
    };

    const IE: u64 = 0xffffe00000000000;
    const LEN_OUT: u64 = 0xffffe00000010000;
    let _ = emu.maps.create_map("poc.ie", IE, 0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.len", LEN_OUT, 0x100, Permission::READ_WRITE);

    let present_id: u16 = 0x0000; // NOT the target -> parser keeps iterating
    let target_id: u16 = 0x1041;  // WPS_ATTR_SELECTED_REGISTRAR (absent here)
    let data_len: u16 = 0xFFFC;   // +4 wraps u16 to 0 in the vulnerable build
    let mut ie = vec![0u8; 0x400];
    ie[0] = 0xDD;
    ie[1] = 0xFF;
    ie[2] = 0x00; ie[3] = 0x50; ie[4] = 0xF2; ie[5] = 0x04; // WPS OUI
    ie[6] = (present_id >> 8) as u8; ie[7] = present_id as u8;
    ie[8] = (data_len >> 8) as u8;  ie[9] = data_len as u8;
    emu.maps.write_bytes(IE, &ie);

    let buf = emu.kernel_alloc(Region::Slab, 1, "u8 sr", "poc", true);
    let wps_ielen: u64 = 0x100;

    let cap = emu.cfg.max_instructions.unwrap_or(0);
    let before = emu.instruction_count;
    let r = emu.kernel_call(addr, &[IE, wps_ielen, target_id as u64, buf, LEN_OUT]);
    let delta = emu.instruction_count.saturating_sub(before);
    let looped = cap > 0 && delta >= cap.saturating_sub(cap / 100); // within 1% of cap

    println!(
        "[{}] {}: attr data_len=0xFFFC, non-matching id -> {} instructions, ret={:?}",
        display, sym, delta, r.map(|v| format!("0x{:x}", v))
    );
    if looped {
        println!("[{}]  ==> ENDLESS LOOP (hit the {}-instruction cap)", display, cap);
    } else {
        println!("[{}]  ==> terminates cleanly (no loop)", display);
    }
}

/// Drive uvc_parse_standard_control(struct uvc_device*, const u8 *buffer, int buflen)
/// from uvcvideo with a crafted USB video-control descriptor. `dev` is a deref-safe
/// dummy: a region whose every 8 bytes point back into itself, so dev->field and
/// dev->field->field always land in mapped memory. The descriptor's length fields
/// drive uvc_alloc_new_entity() (tracked kzalloc) + memcpy; the ledger watches those.
fn run_uvc_case(path: &str, name: &str, buf: &[u8], buflen: u64) {
    let Some(mut emu) = fresh(path, false) else { println!("  [{}] load failed", name); return; };
    let Some(addr) = emu.module_symbol("uvc_parse_standard_control") else {
        println!("  [{}] no symbol uvc_parse_standard_control", name); return;
    };
    // struct uvc_device (offsets from pahole): udev@0, intf@8, entities@888, size 1144.
    // Zero-fill it (so numeric fields are 0 -> no runaway loops), then set only the
    // pointers that get dereferenced, plus an empty `entities` list for list_add_tail.
    const DEV: u64 = 0xffffe00001000000;
    const UDEV: u64 = 0xffffe00001100000;
    const INTF: u64 = 0xffffe00001200000;
    let _ = emu.maps.create_map("poc.dev", DEV, 0x2000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.udev", UDEV, 0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.intf", INTF, 0x1000, Permission::READ_WRITE);
    emu.maps.write_bytes(DEV, &vec![0u8; 0x2000]);
    emu.maps.write_bytes(UDEV, &vec![0u8; 0x1000]);
    emu.maps.write_bytes(INTF, &vec![0u8; 0x1000]);
    emu.maps.write_bytes(DEV, &UDEV.to_le_bytes());          // dev->udev @0
    emu.maps.write_bytes(DEV + 8, &INTF.to_le_bytes());      // dev->intf @8
    emu.maps.write_bytes(DEV + 888, &(DEV + 888).to_le_bytes()); // entities.next (empty list)
    emu.maps.write_bytes(DEV + 896, &(DEV + 888).to_le_bytes()); // entities.prev
    const BUF: u64 = 0xffffe00002000000;
    let _ = emu.maps.create_map("poc.buf", BUF, 0x4000, Permission::READ_WRITE);
    emu.maps.write_bytes(BUF, buf);
    let before = emu.instruction_count;
    let a0 = emu.kernel_alloc_count();
    let r = emu.kernel_call(addr, &[DEV, BUF, buflen]);
    let delta = emu.instruction_count.saturating_sub(before);
    let allocs = emu.kernel_alloc_count().saturating_sub(a0);
    let findings = emu.kernel_findings();
    println!("  [{}] ret={:?} instrs={} allocs={} findings={}", name,
             r.map(|v| v as i64), delta, allocs, findings.len());
    for f in findings { println!("{}", indent(&f.report())); }
}

fn drive_uvc(display: &str, path: &str) {
    println!("[{}] uvc_parse_standard_control(dev, buffer, buflen) — crafted VC descriptors", display);
    // INPUT_TERMINAL / camera: n = buffer[14] controls copied into entity extra
    {
        let mut b = vec![0u8; 0x100];
        b[1] = 0x24; b[2] = 0x02; b[3] = 0x01;   // CS_INTERFACE, INPUT_TERMINAL, id
        b[4] = 0x01; b[5] = 0x02;                 // wTerminalType = UVC_ITT_CAMERA (0x0201)
        b[14] = 0x40;                             // bControlSize = 64
        run_uvc_case(path, "input-terminal-camera n=0x40", &b, 0x100);
    }
    // EXTENSION_UNIT: p = buffer[21], n = buffer[22+p]
    {
        let mut b = vec![0u8; 0x100];
        b[1] = 0x24; b[2] = 0x06; b[3] = 0x02;   // EXTENSION_UNIT
        b[21] = 0x10;                             // p (bNrInPins) = 16
        b[22 + 0x10] = 0x40;                      // n (bControlSize) = 64
        run_uvc_case(path, "extension-unit p=0x10 n=0x40", &b, 0x100);
    }
    // EXTENSION_UNIT with p=0 and a large n
    {
        let mut b = vec![0u8; 0x200];
        b[1] = 0x24; b[2] = 0x06; b[3] = 0x03;
        b[21] = 0x00;                             // p = 0
        b[22] = 0xff;                             // n = 255
        run_uvc_case(path, "extension-unit p=0 n=0xff", &b, 0x200);
    }
}

/// Drive hid_open_report(struct hid_device*) -> hid_parse_collections(): the HID
/// report-descriptor parser (classic syzkaller memory-safety surface). We set up a
/// zeroed hid_device with: status=0 (not yet parsed), driver->report_fixup=0 (skip
/// the fixup copy), and bpf_rdesc/bpf_rsize pointing at a crafted report descriptor.
/// NOTE: offsets below are filled from `pahole -C hid_device` once hid.ko is built.
const HID_OFF_STATUS: u64 = 7160;
const HID_OFF_DRIVER: u64 = 7104;
const HID_OFF_BPF_RDESC: u64 = 8;
const HID_OFF_BPF_RSIZE: u64 = 28;

fn run_hid_case(path: &str, name: &str, rdesc: &[u8]) {
    let Some(mut emu) = fresh(path, false) else { println!("  [{}] load failed", name); return; };
    let Some(addr) = emu.module_symbol("hid_open_report") else {
        println!("  [{}] no symbol hid_open_report", name); return;
    };
    const DEV: u64 = 0xffffe00003000000;
    const DRV: u64 = 0xffffe00003100000;   // struct hid_driver (report_fixup=0 -> skip)
    const RDESC: u64 = 0xffffe00003200000; // crafted report descriptor
    let _ = emu.maps.create_map("poc.hdev", DEV, 0x8000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.hdrv", DRV, 0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.rdesc", RDESC, 0x4000, Permission::READ_WRITE);
    emu.maps.write_bytes(DEV, &vec![0u8; 0x8000]);
    emu.maps.write_bytes(DRV, &vec![0u8; 0x1000]);
    emu.maps.write_bytes(RDESC, rdesc);
    emu.maps.write_bytes(DEV + HID_OFF_DRIVER, &DRV.to_le_bytes());
    emu.maps.write_bytes(DEV + HID_OFF_BPF_RDESC, &RDESC.to_le_bytes());
    emu.maps.write_bytes(DEV + HID_OFF_BPF_RSIZE, &(rdesc.len() as u32).to_le_bytes());
    // report_enum@80, each hid_report_enum=2072, report_list@+8: init as empty lists
    for i in 0..3u64 {
        let l = DEV + 80 + i * 2072 + 8;
        emu.maps.write_bytes(l, &l.to_le_bytes());       // next = self
        emu.maps.write_bytes(l + 8, &l.to_le_bytes());   // prev = self
    }
    // HID_OFF_STATUS left 0 (not HID_STAT_PARSED)
    let before = emu.instruction_count;
    let a0 = emu.kernel_alloc_count();
    let r = emu.kernel_call(addr, &[DEV]);
    let delta = emu.instruction_count.saturating_sub(before);
    let allocs = emu.kernel_alloc_count().saturating_sub(a0);
    let findings = emu.kernel_findings();
    println!("  [{}] ret={:?} instrs={} allocs={} findings={}", name,
             r.map(|v| v as i64), delta, allocs, findings.len());
    for f in findings { println!("{}", indent(&f.report())); }
}

fn drive_hid(display: &str, path: &str) {
    println!("[{}] hid_open_report(dev) -> report-descriptor parser", display);
    // --- collection bisection ---
    run_hid_case(path, "bis-open-only", &[0x05,0x01, 0xA1,0x01]);
    run_hid_case(path, "bis-open-close", &[0x05,0x01, 0xA1,0x01, 0xC0]);
    run_hid_case(path, "bis-just-endcoll", &[0x05,0x01, 0xC0]);
    // --- diagnostic cases to locate where the parse stops (compare instrs) ---
    run_hid_case(path, "diag-1item-usagepage", &[0x05,0x01]);
    run_hid_case(path, "diag-2item", &[0x05,0x01, 0x09,0x06]);
    run_hid_case(path, "diag-globals-only", &[0x05,0x01, 0x75,0x08, 0x95,0x01]);
    run_hid_case(path, "diag-valid-mouse", &[
        0x05,0x01, 0x09,0x02, 0xA1,0x01, 0x09,0x01, 0xA1,0x00,
        0x05,0x09, 0x19,0x01, 0x29,0x03, 0x15,0x00, 0x25,0x01,
        0x95,0x03, 0x75,0x01, 0x81,0x02, 0x95,0x01, 0x75,0x05,
        0x81,0x01, 0x05,0x01, 0x09,0x30, 0x09,0x31, 0x15,0x81,
        0x25,0x7F, 0x75,0x08, 0x95,0x02, 0x81,0x06, 0xC0, 0xC0,
    ]);
    // minimal valid keyboard-ish descriptor
    run_hid_case(path, "minimal", &[
        0x05,0x01, 0x09,0x06, 0xA1,0x01, 0x75,0x08, 0x95,0x01, 0x81,0x00, 0xC0,
    ]);
    // large 16-bit Report Count
    run_hid_case(path, "report-count-0xffff", &[
        0x05,0x01, 0x09,0x06, 0xA1,0x01, 0x75,0x08, 0x96,0xFF,0xFF, 0x81,0x00, 0xC0,
    ]);
    // large Report Size + Count
    run_hid_case(path, "report-size-0xff-count-0xff", &[
        0x05,0x01, 0x09,0x06, 0xA1,0x01, 0x75,0xFF, 0x95,0xFF, 0x81,0x00, 0xC0,
    ]);
    // many nested collections
    {
        let mut d = vec![0x05,0x01, 0x09,0x06];
        for _ in 0..64 { d.extend_from_slice(&[0xA1,0x01]); }   // 64x Collection
        for _ in 0..64 { d.push(0xC0); }                        // 64x End Collection
        run_hid_case(path, "64-nested-collections", &d);
    }
}

/// Drive l2cap_parse_conf_req(chan, data, data_size): parses L2CAP config
/// options out of chan->conf_req (inline __u8[64], length chan->conf_len) — the
/// attacker-controlled input — and writes a response into `data`. chan->conn is
/// dereferenced (->feat_mask, ->mtu) so it must point at a mapped region.
/// Offsets from `pahole -C l2cap_chan` once bluetooth.ko is built without constprop.
const L2_OFF_CONN: u64 = 0;
const L2_OFF_MODE: u64 = 46;
const L2_OFF_CONF_REQ: u64 = 51;
const L2_OFF_CONF_LEN: u64 = 115;

fn run_l2cap_case(path: &str, name: &str, opts: &[u8]) {
    let Some(mut emu) = fresh(path, false) else { println!("  [{}] load failed", name); return; };
    let Some(addr) = emu.module_symbol("l2cap_parse_conf_req") else {
        println!("  [{}] no symbol l2cap_parse_conf_req", name); return;
    };
    const CHAN: u64 = 0xffffe00004000000;
    const CONN: u64 = 0xffffe00004100000;
    const OUT:  u64 = 0xffffe00004200000;
    let _ = emu.maps.create_map("poc.chan", CHAN, 0x4000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.conn", CONN, 0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.out",  OUT,  0x1000, Permission::READ_WRITE);
    emu.maps.write_bytes(CHAN, &vec![0u8; 0x4000]);
    emu.maps.write_bytes(CONN, &vec![0u8; 0x1000]);
    emu.maps.write_bytes(OUT,  &vec![0u8; 0x1000]);
    emu.maps.write_bytes(CHAN + L2_OFF_CONN, &CONN.to_le_bytes());      // chan->conn
    let clen = opts.len().min(64) as u8;
    emu.maps.write_bytes(CHAN + L2_OFF_CONF_REQ, &opts[..clen as usize]); // inline conf_req[64]
    emu.maps.write_bytes(CHAN + L2_OFF_CONF_LEN, &[clen]);                // conf_len (u8)
    // mode left 0 (L2CAP_MODE_BASIC)
    let before = emu.instruction_count;
    let a0 = emu.kernel_alloc_count();
    let r = emu.kernel_call(addr, &[CHAN, OUT, 0x400]);
    let delta = emu.instruction_count.saturating_sub(before);
    let allocs = emu.kernel_alloc_count().saturating_sub(a0);
    let findings = emu.kernel_findings();
    println!("  [{}] ret={:?} instrs={} allocs={} findings={}", name,
             r.map(|v| v as i64), delta, allocs, findings.len());
    for f in findings { println!("{}", indent(&f.report())); }
}

fn drive_l2cap(display: &str, path: &str) {
    println!("[{}] l2cap_parse_conf_req(chan, data, size) — crafted config options", display);
    // MTU option: type=1(MTU), len=2, val=u16
    run_l2cap_case(path, "mtu", &[0x01,0x02, 0x00,0x04]);
    // option declaring len far bigger than the buffer (bounds-check probe)
    run_l2cap_case(path, "oversized-len", &[0x01,0xff, 0x41,0x41,0x41,0x41]);
    // several options back to back
    run_l2cap_case(path, "multi", &[0x01,0x02,0x00,0x04, 0x02,0x02,0xff,0xff, 0x04,0x01,0x03]);
    // fill the whole 64-byte inline buffer with 1-byte options
    { let mut o=Vec::new(); while o.len()<60 { o.extend_from_slice(&[0x10,0x01,0xAA]); } run_l2cap_case(path,"fill64",&o); }

    println!("[{}] l2cap_parse_conf_rsp(chan, rsp, len, data, size, result)", display);
    run_l2cap_rsp_case(path, "rsp-mtu", &[0x01,0x02, 0x00,0x04]);
    run_l2cap_rsp_case(path, "rsp-oversized", &[0x01,0xff, 0x41,0x41]);
    run_l2cap_rsp_case(path, "rsp-multi", &[0x01,0x02,0x00,0x04, 0x04,0x09,1,2,3,4,5,6,7,8,9]);
}

fn run_l2cap_rsp_case(path: &str, name: &str, rsp: &[u8]) {
    let Some(mut emu) = fresh(path, false) else { println!("  [{}] load failed", name); return; };
    let Some(addr) = emu.module_symbol("l2cap_parse_conf_rsp") else {
        println!("  [{}] no symbol l2cap_parse_conf_rsp", name); return;
    };
    const CHAN: u64 = 0xffffe00004000000;
    const CONN: u64 = 0xffffe00004100000;
    const RSP:  u64 = 0xffffe00004300000;
    const OUT:  u64 = 0xffffe00004200000;
    const RES:  u64 = 0xffffe00004400000;
    let _ = emu.maps.create_map("poc.chan", CHAN, 0x4000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.conn", CONN, 0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.rsp",  RSP,  0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.out",  OUT,  0x1000, Permission::READ_WRITE);
    let _ = emu.maps.create_map("poc.res",  RES,  0x100,  Permission::READ_WRITE);
    emu.maps.write_bytes(CHAN, &vec![0u8; 0x4000]);
    emu.maps.write_bytes(CONN, &vec![0u8; 0x1000]);
    emu.maps.write_bytes(RSP, &vec![0u8; 0x1000]);
    emu.maps.write_bytes(CHAN + L2_OFF_CONN, &CONN.to_le_bytes());
    emu.maps.write_bytes(RSP, rsp);
    // l2cap_parse_conf_rsp(chan, rsp, len, data, size, result)
    let before = emu.instruction_count;
    let a0 = emu.kernel_alloc_count();
    let r = emu.kernel_call(addr, &[CHAN, RSP, rsp.len() as u64, OUT, 0x400, RES]);
    let delta = emu.instruction_count.saturating_sub(before);
    let allocs = emu.kernel_alloc_count().saturating_sub(a0);
    let findings = emu.kernel_findings();
    let result = emu.maps.read_word(RES).unwrap_or(0);
    println!("  [{}] ret={:?} result=0x{:x} instrs={} allocs={} findings={}", name,
             r.map(|v| v as i64), result, delta, allocs, findings.len());
    for f in findings { println!("{}", indent(&f.report())); }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: kohunt <init|probe> <file.ko|dir> [cap]");
        std::process::exit(1);
    }
    let mode = args[1].clone();
    let cap: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(48);
    let mut files = Vec::new();
    collect_ko(Path::new(&args[2]), &mut files);
    files.sort();
    eprintln!("[kohunt/{}] {} module(s), cap {}", mode, files.len(), cap);
    for (i, f) in files.iter().enumerate() {
        eprintln!("[{}/{}] {}", i + 1, files.len(), f.display());
        let Some(real) = materialize(f) else { continue };
        let path = real.to_string_lossy().to_string();
        let display = f.file_name().unwrap().to_string_lossy().replace(".ko.zst", ".ko");
        let m = mode.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match m.as_str() {
            "probe" => drive_probe(&display, &path, cap),
            "wps" => drive_wps(&display, &path),
            "loop" => drive_loop(&display, &path),
            "uvc" => drive_uvc(&display, &path),
            "hid" => drive_hid(&display, &path),
            "l2cap" => drive_l2cap(&display, &path),
            _ => drive_init(&display, &path, cap),
        }));
        if r.is_err() {
            println!("[{}] PANIC during analysis", f.file_name().unwrap().to_string_lossy());
        }
    }
    eprintln!("[kohunt] done");
}
