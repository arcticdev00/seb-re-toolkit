import argparse, sys, os, json, time, struct, math, re, hashlib, inspect
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

SEB_DIR = Path(r"C:\Program Files\SafeExamBrowser\Application")
DLL_PATH = SEB_DIR / "seb_x64.dll"
LOG_DIR = Path(__file__).parent / "seb_analysis_logs"

def hexdump(b, length=64, label=""):
    """Return a compact hex+ascii dump."""
    if not b:
        return "(empty)"
    b = bytes(b)[:length]
    out = label + (" " if label else "")
    out += b.hex().upper()
    out += "  " + "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    return out

def shannon_entropy(data):
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum(p/n * math.log2(p/n) for p in c.values())

def warn(msg):
    print(f"[!] {msg}")

def info(msg):
    print(f"[*] {msg}")

def ok(msg):
    print(f"[+] {msg}")

def sec(msg):
    print(f"    {msg}")

def cmd_info(args):
    if not DLL_PATH.exists():
        warn(f"SEB not found at {DLL_PATH}")
        return

    data = DLL_PATH.read_bytes()
    vi = DLL_PATH.stat()

    border = "-" * 60
    print(f"[seb_x64.dll Overview]")
    print(border)
    print(f"  File      : {DLL_PATH}")
    print(f"  Size      : {vi.st_size:,} bytes ({vi.st_size/1024/1024:.1f} MB)")
    print(f"  Modified  : {datetime.fromtimestamp(vi.st_mtime)}")
    print(f"  MD5       : {hashlib.md5(data).hexdigest()}")
    print(f"  SHA256    : {hashlib.sha256(data).hexdigest()}")
    print(f"  Entropy   : {shannon_entropy(data):.2f} / 8.0")

    # Authenticode
    try:
        r = subprocess.run(
            ["powershell", "-noprofile", "-c",
             f"Get-AuthenticodeSignature '{DLL_PATH}' | Format-List Status,SignerCertificate"],
            capture_output=True, timeout=10)
        stdout = r.stdout.decode('utf-8', errors='replace')
        for line in stdout.splitlines():
            ls = line.strip()
            if ls:
                print(f"  {ls}")
    except:
        pass

    arch = "x64"
    try:
        with open(DLL_PATH, 'rb') as f:
            f.seek(0x3C); pe_off = struct.unpack('<I', f.read(4))[0]
            f.seek(pe_off + 4)
            machine = struct.unpack('<H', f.read(2))[0]
            f.read(14)
            opt_hdr_size = struct.unpack('<H', f.read(2))[0]
            f.seek(pe_off + 4 + 20 + opt_hdr_size - 2)
            dll_char = struct.unpack('<H', f.read(2))[0]
            arch = "x64" if machine == 0x8664 else f"0x{machine:04X}"
    except:
        dll_char = 0

    print(f"  Arch      : {arch}")
    print(f"  DEP/NX    : {'ENABLED' if (dll_char & 0x0100) else 'DISABLED (Themida RWX)'}")
    print(f"  ASLR      : {'ENABLED' if (dll_char & 0x0040) else 'DISABLED (Themida)'}")
    print(f"  CFG       : {'ENABLED' if (dll_char & 0x4000) else 'DISABLED'}")

    if b".themida" in data:
        print(f"  Packer    : WinLicense/Themida 3.x")
        print(f"  Note      : 5.5 MB RWX .themida section, entry in .themida")

    print(border)

def cmd_static(args):
    if not DLL_PATH.exists():
        warn(f"SEB not found at {DLL_PATH}"); return

    import pefile
    data = DLL_PATH.read_bytes()
    pe = pefile.PE(str(DLL_PATH), fast_load=False)

    print(f"=== STATIC ANALYSIS =======================================")
    print(f"PE format  : {'PE32+' if pe.PE_TYPE == 0x20B else 'PE32'}")
    print(f"Linker     : {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")
    ts = pe.FILE_HEADER.TimeDateStamp
    print(f"Timestamp  : {datetime.fromtimestamp(ts, tz=timezone.utc)}  (0x{ts:08X})")
    print(f"ImageBase  : 0x{pe.OPTIONAL_HEADER.ImageBase:016X}")
    print(f"Subsystem  : {['UNKNOWN','NATIVE','GUI','CUI'][pe.OPTIONAL_HEADER.Subsystem]}")
    print(f"EntryPoint : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")

    # Sections
    print(f"\n-- Sections ----------------------------------------------")
    print(f"{'Name':12s} {'VAddr':>10s} {'VSize':>8s} {'Raw':>8s} {'Entropy':>8s}  {'Perms':>5s}")
    print("-" * 56)
    for s in pe.sections:
        name = s.Name.decode(errors='replace').rstrip('\x00')
        e = s.get_entropy()
        c = s.Characteristics
        perms = ""
        if c & 0x20000000: perms += "X"
        else: perms += "."
        if c & 0x40000000: perms += "R"
        else: perms += "."
        if c & 0x80000000: perms += "W"
        else: perms += "."
        note = ""
        if name == ".themida": note = " <-- Themida packer"
        elif e > 7.0: note = " <-- encrypted"
        print(f"{name:12s} 0x{s.VirtualAddress:08X} 0x{s.Misc_VirtualSize:06X} "
              f"0x{s.SizeOfRawData:06X} {e:>7.2f}  {perms:>5s}{note}")

    # Rich header
    print(f"\n-- Compiler Fingerprint ----------------------------------")
    try:
        rich = pe.parse_rich_header()
        if rich:
            key = rich.get("key", 0)
            prods = {}
            for r in rich.get("records", []):
                p = r["product_name"]
                prods[p] = prods.get(p, 0) + r["count"]
            print(f"Rich Key  : 0x{key:X}")
            for p, cnt in sorted(prods.items(), key=lambda x: -x[1]):
                print(f"  {p:40s} x{cnt}")
    except:
        print("  (not available)")

    # Exports
    print(f"\n-- Exports ------------------------------------------------")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exp = pe.DIRECTORY_ENTRY_EXPORT
        print(f"Name: {exp.name.decode(errors='replace')}")
        print(f"Functions: {exp.struct.NumberOfFunctions}  Names: {exp.struct.NumberOfNames}")
        print(f"Entry point RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        print(f"")
        # Determine which section each export lives in
        for sym in exp.symbols:
            name = sym.name.decode(errors='replace') if sym.name else f"ORD_{sym.ordinal}"
            rva = sym.address
            sec_name = "?"
            for s in pe.sections:
                if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                    sec_name = s.Name.decode(errors='replace').rstrip('\x00')
                    break
            print(f"  [{sym.ordinal:3d}] {name:40s} RVA=0x{rva:08X}  ({sec_name})")
    else:
        print("  (no exports)")

    # Imports (visible only -- Themida hides the real ones)
    print(f"\n-- Visible Imports (spoofed by Themida) -------------------")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        total = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='replace')
            apis = [imp.name.decode(errors='replace') if imp.name else f'ORD_{imp.ordinal}'
                    for imp in entry.imports]
            total += len(apis)
            print(f"  {dll}:")
            for a in apis[:20]:
                print(f"    {a}")
            if len(apis) > 20:
                print(f"    ... ({len(apis)-20} more)")
        print(f"  Total: {total} imports across {len(list(pe.DIRECTORY_ENTRY_IMPORT))} DLLs")
        print(f"  (Themida resolves real imports at runtime -- these are decoys)")

    # Resources
    print(f"\n-- Resources ----------------------------------------------")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        def walk(node, indent=2):
            for e in node.directory.entries:
                if hasattr(e, 'directory'):
                    walk(e.directory, indent+2)
                else:
                    t = pefile.RESOURCE_TYPE.get(e.data.struct.Id, f"ID:{e.data.struct.Id}")
                    print(f"{' '*indent}{t}: {e.data.struct.Size} bytes")
        try:
            walk(pe.DIRECTORY_ENTRY_RESOURCE)
        except:
            print("  (parse error)")
    else:
        print("  (none)")

    # TLS callbacks (used by Themida for anti-debug)
    print(f"\n-- TLS ----------------------------------------------------")
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        tls = pe.DIRECTORY_ENTRY_TLS
        cb = tls.struct.AddressOfCallBacks
        print(f"  Callbacks table : 0x{cb:016X}")
        # read callback pointers
        off = cb - pe.OPTIONAL_HEADER.ImageBase
        for i in range(4):
            try:
                ptr = struct.unpack('<Q', data[off:off+8])[0]
                if ptr == 0: break
                print(f"  Callback[{i}]   : 0x{ptr:016X}")
                off += 8
            except:
                break
    else:
        print("  (none)")


def cmd_detect(args):
    if not DLL_PATH.exists():
        warn(f"SEB not found at {DLL_PATH}"); return

    data = DLL_PATH.read_bytes()
    print(f"=== PACKER / SECURITY DETECTION ============================")

    # Themida/WinLicense specific
    checks = [
        (b".themida", "Themida section present"),
        (b"WinLicense", "WinLicense string"),
        (b"ORESNO", "Oreans signature (Themida)"),
        (b"!This program", "Generic packer warning"),
        (b"UPX", "UPX signature"),
        (b"MPRESS", "MPRESS signature"),
        (b"VMP", "VMProtect"),
        (b"VProtect", "VProtect"),
        (b"Enigma", "Enigma Protector"),
    ]
    found = 0
    for sig, label in checks:
        if sig in data:
            idx = data.find(sig)
            print(f"  [+] {label:45s} @ offset 0x{idx:X}")
            found += 1
    if found == 0:
        print("  No known packer signatures found")

    # Section anomalous permissions
    import pefile
    try:
        pe = pefile.PE(str(DLL_PATH))
        print(f"\n-- Anomalous Sections ----------------------------------")
        for s in pe.sections:
            name = s.Name.decode(errors='replace').rstrip('\x00')
            c = s.Characteristics
            is_rwx = (c & 0x20000000) and (c & 0x40000000) and (c & 0x80000000)
            high_entropy = s.get_entropy() > 7.0
            huge = s.SizeOfRawData > 1024 * 1024
            flags = []
            if is_rwx: flags.append("RWX")
            if high_entropy: flags.append("HIGH_ENTROPY")
            if huge: flags.append("LARGE")
            if flags:
                print(f"  {name:12s} {' | '.join(flags)}")

        # DLL characteristics analysis
        print(f"\n-- Security Features (from PE header) -----------------")
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        for mask, name in [
            (0x0040, "ASLR (DYNAMIC_BASE)"),
            (0x0100, "DEP (NX_COMPAT)"),
            (0x4000, "Control Flow Guard"),
            (0x0080, "Force Integrity"),
            (0x1000, "AppContainer"),
            (0x8000, "Terminal Server Aware"),
        ]:
            print(f"  {'+' if dc & mask else '-'} {name}")

        # Check for Authenticode signature
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        print(f"  {'+' if sec.Size > 0 else '-'} Authenticode signature (size={sec.Size} bytes)")

        print(f"\n-- Integrity Recommendations --------------------------")
        if dc & 0x0100 == 0:
            print("  ! DEP disabled (Themida requires RWX for code emission)")
        if dc & 0x0040 == 0:
            print("  ! ASLR disabled (image base fixed)")
        if b".themida" in data:
            print("  ! Themida packer detected -- static analysis limited")
            print("  ! Real imports are resolved at runtime")
            print("  ! Code sections encrypted; decrypted at runtime")
    except Exception as e:
        warn(f"PE parse error: {e}")


def cmd_call(args):
    """
    Call seb_x64.dll exports directly via ctypes with proper BSTR handling.
    Only works after the DLL is initialized by SEB -- otherwise results
    may be incorrect (Themida blocks out-of-context calls).
    """
    import ctypes, ctypes.wintypes as w

    DLL = str(DLL_PATH)
    LOG = LOG_DIR / f"call_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    LOG_DIR.mkdir(exist_ok=True)

    k32 = ctypes.WinDLL("kernel32", use_last_error=False)
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [w.HMODULE, ctypes.c_void_p]
    k32.LoadLibraryW.restype = w.HMODULE
    k32.LoadLibraryW.argtypes = [w.LPCWSTR]
    k32.FreeLibrary.restype = w.BOOL
    k32.FreeLibrary.argtypes = [w.HMODULE]

    oa = ctypes.WinDLL("oleaut32", use_last_error=False)
    oa.SysFreeString.restype = None
    oa.SysFreeString.argtypes = [ctypes.c_void_p]
    oa.SysStringLen.restype = ctypes.c_uint
    oa.SysStringLen.argtypes = [ctypes.c_void_p]
    oa.SysAllocString.restype = ctypes.c_void_p
    oa.SysAllocString.argtypes = [w.LPCWSTR]

    def read_bstr(p):
        if not p: return "(null)"
        length = oa.SysStringLen(p)
        return ctypes.wstring_at(p, length)

    def make_bstr(s):
        return oa.SysAllocString(s)

    def free_bstr(p):
        if p: oa.SysFreeString(p)

    def call_bstr_export(addr, *str_args):
        """Call BOOL __cdecl(BSTR, BSTR) or similar returning BSTR as c_void_p."""
        if not addr:
            return None, "NOT_FOUND"
        param_ct = [ctypes.c_void_p] * len(str_args)
        fn = ctypes.CFUNCTYPE(ctypes.c_void_p, *param_ct)(addr)
        bstrs = [make_bstr(s) for s in str_args]
        try:
            result = fn(*bstrs)
            if result and result != 0:
                return read_bstr(result), "OK"
            return None, "NULL"
        except Exception as e:
            return None, f"EXCEPTION: {e}"
        finally:
            for b in bstrs:
                free_bstr(b)

    def call_vm_export(addr):
        if not addr: return None, "NOT_FOUND"
        fn = ctypes.CFUNCTYPE(w.BOOL, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int))(addr)
        mfr_ptr = ctypes.c_void_p(0)
        prob = ctypes.c_int(0)
        try:
            ok = fn(ctypes.byref(mfr_ptr), ctypes.byref(prob))
            mfr = read_bstr(mfr_ptr.value) if mfr_ptr.value else "(null)"
            if mfr_ptr.value: free_bstr(mfr_ptr.value)
            return {"is_vm": bool(ok), "manufacturer": mfr, "probability": prob.value}, "OK"
        except Exception as e:
            return None, f"EXCEPTION: {e}"

    def call_void_bool(addr):
        if not addr: return None, "NOT_FOUND"
        fn = ctypes.CFUNCTYPE(w.BOOL)(addr)
        try:
            return bool(fn()), "OK"
        except Exception as e:
            return None, f"EXCEPTION: {e}"

    print(f"+== Calling seb_x64.dll exports via ctypes ===============")
    print(f"| DLL: {DLL}")
    print(f"| Log: {LOG}")
    print(f"|")
    print(f"| Note: Themida protects the DLL. Without SEB context:")
    print(f"|   - CalculateAppSignatureKey --> non-deterministic output")
    print(f"|   - CalculateBrowserExamKey  --> constant per-load value")
    print(f"|   - IsVirtualMachine         --> only works after init cal")
    print(f"|   - VerifyCodeSignature      --> always returns FALSE")
    print(f"+===========================================================")

    log_lines = []
    def add(msg):
        print(msg)
        log_lines.append(msg)

    hmod = k32.LoadLibraryW(DLL)
    add(f"\nLoadLibraryW: 0x{hmod:016X}" if hmod else f"LoadLibraryW FAILED")

    if not hmod:
        return

    exports = {}
    for name in ["CalculateAppSignatureKey", "CalculateBrowserExamKey",
                  "IsVirtualMachine", "VerifyCodeSignature"]:
        addr = k32.GetProcAddress(hmod, name.encode())
        exports[name] = addr
        add(f"  {'+' if addr else '-'} {name}: {'@ 0x%016X' % addr if addr else 'not found'}")

    # -- CalculateAppSignatureKey --
    add("\n-- CalculateAppSignatureKey(BSTR token, BSTR salt) -> BSTR --")
    for token, salt in [("test-token", "test-salt"), ("", ""),
                         ("SafeExamBrowser", "examsalt")]:
        val, status = call_bstr_export(exports["CalculateAppSignatureKey"], token, salt)
        add(f"  token={token!r:20s} salt={salt!r:20s} --> {val[:64] if val else status}")

    # -- CalculateBrowserExamKey --
    add("\n-- CalculateBrowserExamKey(BSTR cfgKey, BSTR salt) -> BSTR --")
    for ck, salt in [("cfg-key", "bek-salt"), ("", "")]:
        val, status = call_bstr_export(exports["CalculateBrowserExamKey"], ck, salt)
        add(f"  cfgKey={ck!r:20s} salt={salt!r:20s} --> {val if val else status}")

    # -- IsVirtualMachine --
    add("\n-- IsVirtualMachine(BSTR* out mfr, int* out prob) -> BOOL --")
    result, status = call_vm_export(exports["IsVirtualMachine"])
    if status == "OK":
        add(f"  isVM={result['is_vm']}  manufacturer={result['manufacturer']!r}  "
            f"probability={result['probability']}%")
    else:
        add(f"  {status}")

    # -- VerifyCodeSignature --
    add("\n-- VerifyCodeSignature() -> BOOL --")
    val, status = call_void_bool(exports["VerifyCodeSignature"])
    add(f"  --> {val}")

    k32.FreeLibrary(hmod)
    add("\nDone. This data may differ from SEB-context calls (see 'trace' subcommand).")

    with open(LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    print(f"\n[*] Log saved: {LOG}")


def cmd_trace(args):
    """
    Frida-based tracer. Intercepts seb_x64.dll exports in the real
    SafeExamBrowser process and logs every call with parameters.
    """
    try:
        import frida
    except ImportError:
        warn("Frida not installed. Run: pip install frida-tools")
        return

    JS_HOOK = """
    'use strict';
    const LOG_DIR = '{log_dir}';
    let logFile = null;
    const NAMES = ['CalculateAppSignatureKey','CalculateBrowserExamKey',
                   'IsVirtualMachine','VerifyCodeSignature'];
    let callN = {};
    let hooked = false;

    function b2s(b) {
        if (b.isNull()) return '(null)';
        try {
            const len = b.add(-4).readU32();
            return len ? b.readUtf16String(len) : '(empty)';
        } catch(e) { return '(error)'; }
    }

    function b2h(b) {
        if (b.isNull()) return '(null)';
        try {
            const len = b.add(-4).readU32();
            const arr = new Uint8Array(b.readByteArray(len * 2));
            return Array.from(arr).map(x => x.toString(16).padStart(2,'0')).join('');
        } catch(e) { return '(error)'; }
    }

    function log(m) {
        const t = new Date();
        const ts = t.getHours().toString().padStart(2,'0') + ':' +
                   t.getMinutes().toString().padStart(2,'0') + ':' +
                   t.getSeconds().toString().padStart(2,'0') + '.' +
                   t.getMilliseconds().toString().padStart(3,'0');
        const line = '[' + ts + '] ' + m;
        if (logFile) { logFile.write(line + '\\n'); logFile.flush(); }
        send({type:'log', line:line});
    }

    function hook(name, addr) {
        callN[name] = 0;
        Interceptor.attach(addr, {
            onEnter(args) {
                callN[name]++;
                log(name + ' #' + callN[name]);
                if (name.indexOf('Calculate') !== -1) {
                    log('  arg0: "' + b2s(args[0]) + '"');
                    log('  arg0(hex): ' + b2h(args[0]));
                    log('  arg1: "' + b2s(args[1]) + '"');
                    log('  arg1(hex): ' + b2h(args[1]));
                } else if (name === 'IsVirtualMachine') {
                    log('  manufacturer out: ' + args[0]);
                    log('  probability out:  ' + args[1]);
                }
            },
            onLeave(ret) {
                const n = callN[name];
                if (name.indexOf('Calculate') !== -1) {
                    const r = ret.toInt32() ? ret : ptr(0);
                    log('  => "' + (r.isNull() ? '(null)' : b2s(r)) + '"');
                    if (!r.isNull()) log('  => hex: ' + b2h(r));
                } else if (name === 'IsVirtualMachine') {
                    log('  => BOOL: ' + ret.toInt32());
                    try {
                        const mfr = this.context.rcx;
                        const prob = this.context.rdx;
                        if (mfr && !mfr.isNull()) {
                            const v = mfr.readPointer();
                            log('  => manufacturer: ' + b2s(v));
                        }
                        if (prob && !prob.isNull()) {
                            log('  => probability: ' + prob.readU32() + '%');
                        }
                    } catch(e) { log('  => (out-param error: ' + e.message + ')'); }
                } else if (name === 'VerifyCodeSignature') {
                    log('  => BOOL: ' + ret.toInt32());
                }
                log('');
            }
        });
        log('HOOK: ' + name);
    }

    function tryHook() {
        if (hooked) return;
        const mod = Process.findModuleByName('seb_x64.dll');
        if (!mod) return;
        hooked = true;
        log('=== SEB TRACE START === PID=' + Process.id + ' MOD=' + mod.base);
        const exps = mod.enumerateExports();
        let n = 0;
        for (const e of exps) {
            if (NAMES.indexOf(e.name) !== -1) { hook(e.name, e.address); n++; }
        }
        log('Hooked ' + n + '/' + NAMES.length);
    }

    tryHook();
    const iv = setInterval(function() { tryHook(); if (hooked) clearInterval(iv); }, 100);
    """

    JS_HOOK = JS_HOOK.replace('{log_dir}', str(LOG_DIR).replace('\\', '\\\\'))

    device = frida.get_local_device()

    if args.attach:
        target = None
        for p in device.enumerate_processes():
            if args.attach.lower() in p.name.lower():
                target = p; break
        if not target:
            warn(f"Process '{args.attach}' not found")
            # list candidates
            for p in device.enumerate_processes():
                nm = p.name.lower()
                if 'safe' in nm or 'seb' in nm or 'browser' in nm:
                    sec(f"  PID {p.pid}: {p.name}")
            return
        print(f"[*] Attaching to PID {target.pid}: {target.name}")
        session = device.attach(target.pid)
    else:
        exe = args.exe or str(SEB_DIR / "SafeExamBrowser.exe")
        print(f"[*] Spawning: {exe}")
        pid = frida.spawn([exe])
        session = device.attach(pid)
        frida.resume(pid)
        print(f"[*] PID {pid}")

    log_path = LOG_DIR / f"trace_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    LOG_DIR.mkdir(exist_ok=True)
    console = open(log_path, 'w', encoding='utf-8')

    def on_msg(msg, _data):
        if msg.get('type') == 'send':
            line = msg.get('payload', {}).get('line', '')
            print(line)
            console.write(line + '\n'); console.flush()

    script = session.create_script(JS_HOOK, runtime='v8')
    script.on('message', on_msg)
    script.load()

    timeout = args.timeout or 60
    print(f"[*] Tracing for {timeout}s (Ctrl+C to stop early)...")
    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
        console.close()
        print(f"\n[*] Trace saved: {log_path}")


def cmd_exports(args):
    if not DLL_PATH.exists():
        warn(f"SEB not found at {DLL_PATH}"); return

    import pefile
    pe = pefile.PE(str(DLL_PATH))

    print(f"=== EXPORT DETAILS ========================================")
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("  (no exports)")

    # Signature reference from SEB open source
    sigs = {
        "CalculateAppSignatureKey":
            ("BSTR __cdecl(BSTR connectionToken, BSTR salt)\n"
             "   Returns: SHA-384 hex string (96 chars)\n"
             "   Note: Non-deterministic outside SEB context; "
             "call-site verification by Themida"),
        "CalculateBrowserExamKey":
            ("BSTR __cdecl(BSTR configurationKey, BSTR salt)\n"
             "   Returns: SHA-256 hex string (64 chars), constant per session\n"
             "   Note: Output same for all inputs within a session; "
             "changes per DLL load"),
        "IsVirtualMachine":
            ("BOOL __cdecl(BSTR* out manufacturer, int* out probability)\n"
             "   Returns: TRUE if VM detected\n"
             "   out manufacturer: BSTR with VM vendor name\n"
             "   out probability:  int 0-100 confidence"),
        "VerifyCodeSignature":
            ("BOOL __cdecl()\n"
             "   Returns: TRUE if calling module signature is valid\n"
             "   Note: Verifies SafeExamBrowser.Client.exe Authenticode sig"),
    }

    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = sym.name.decode(errors='replace') if sym.name else f"ORD_{sym.ordinal}"
        print(f"\n-- {name} ----------------------------------------------")
        sig = sigs.get(name, "(unknown signature)")
        for line in sig.split('\n'):
            print(f"  {line}")

        # Show section location
        rva = sym.address
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                sname = s.Name.decode(errors='replace').rstrip('\x00')
                off = rva - s.VirtualAddress
                print(f"  Location: {sname}+0x{off:X}  (RVA=0x{rva:08X})")
                break

        # Show thematic context
        ctx = {
            "CalculateAppSignatureKey": "App Signature Key for exam connection authentication",
            "CalculateBrowserExamKey": "Browser Exam Key for session binding integrity",
            "IsVirtualMachine": "Anti-cheating VM detection",
            "VerifyCodeSignature": "Code integrity verification",
        }.get(name, "")
        if ctx:
            print(f"  Purpose: {ctx}")


def main():
    p = argparse.ArgumentParser(
        description="seb_analyzer -- SEB Anti-Tamper Analysis Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  seb_analyzer.py info
  seb_analyzer.py static
  seb_analyzer.py detect
  seb_analyzer.py exports
  seb_analyzer.py call
  seb_analyzer.py trace                    (spawns SEB, 60s default)
  seb_analyzer.py trace -t 120             (2 minutes)
  seb_analyzer.py trace --attach SEB       (attach to running SEB)
        """)
    p.add_argument('--dll', default=str(DLL_PATH), help=f"Path to seb_x64.dll")
    sub = p.add_subparsers(dest='cmd', required=True)

    # info
    p_info = sub.add_parser('info', help='Quick DLL overview')

    # static
    p_static = sub.add_parser('static', help='Deep static PE analysis')

    # detect
    p_detect = sub.add_parser('detect', help='Themida/packer detection')

    # exports
    p_exports = sub.add_parser('exports', help='Export signatures and details')

    # call
    p_call = sub.add_parser('call', help='Call exports via ctypes (limited)')

    # trace
    p_trace = sub.add_parser('trace', help='Frida real-time hooking of SEB')
    p_trace.add_argument('--attach', '-a', help='Attach to existing process name')
    p_trace.add_argument('--exe', default=str(SEB_DIR / "SafeExamBrowser.exe"),
                         help='SEB executable path')
    p_trace.add_argument('--timeout', '-t', type=int, default=60,
                         help='Trace duration in seconds (default 60)')

    args = p.parse_args()

    # Use provided DLL path
    dll_path = Path(args.dll)
    if not dll_path.exists() and args.cmd != 'trace':
        warn(f"DLL not found: {dll_path}")
        return

    LOG_DIR.mkdir(exist_ok=True)

    # Dispatch
    dispatch = {
        'info': cmd_info,
        'static': cmd_static,
        'detect': cmd_detect,
        'exports': cmd_exports,
        'call': cmd_call,
        'trace': cmd_trace,
    }
    dispatch[args.cmd](args)


if __name__ == '__main__':
    main()
