import sys, os, io, threading, time as time_module
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path

SEB_DIR = Path(r"C:\Program Files\SafeExamBrowser\Application")
ANALYZER_DIR = Path(__file__).parent
sys.path.insert(0, str(ANALYZER_DIR))

import seb_analyzer as ana


class StdoutRedirect(io.StringIO):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def write(self, s):
        super().write(s)
        self.text_widget.after(0, self._append, s)

    def _append(self, s):
        self.text_widget.insert(END, s)
        self.text_widget.see(END)


def run_async(target, text_widget, btn=None, done_callback=None):
    old_stdout = sys.stdout
    redirect = StdoutRedirect(text_widget)
    sys.stdout = redirect

    def task():
        try:
            target()
        except Exception as e:
            text_widget.after(0, lambda: text_widget.insert(END, f"\n[!] Error: {e}\n"))
        finally:
            sys.stdout = old_stdout
            if btn:
                text_widget.after(0, lambda: btn.config(state=NORMAL))
            if done_callback:
                text_widget.after(0, done_callback)

    if btn:
        btn.config(state=DISABLED)
    threading.Thread(target=task, daemon=True).start()


class SEBGUI:
    def __init__(self):
        self.root = Tk()
        self.root.title("SEB Analyzer")
        self.root.geometry("1100x750")
        self.root.minsize(800, 500)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=BOTH, expand=True, padx=5, pady=5)

        self._build_info_tab()
        self._build_static_tab()
        self._build_detect_tab()
        self._build_exports_tab()
        self._build_call_tab()
        self._build_trace_tab()

    def _make_tab(self, title):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)

        top = ttk.Frame(frame)
        top.pack(fill=X, padx=5, pady=5)

        btn = ttk.Button(top, text=f"Run {title}")
        btn.pack(side=LEFT, padx=2)

        text = scrolledtext.ScrolledText(frame, wrap=WORD, font=("Consolas", 10),
                                         bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        text.pack(fill=BOTH, expand=True, padx=5, pady=5)

        return frame, btn, text

    def _build_info_tab(self):
        self._info_frame, self._info_btn, self._info_text = self._make_tab("Overview")
        self._info_btn.config(command=lambda: run_async(
            lambda: ana.cmd_info(type("a",(),{"dll":str(ana.DLL_PATH)})()),
            self._info_text, self._info_btn))

    def _build_static_tab(self):
        self._static_frame, self._static_btn, self._static_text = self._make_tab("Static")
        self._static_btn.config(command=lambda: run_async(
            lambda: ana.cmd_static(type("a",(),{"dll":str(ana.DLL_PATH)})()),
            self._static_text, self._static_btn))

    def _build_detect_tab(self):
        self._detect_frame, self._detect_btn, self._detect_text = self._make_tab("Detection")
        self._detect_btn.config(command=lambda: run_async(
            lambda: ana.cmd_detect(type("a",(),{"dll":str(ana.DLL_PATH)})()),
            self._detect_text, self._detect_btn))

    def _build_exports_tab(self):
        self._exports_frame, self._exports_btn, self._exports_text = self._make_tab("Exports")
        self._exports_btn.config(command=lambda: run_async(
            lambda: ana.cmd_exports(type("a",(),{"dll":str(ana.DLL_PATH)})()),
            self._exports_text, self._exports_btn))

    def _build_call_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Call")
        self._call_frame = frame

        controls = ttk.LabelFrame(frame, text="Call Parameters")
        controls.pack(fill=X, padx=5, pady=5)

        row = ttk.Frame(controls)
        row.pack(fill=X, padx=5, pady=2)
        ttk.Label(row, text="Test token:").pack(side=LEFT)
        self._call_token = ttk.Entry(row, width=30)
        self._call_token.insert(0, "test-token")
        self._call_token.pack(side=LEFT, padx=5)
        ttk.Label(row, text="Test salt:").pack(side=LEFT)
        self._call_salt = ttk.Entry(row, width=30)
        self._call_salt.insert(0, "test-salt")
        self._call_salt.pack(side=LEFT, padx=5)

        row2 = ttk.Frame(controls)
        row2.pack(fill=X, padx=5, pady=2)
        ttk.Label(row2, text="BEK cfgKey:").pack(side=LEFT)
        self._call_cfgkey = ttk.Entry(row2, width=30)
        self._call_cfgkey.insert(0, "cfg-key")
        self._call_cfgkey.pack(side=LEFT, padx=5)
        ttk.Label(row2, text="BEK salt:").pack(side=LEFT)
        self._call_beksalt = ttk.Entry(row2, width=30)
        self._call_beksalt.insert(0, "bek-salt")
        self._call_beksalt.pack(side=LEFT, padx=5)

        btn_frame = ttk.Frame(controls)
        btn_frame.pack(fill=X, padx=5, pady=5)
        self._call_btn = ttk.Button(btn_frame, text="▶  Run Call")
        self._call_btn.pack(side=LEFT, padx=2)

        self._call_text = scrolledtext.ScrolledText(frame, wrap=WORD, font=("Consolas", 10),
                                                     bg="#1e1e1e", fg="#d4d4d4",
                                                     insertbackground="white")
        self._call_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

        self._call_btn.config(command=self._run_call)

    def _run_call(self):
        self._call_btn.config(state=DISABLED)
        self._call_text.delete(1.0, END)

        def task():
            import ctypes, ctypes.wintypes as w
            old_stdout = sys.stdout
            sys.stdout = StdoutRedirect(self._call_text)
            try:
                k32 = ctypes.WinDLL("kernel32", use_last_error=False)
                k32.GetProcAddress.restype = ctypes.c_void_p
                k32.GetProcAddress.argtypes = [w.HMODULE, ctypes.c_void_p]
                k32.LoadLibraryW.restype = w.HMODULE
                k32.LoadLibraryW.argtypes = [w.LPCWSTR]
                k32.FreeLibrary.restype = w.BOOL
                k32.FreeLibrary.argtypes = [w.HMODULE]

                hmod = k32.LoadLibraryW(str(ana.DLL_PATH))
                if not hmod:
                    print("[!] LoadLibraryW FAILED")
                    return
                print(f"[*] LoadLibraryW: 0x{hmod:016X}")

                oa = ctypes.WinDLL("oleaut32", use_last_error=False)
                oa.SysFreeString.restype = None
                oa.SysFreeString.argtypes = [ctypes.c_void_p]
                oa.SysStringLen.restype = ctypes.c_uint
                oa.SysStringLen.argtypes = [ctypes.c_void_p]
                oa.SysAllocString.restype = ctypes.c_void_p
                oa.SysAllocString.argtypes = [w.LPCWSTR]

                def read_bstr(p):
                    if not p: return "(null)"
                    return ctypes.wstring_at(p, oa.SysStringLen(p))

                def make_bstr(s):
                    return oa.SysAllocString(s)

                def free_bstr(p):
                    if p: oa.SysFreeString(p)

                names = ["CalculateAppSignatureKey", "CalculateBrowserExamKey",
                         "IsVirtualMachine", "VerifyCodeSignature"]
                for name in names:
                    addr = k32.GetProcAddress(hmod, name.encode())
                    print(f"  {name}: @ 0x{addr:016X}" if addr else f"  {name}: not found")

                token, salt, cfgkey, beksalt = (
                    self._call_token.get(), self._call_salt.get(),
                    self._call_cfgkey.get(), self._call_beksalt.get())

                print("\n-- CalculateAppSignatureKey --")
                addr = k32.GetProcAddress(hmod, b"CalculateAppSignatureKey")
                if addr:
                    fn = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(addr)
                    b1, b2 = make_bstr(token), make_bstr(salt)
                    res = fn(b1, b2)
                    out = read_bstr(res) if res else "(null)"
                    free_bstr(b1); free_bstr(b2)
                    print(f"  token={token!r}  salt={salt!r}")
                    print(f"  --> {out[:96]}")

                print("\n-- CalculateBrowserExamKey --")
                addr = k32.GetProcAddress(hmod, b"CalculateBrowserExamKey")
                if addr:
                    fn = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(addr)
                    b1, b2 = make_bstr(cfgkey), make_bstr(beksalt)
                    res = fn(b1, b2)
                    out = read_bstr(res) if res else "(null)"
                    free_bstr(b1); free_bstr(b2)
                    print(f"  cfgKey={cfgkey!r}  salt={beksalt!r}")
                    print(f"  --> {out}")

                print("\n-- IsVirtualMachine --")
                addr = k32.GetProcAddress(hmod, b"IsVirtualMachine")
                if addr:
                    fn = ctypes.CFUNCTYPE(w.BOOL, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int))(addr)
                    mfr_ptr = ctypes.c_void_p(0)
                    prob = ctypes.c_int(0)
                    ok = fn(ctypes.byref(mfr_ptr), ctypes.byref(prob))
                    mfr = read_bstr(mfr_ptr.value) if mfr_ptr.value else "(null)"
                    if mfr_ptr.value: free_bstr(mfr_ptr.value)
                    print(f"  isVM={bool(ok)}  manufacturer={mfr!r}  probability={prob.value}%")

                print("\n-- VerifyCodeSignature --")
                addr = k32.GetProcAddress(hmod, b"VerifyCodeSignature")
                if addr:
                    fn = ctypes.CFUNCTYPE(w.BOOL)(addr)
                    print(f"  --> {bool(fn())}")

                k32.FreeLibrary(hmod)
                print("\n[*] Done")
            except Exception as e:
                import traceback
                print(f"[!] {e}")
                traceback.print_exc()
            finally:
                sys.stdout = old_stdout
                self._call_text.after(0, lambda: self._call_btn.config(state=NORMAL))

        threading.Thread(target=task, daemon=True).start()

    def _build_trace_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Trace")
        self._trace_frame = frame

        controls = ttk.LabelFrame(frame, text="Trace Configuration")
        controls.pack(fill=X, padx=5, pady=5)

        row = ttk.Frame(controls)
        row.pack(fill=X, padx=5, pady=2)
        ttk.Label(row, text="Mode:").pack(side=LEFT)
        self._trace_mode = ttk.Combobox(row, values=["Spawn SEB", "Attach to PID"],
                                        state="readonly", width=20)
        self._trace_mode.current(0)
        self._trace_mode.pack(side=LEFT, padx=5)
        ttk.Label(row, text="Target:").pack(side=LEFT)
        self._trace_target = ttk.Entry(row, width=40)
        self._trace_target.insert(0, "SafeExamBrowser")
        self._trace_target.pack(side=LEFT, padx=5)
        ttk.Label(row, text="Timeout (s):").pack(side=LEFT)
        self._trace_timeout = ttk.Entry(row, width=8)
        self._trace_timeout.insert(0, "60")
        self._trace_timeout.pack(side=LEFT, padx=5)

        btn_frame = ttk.Frame(controls)
        btn_frame.pack(fill=X, padx=5, pady=5)
        self._trace_start_btn = ttk.Button(btn_frame, text="Start Trace")
        self._trace_start_btn.pack(side=LEFT, padx=2)
        self._trace_stop_btn = ttk.Button(btn_frame, text="Stop", state=DISABLED)
        self._trace_stop_btn.pack(side=LEFT, padx=2)

        self._trace_text = scrolledtext.ScrolledText(frame, wrap=WORD, font=("Consolas", 10),
                                                      bg="#1e1e1e", fg="#d4d4d4",
                                                      insertbackground="white")
        self._trace_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

        self._trace_start_btn.config(command=self._start_trace)
        self._trace_stop_btn.config(command=self._stop_trace)

    def _start_trace(self):
        try:
            import frida
        except ImportError:
            messagebox.showerror("Missing Dependency",
                                 "Frida not installed.\nRun: pip install frida-tools")
            return

        self._trace_start_btn.config(state=DISABLED)
        self._trace_stop_btn.config(state=NORMAL)
        self._trace_text.delete(1.0, END)
        self._trace_stop_flag = False

        mode = self._trace_mode.get()
        target = self._trace_target.get().strip()
        try:
            timeout = int(self._trace_timeout.get().strip()) or 60
        except ValueError:
            timeout = 60

        def on_msg(msg, _data):
            if msg.get('type') == 'send':
                line = msg.get('payload', {}).get('line', '')
                self._trace_text.after(0, lambda: (
                    self._trace_text.insert(END, line + "\n"),
                    self._trace_text.see(END)
                ))
            elif msg.get('type') == 'error':
                desc = msg.get('description', '')
                self._trace_text.after(0, lambda: (
                    self._trace_text.insert(END, f"[!] Frida error: {desc}\n"),
                    self._trace_text.see(END)
                ))

        def task():
            session = None
            old_stdout = sys.stdout
            sys.stdout = StdoutRedirect(self._trace_text)
            try:
                device = frida.get_local_device()
                if mode == "Attach to PID":
                    try:
                        pid = int(target)
                    except ValueError:
                        matches = [p for p in device.enumerate_processes()
                                   if target.lower() in p.name.lower()]
                        if not matches:
                            print(f"[!] Process '{target}' not found")
                            return
                        pid = matches[0].pid
                        print(f"[*] Attaching to PID {pid}: {matches[0].name}")
                    session = device.attach(pid)
                else:
                    exe = str(ana.SEB_DIR / "SafeExamBrowser.exe")
                    print(f"[*] Spawning: {exe}")
                    pid = frida.spawn([exe])
                    session = device.attach(pid)
                    frida.resume(pid)
                    print(f"[*] PID {pid}")

                js = """
                'use strict';
                const NAMES = ['CalculateAppSignatureKey','CalculateBrowserExamKey',
                               'IsVirtualMachine','VerifyCodeSignature'];
                let callN = {};
                function b2s(b) {
                    if (b.isNull()) return '(null)';
                    try { const len = b.add(-4).readU32();
                          return len ? b.readUtf16String(len) : '(empty)'; }
                    catch(e) { return '(error)'; }
                }
                function log(m) {
                    const t = new Date();
                    const ts = t.getHours().toString().padStart(2,'0') + ':' +
                               t.getMinutes().toString().padStart(2,'0') + ':' +
                               t.getSeconds().toString().padStart(2,'0') + '.' +
                               t.getMilliseconds().toString().padStart(3,'0');
                    send({type:'log', line:'[' + ts + '] ' + m});
                }
                function hook(name, addr) {
                    callN[name] = 0;
                    Interceptor.attach(addr, {
                        onEnter(args) {
                            callN[name]++;
                            log(name + ' #' + callN[name]);
                            if (name.indexOf('Calculate') !== -1) {
                                log('  arg0: "' + b2s(args[0]) + '"');
                                log('  arg1: "' + b2s(args[1]) + '"');
                            } else if (name === 'IsVirtualMachine') {
                                log('  mfr out: ' + args[0] + '  prob out: ' + args[1]);
                            }
                        },
                        onLeave(ret) {
                            if (name.indexOf('Calculate') !== -1) {
                                const r = ret.toInt32() ? ret : ptr(0);
                                log('  => "' + (r.isNull() ? '(null)' : b2s(r)) + '"');
                            } else if (name === 'IsVirtualMachine') {
                                log('  => BOOL: ' + ret.toInt32());
                                try {
                                    const mfr = this.context.rcx;
                                    const prob = this.context.rdx;
                                    if (mfr && !mfr.isNull()) {
                                        const v = mfr.readPointer();
                                        log('  => mfr: ' + b2s(v));
                                    }
                                    if (prob && !prob.isNull())
                                        log('  => prob: ' + prob.readU32() + '%');
                                } catch(e) {}
                            } else if (name === 'VerifyCodeSignature') {
                                log('  => BOOL: ' + ret.toInt32());
                            }
                            log('');
                        }
                    });
                    log('HOOK: ' + name);
                }
                function tryHook() {
                    const mod = Process.findModuleByName('seb_x64.dll');
                    if (!mod) return;
                    log('=== SEB TRACE START === PID=' + Process.id + ' MOD=' + mod.base);
                    const exps = mod.enumerateExports();
                    let n = 0;
                    for (const e of exps) {
                        if (NAMES.indexOf(e.name) !== -1) { hook(e.name, e.address); n++; }
                    }
                    log('Hooked ' + n + '/' + NAMES.length);
                }
                tryHook();
                setInterval(tryHook, 200);
                """
                script = session.create_script(js, runtime='v8')
                script.on('message', on_msg)
                script.load()

                print(f"[*] Tracing for {timeout}s ...")
                deadline = time_module.time() + timeout
                while time_module.time() < deadline:
                    if getattr(self, '_trace_stop_flag', False):
                        print("[*] Stopped by user")
                        break
                    time_module.sleep(0.5)

            except Exception as e:
                import traceback
                print(f"[!] Trace error: {e}")
                traceback.print_exc()
            finally:
                if session:
                    try:
                        session.detach()
                    except:
                        pass
                sys.stdout = old_stdout
                self._trace_text.after(0, self._trace_cleanup)
                print("[*] Trace ended")

        threading.Thread(target=task, daemon=True).start()

    def _stop_trace(self):
        self._trace_stop_flag = True

    def _trace_cleanup(self):
        self._trace_start_btn.config(state=NORMAL)
        self._trace_stop_btn.config(state=DISABLED)

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    SEBGUI().run()
