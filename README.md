# seb-re-toolkit

Reverse engineering toolkit for Safe Exam Browser's Themida-protected seb_x64.dll integrity module.

Ai readme because im lazy

## Overview

seb_x64.dll (8.9 MB) is the native anti-tamper module used by Safe Exam Browser 3.10.1 to enforce exam integrity. It is packed with **Oreans WinLicense / Themida 3.x** — code sections are encrypted at rest, real imports are resolved at runtime, and call-site verification blocks out-of-context invocation.

This toolkit provides:

- **Static analysis** — PE structure, sections, entropy, Rich header, imports, security features
- **Packer detection** — Themida/VMProtect/Enigma signatures, RWX anomalies
- **Export calling** — BSTR-aware ctypes invocation with correct `__cdecl` convention
- **Frida tracing** — Real-time hooking of `seb_x64.dll` exports in a live SEB process
- **GUI frontend** — Tabbed interface wrapping all CLI functionality

## Identified Exports

All four exports use `CallingConvention.Cdecl` and expect **BSTR** (length-prefixed UTF-16) parameters, not plain LPCWSTR:

| Export | Signature | Returns |
|---|---|---|
| `CalculateAppSignatureKey` | `BSTR __cdecl(BSTR token, BSTR salt)` | SHA-384 hex (96 chars) |
| `CalculateBrowserExamKey` | `BSTR __cdecl(BSTR cfgKey, BSTR salt)` | SHA-256 hex (64 chars) |
| `IsVirtualMachine` | `BOOL __cdecl(BSTR* mfr, int* prob)` | VM status + manufacturer + confidence |
| `VerifyCodeSignature` | `BOOL __cdecl()` | TRUE if caller's Authenticode is valid |

## Dependencies

pefile, frida-tools

## Usage

### CLI

```
python seb_analyzer.py info          # Quick DLL overview
python seb_analyzer.py static        # Deep PE analysis
python seb_analyzer.py detect        # Packer/security detection
python seb_analyzer.py exports       # Export signatures & details
python seb_analyzer.py call          # Call exports via ctypes
python seb_analyzer.py trace         # Frida hook SEB (spawns process, 60s)
python seb_analyzer.py trace -a SEB  # Attach to running SEB by name
python seb_analyzer.py trace -t 120  # 2-minute trace window
```

### GUI

```
python seb_gui.py
```

Six tabs: Overview, Static, Detection, Exports, Call (with parameter inputs), Trace (spawn/attach + Start/Stop).

## Key Findings

- **Themida 3.x** — `.themida` section (5.5 MB, RWX, entropy 6.26), entry point inside packed code, DEP/ASLR/CFG all disabled
- **Call-site verification** — Themida's `CalculateAppSignatureKey` and `CalculateBrowserExamKey` refuse to execute when called via `NativeFunction` from Frida; only `Interceptor.attach` works because SEB's own code triggers the call
- **Out-of-context calls** — BSTR-based ctypes invocations produce non-deterministic output (different from real SEB-context results)
- **BSTR marshaling** — All string parameters are BSTR, allocated via `SysAllocString`/`SysAllocStringLen`
- **VerifyCodeSignature** returns TRUE inside SEB, FALSE outside
- **IsVirtualMachine** detects Hyper-V artifacts even on bare metal (0% probability)

## Important thing

- Key derivation exports (CalculateAppSignatureKey, CalculateBrowserExamKey) are only reliably observed via Frida Interceptor.attach inside SEB
- .seb config without browserExamKeySalt/appSignatureKeySalt values will never trigger these exports during tracing
- Static analysis is inherently limited — Themida decrypts code and resolves imports at runtime

One non ai generated part though, even with correct BSTR signatures and LoadLibrary, both key derivation functions return deterministic looking output, but it's wrong. The values change per LoadLibrary call, aren't real SHA-384/256, and the DLL clearly detects it's not running under SafeExamBrowser.Client.exe. Themida's antiscraping is baked into the export stubs themselves. Um star this repo and join my discord: https://discord.gg/HBjpBv9dUv
## License

MIT
