# Native Windows validation prompt (for an AI coding agent on a real Windows machine)

This prompt drives a full native validation of the Windows x64 binaries. It was written when the DLLs
were still cross-built under Wine and the **crash-safety guard in the bytecode loader (Windows SEH,
`__try`/`__except`)** had never run on a real Windows. It was run on 2026-11-10 on Windows 11 x64: the
DLLs in `prebuilt/loader/windows-x64/` are now built natively with `scripts/build-windows.ps1`, and the
results (including a guard defect that only native runs exposed, BC-1) are in `TEST-STATUS.md` and
`docs/AUDITORIA.md` (Pass 32). Keep it to re-run the validation: paste it into your terminal AI coding
agent on the Windows machine that has this repository.

---

You are on a real Windows x64 machine with the Envelock repository (an open-source PHP source-protection
tool). Validate the Windows binaries **natively**, with special attention to the new crash-safety guard
in the bytecode deserializer, which is implemented with SEH (`__try`/`__except`) and has never run on
Windows. Be rigorous: never invent results, and if something fails, say so with the exact error and
stop rather than papering over it.

Repo facts: native Windows build is `scripts/build-windows.ps1` (uses the official
`php/php-windows-builder` `BuildPhpExtension` module). Tests are in `tests/test_native.py`, run against a
DLL via the environment variables `ENVELOCK_TEST_EXTENSION`, `ENVELOCK_TEST_OWNER`,
`ENVELOCK_TEST_RECIPIENT`. Build guide: `docs/BUILDING.md` §2. The bytecode PoC functions are gated in
`extension/config.w32` by `--enable-envelock-bcemit` / `--enable-envelock-bcrun-unsafe`; a **production**
DLL is built with **neither**.

Prerequisites (verify first; if any is missing, tell me what and where to get it — do not proceed blind):
- PHP for Windows x64, **dev packs AND binaries**, for 8.2, 8.3 (VS16) and 8.4, 8.5 (VS17), each in NTS and TS.
- Visual Studio Build Tools with the matching C++ toolset (VS16 for 8.2/8.3, VS17 for 8.4/8.5).
- OpenSSL 3.x for Windows x64 (dev).
- Python 3.11+ with pip; install the test dependencies (`pytest` etc.) from `requirements.lock`.
- The `BuildPhpExtension` PowerShell module imported.

Phase A — the eight production DLLs:
1. Make throwaway keys: `python encoder\envelock.py init-owner --no-encrypt --out test_owner.json`,
   `... init-recipient --no-encrypt --label test --out test_recip.json`,
   `... export-public --recipient test_recip.json --out test_recip.pub`.
2. For each (version, TS) in {8.2,8.3,8.4,8.5}×{nts,ts}: run
   `scripts\build-windows.ps1 -PhpVersion X -ThreadSafety Y -OutputDirectory out\X-Y -Owner test_owner.json -Recipient test_recip.json`.
   With Owner/Recipient (both PRIVATE files: the suite derives the identity from them; a `.pub` is
   refused) it also runs `tests/test_native.py` against the freshly built DLL; on a test failure the
   DLL is kept and the script fails.
3. Require the native suite to pass. The bytecode emit/run PoC tests **skip** on a production DLL — that
   is correct. Report passed/skipped/failed for each engine. On any FAILED, stop and show me the error.
4. Confirm each **production** DLL exports and contains **no** `envelock_bc_emit` / `envelock_bc_run` /
   `envelock_trusted_time` symbols (use `dumpbin /exports` and a string search). Must be 0.

Phase B — the deserializer crash-safety guard (the Windows-specific SEH path, the main point):
5. Build ONE **test** DLL with the bytecode PoC enabled: a build with `--enable-envelock-bcrun-unsafe`
   (defines `ENVELOCK_BCRUN`; see `config.w32`). Use `phpize`+`configure` from the PHP Windows SDK, or the
   builder with that flag. This DLL is for testing ONLY and is never distributed.
6. Point `ENVELOCK_TEST_EXTENSION` at that test DLL (plus OWNER/RECIPIENT) and run specifically:
   - `test_bytecode_deserializer_never_crashes_on_a_corrupted_image` (fuzz: it forces every field of a
     bytecode image to a hostile value and requires the loader to NEVER crash — SEH must turn each into a
     clean rejection).
   - `test_bytecode_loader_reanchors_a_corrupted_script_size`
   - `test_bytecode_roundtrip_matches_source`, `test_bytecode_package_runs_identically_to_source`,
     `test_bytecode_refuses_a_tampered_image`, `test_bytecode_loader_requires_empty_interned_region`.
   - all of `tests/test_bytecode_guard.py`, in particular
     `test_fatal_error_after_a_rejected_image_does_not_crash`: a rejection must also leave the engine
     able to raise the NEXT fatal error cleanly (exit 255), not crash on it (`0xC0000409`).
7. The crash-safety test MUST pass on Windows: confirm the PHP process never dies with a Windows
   exception code (e.g. 0xC0000005 access violation) on any corrupted image. If it crashes, SEH is not
   catching it — report the offset and the process exit code.

Phase C — a real end-to-end roundtrip:
8. `export-identity --recipient test_recip.json --owner test_owner.json --out identity.bin`. Encrypt a
   small sample PHP project (2–3 files) with `pack ... --recipient test_recip.pub`. Serve it with
   `php -d extension=<production_dll> -d envelock.identity=identity.bin -S 127.0.0.1:8080` and confirm the
   encrypted output is identical to the cleartext source's. Then repeat with `--bytecode --deploy-root <path>`
   on an NTS production DLL (which carries the bytecode layer).

Phase D — the graphical assistant:
9. Build the assistant `.exe` (see `docs/ASSISTANT.md` / `BUILDING.md`) and run it with `--selftest` and
   `--e2e <empty work folder>` (once more with `ENVELOCK_E2E_PHP` set to a `php.exe`, so the executable
   also runs a real PHP); confirm both pass.

When done:
- Give me a table: per DLL (8 production + 1 test) → passed/skipped/failed and forbidden-symbols = 0.
- State explicitly whether the SEH crash-safety guard works on Windows (yes/no) with the evidence.
- If any rebuilt production DLL differs from `prebuilt/loader/windows-x64/`, copy it there and update
  its line in `prebuilt/SHA256SUMS` (do NOT regenerate the whole manifest on Windows: NTFS cannot hold
  the Linux terminfo files that differ only by case, so a full regeneration would drop them), and run
  `python scripts\check_release.py --require-complete .`. It must pass in a live git checkout or a
  clean staged tree; on NTFS the case-colliding groups are reported as NOTEs, not failures.
- Delete the throwaway keys (`test_owner.json`, `test_recip.*`, `identity.bin`) before finishing — they
  must never be committed or shipped.
- Be honest: if something cannot be tested (a missing PHP version, etc.), say so; never mark as OK
  anything you did not actually run.
