# Contributing

This is an experimental security implementation. Changes must include a threat model, regression tests and explicit limits; claims of absolute protection are not accepted.

## Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
python -m ruff check encoder tests scripts/demo_material.py
ENVELOCK_REQUIRE_NATIVE=1 python -m pytest -q tests
```

Do not use production identities in tests. `scripts/demo_material.py` generates publicly reproducible material. For changes to the C parser also run `scripts/audit-native.sh` and review its logs. Record the versions of the tools and the targets actually tested.

## Requirements for a change

- A security bug must have a regression test whenever possible.
- Review lengths, integers, offsets, allocation/freeing, Zend bailouts and secret cleanup.
- Do not introduce `eval`, homemade cryptography, universal production secrets or networking in the loader.
- Do not silently change format/AAD/signatures: version them and document compatibility.
- Do not treat obfuscation, anti-debug or permissions as a guarantee against root.
- Run the PHP 8.2–8.5 matrix and the affected systems. Declare any pending target.
- Review artifacts, not just tests: avoid source, headers, PDBs, passwords and private logs.
- Update the manual, changelog, results and threat model.

Do not include real keys or commercial sources in issues, pull requests or examples. For vulnerabilities use the private channel described in `SECURITY.md`.
