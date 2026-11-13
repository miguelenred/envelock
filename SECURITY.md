# Security policy

## Status

Envelock 1.0.0 is experimental. It has not been independently audited and it is not promised to be free of vulnerabilities. The effective verification matrix is in `docs/VERIFICACION.md`; code targeting a platform is not equivalent to a binary certified for it.

Hiding the source from an administrator who controls the runtime is not guaranteed. Recovering code through a modified PHP or extracting the secret from the binary are known limits of the model, not security promises that can be resolved with AES alone.

## Reporting a vulnerability

When this repository is published, the maintainer must enable Private Vulnerability Reporting/Security Advisories and complete their contact details. **No remote channel has currently been published or configured from this delivery.**

Use a confirmed private channel of the maintainer; do not publish secrets or an operational exploit in an open issue before coordinating disclosure.

Include version, OS, architecture, PHP/ABI/TS, configuration, impact, minimal reproducible steps and, if possible, a proof using demo public keys. Never attach private identities or client source.

## Operation

Keep PHP/OpenSSL/dependencies up to date, restrict permissions, isolate clients and protect the packaging machine. See `docs/SEGURIDAD.md`, `docs/AUDITORIA.md` and `docs/MANUAL.md` before relying on it in production.
