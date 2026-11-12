# About this source archive

First-party source tree of Envelock 1.0.0, ready to push to a Git host; it passes the release guard
(`python scripts/check_release.py --require-complete`). `third_party/` carries only the vendored
`php-parser` here (its `SHA256SUMS` lists just those files), and `prebuilt/` only its README: the
upstream sources (CPython, OpenSSL, cryptography, cffi, …), the prebuilt loaders and assistants, the
portable Pythons and the offline wheels ship in the complete archive, or are rebuilt/fetched as
`docs/BUILDING.md` explains. Linux and Windows (PHP 8.2–8.5) build the full loader including the
bytecode layer; macOS is built and tested by the CI. The loader can also be installed with PIE
(`composer.json`, `docs/HOSTING.md` §4.1). See `TEST-STATUS.md`, `docs/PLATAFORMAS.md` and
`docs/AUDITORIA.md`. This is Envelock's first **1.0.0** release, published on 2026-11-12 at
<https://github.com/miguelenred/envelock>.
