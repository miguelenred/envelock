PHP_ARG_ENABLE([envelock], [whether to enable the offline Envelock loader],
  [AS_HELP_STRING([--enable-envelock], [Enable Envelock])], [no])

dnl The bytecode proof-of-concept userland functions are gated by EXPLICIT configure flags, never by
dnl an environment variable (ENV-2026-02): an inherited ENVELOCK_BCPOC=1 used to compile them silently
dnl into whatever was being built, including a server loader, exposing envelock_bc_run (an RCE surface
dnl that deserializes and executes caller-supplied bytecode). Splitting the two:
dnl   --enable-envelock-bcemit        envelock_bc_emit only (the pack-side compiler; safe to ship in a
dnl                                   dedicated packer build, never in a server loader)
dnl   --enable-envelock-bcrun-unsafe  envelock_bc_run (executes caller-supplied images); TEST ONLY,
dnl                                   must never be distributed in any form.
PHP_ARG_ENABLE([envelock-bcemit], [whether to compile the pack-side bytecode emitter],
  [AS_HELP_STRING([--enable-envelock-bcemit], [Compile envelock_bc_emit (pack side only)])], [no], [no])
PHP_ARG_ENABLE([envelock-bcrun-unsafe], [whether to compile the UNSAFE bytecode runner],
  [AS_HELP_STRING([--enable-envelock-bcrun-unsafe], [Compile envelock_bc_run; TEST ONLY, never ship])], [no], [no])

if test "$PHP_ENVELOCK" != "no"; then
  dnl Both libraries, not just libcrypto. envelock_trusted_time.c (objective O8) speaks TLS, which
  dnl lives in libssl; the crypto primitives alone are in libcrypto. A module gets away with asking
  dnl for libcrypto only, because a shared object is allowed undefined symbols and the dynamic
  dnl linker resolves SSL_* from the host process at load time — so the dependency is real but
  dnl undeclared, and it breaks the moment the SAPI does not happen to have libssl loaded. Linking
  dnl the extension into the engine has nowhere to borrow the symbols from, which is what exposes
  dnl it here.
  PKG_CHECK_MODULES([ENVELOCK_OPENSSL], [libcrypto >= 3.0 libssl >= 3.0])
  PHP_EVAL_INCLINE([$ENVELOCK_OPENSSL_CFLAGS])
  PHP_EVAL_LIBLINE([$ENVELOCK_OPENSSL_LIBS], [ENVELOCK_SHARED_LIBADD])
  PHP_SUBST([ENVELOCK_SHARED_LIBADD])
  dnl ENVELOCK_SHARED_LIBADD is consulted only when ext_shared=yes (see PHP_EVAL_LIBLINE in
  dnl build/php.m4), i.e. for a loadable module. A static build links this extension into the PHP
  dnl binary itself, where nothing adds libcrypto and the link dies on undefined EVP_*/OSSL_*
  dnl references. That build shape is what a statically embedded distribution needs: a static PHP
  dnl has no dynamic loader, so the loader has to be compiled in rather than loaded.
  if test "$ext_shared" != "yes"; then
    PHP_EVAL_LIBLINE([$ENVELOCK_OPENSSL_LIBS], [EXTRA_LIBS])
  fi
  dnl Objective O1: the bytecode layer adapts Zend-internal files that are not part of the stable
  dnl extension API, so it is vendored per PHP version and the build picks the matching copy. A
  dnl PHP without one fails here, at configure time, rather than producing a module that would
  dnl silently mis-deserialize.
  dnl The engine's own answer, not a guess: the layer must match the PHP this module links to,
  dnl exactly (major and minor). There is no fallback to the previous minor's layer: it adapts
  dnl Zend internals of that minor, and compiling it against a newer engine's headers is undefined;
  dnl config.w32 and scripts/build-windows-wine.sh build source-only in that case too.
  ENVELOCK_PHP_VER=`$PHP_CONFIG --version 2>/dev/null`
  dnl Inside a PHP source tree there is no installed php-config to ask yet, so the above reads
  dnl empty and the check below fails with "no bytecode layer for PHP ." even though the layer is
  dnl present. configure has already computed the engine's own version by this point, and it is the
  dnl same authority php-config would have quoted.
  if test -z "$ENVELOCK_PHP_VER"; then
    ENVELOCK_PHP_VER="$PHP_VERSION"
  fi
  if test -z "$ENVELOCK_PHP_VER"; then
    ENVELOCK_PHP_VER="$PACKAGE_VERSION"
  fi
  ENVELOCK_PHP_MM=`echo "$ENVELOCK_PHP_VER" | $AWK -F. '{print "php" $1 $2}'`
  dnl Where this extension's own sources are. Under phpize, $srcdir IS the extension directory.
  dnl Inside a PHP source tree it is the PHP root, and $ext_srcdir is not assigned until
  dnl PHP_NEW_EXTENSION runs — after this point — so the layer has to be located by trying the
  dnl candidates rather than by trusting one variable. A static build (compiling the loader into
  dnl PHP itself, which is what a statically embedded distribution requires, since a static PHP has
  dnl no dynamic loader) takes the second branch.
  ENVELOCK_EXT_SRCDIR=""
  for envelope_candidate in "$srcdir" "$abs_srcdir/ext/envelock"; do
    if test -f "$envelope_candidate/opcache/$ENVELOCK_PHP_MM/envelock_bc.c"; then
      ENVELOCK_EXT_SRCDIR="$envelope_candidate"
      break
    fi
  done
  dnl O1 bytecode layer is OPTIONAL and per PHP version. When one exists for this engine it is
  dnl compiled in and ENVELOCK_HAVE_BYTECODE=1; otherwise the loader is built source-only (it runs
  dnl source packages and refuses a FLAG_BYTECODE file at runtime). Generate a layer with
  dnl extension/opcache/gen_persist.py against the matching PHP source tree.
  dnl ENV-2026-03: the bytecode layer keeps per-process state without thread-local storage, so it is
  dnl not thread-safe. Drop it (build a source-only loader) for a ZTS engine, so a thread-safe build
  dnl still succeeds; the #error in envelock_accel_shim.h is the compile-time backstop if it is forced.
  ENVELOCK_ZTS="no"
  if test "x$PHP_THREAD_SAFETY" = "xyes"; then
    ENVELOCK_ZTS="yes"
  else
    envelock_php_bin=`$PHP_CONFIG --php-binary 2>/dev/null`
    if test -n "$envelock_php_bin" && test -x "$envelock_php_bin"; then
      if test "`"$envelock_php_bin" -r 'echo (int) ZEND_THREAD_SAFE;' 2>/dev/null`" = "1"; then
        ENVELOCK_ZTS="yes"
      fi
    fi
  fi
  ENVELOCK_HAVE_BC=0
  ENVELOCK_BC_SOURCES=""
  if test -n "$ENVELOCK_EXT_SRCDIR" && test "$ENVELOCK_ZTS" != "yes"; then
    ENVELOCK_HAVE_BC=1
    PHP_ADD_BUILD_DIR([$ENVELOCK_EXT_SRCDIR/opcache/$ENVELOCK_PHP_MM])
    PHP_ADD_INCLUDE([$ENVELOCK_EXT_SRCDIR/opcache/$ENVELOCK_PHP_MM])
    ENVELOCK_BC_SOURCES="envelock_bcpoc.c opcache/$ENVELOCK_PHP_MM/envelock_arena.c opcache/$ENVELOCK_PHP_MM/envelock_bc.c opcache/$ENVELOCK_PHP_MM/envelock_persist.c opcache/$ENVELOCK_PHP_MM/envelock_file_cache.c opcache/$ENVELOCK_PHP_MM/envelock_script.c"
  elif test "$ENVELOCK_ZTS" = "yes"; then
    AC_MSG_WARN([Envelock: thread-safe (ZTS) engine detected; building a source-only loader. The bytecode layer is not ZTS-safe (ENV-2026-03) and is omitted; FLAG_BYTECODE files are refused at runtime.])
  else
    AC_MSG_WARN([Envelock: no bytecode layer for PHP $ENVELOCK_PHP_VER; building a source-only loader (FLAG_BYTECODE refused at runtime). Run extension/opcache/gen_persist.py to add one.])
  fi
  dnl The PoC userland functions are compiled ONLY under their explicit flags (see the top of this
  dnl file). The environment variable ENVELOCK_BCPOC is deliberately NOT consulted here any more
  dnl (ENV-2026-02). A server loader is built with neither flag, so it never exposes the bytecode
  dnl emit/run surface; the pack-time loader is built with --enable-envelock-bcemit only; the test
  dnl suite adds --enable-envelock-bcrun-unsafe to exercise the round-trip.
  ENVELOCK_BCPOC_DEF=""
  if test "$PHP_ENVELOCK_BCEMIT" = "yes"; then
    ENVELOCK_BCPOC_DEF="$ENVELOCK_BCPOC_DEF -DENVELOCK_BCEMIT=1"
  fi
  if test "$PHP_ENVELOCK_BCRUN_UNSAFE" = "yes"; then
    dnl The runner needs the emitter present too (the round-trip tests emit then run).
    ENVELOCK_BCPOC_DEF="$ENVELOCK_BCPOC_DEF -DENVELOCK_BCEMIT=1 -DENVELOCK_BCRUN=1"
  fi
  dnl -fvisibility=hidden in the extension's own flags, as config.w32 carries its hardening: a plain
  dnl `phpize && ./configure && make` (without scripts/build-unix.sh) must not export the envelock_*
  dnl internals (the decrypt/key-unwrap API, M-01) for another extension to dlsym. get_module stays
  dnl exported: ZEND_GET_MODULE marks it with default visibility. scripts/build-unix.sh adds the rest
  dnl of the hardening (fortify, stack protector, relro...).
  dnl Hardening that a plain `phpize && ./configure && make` gets too — which is what PIE runs when it
  dnl builds the loader on a server (docs/HOSTING.md). scripts/build-unix.sh passes the same flags plus
  dnl _FORTIFY_SOURCE (left to it: a value here would come last on the compile line and could lower a
  dnl toolchain default of 3). Each flag only where the compiler accepts it; AX_CHECK_COMPILE_FLAG
  dnl ships with phpize on every supported PHP (PHP_CHECK_GCC_ARG is gone in 8.5).
  ENVELOCK_HARDEN_CFLAGS=""
  AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], [ENVELOCK_HARDEN_CFLAGS="$ENVELOCK_HARDEN_CFLAGS -fstack-protector-strong"])
  AX_CHECK_COMPILE_FLAG([-fstack-clash-protection], [ENVELOCK_HARDEN_CFLAGS="$ENVELOCK_HARDEN_CFLAGS -fstack-clash-protection"])
  AX_CHECK_COMPILE_FLAG([-fcf-protection=full], [ENVELOCK_HARDEN_CFLAGS="$ENVELOCK_HARDEN_CFLAGS -fcf-protection=full"])
  case "${host_alias:-`uname -s`}" in
    *linux*|Linux*)
      dnl Full RELRO, immediate binding, non-executable stack: GNU ld only.
      ENVELOCK_SHARED_LIBADD="$ENVELOCK_SHARED_LIBADD -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
      ;;
  esac
  PHP_NEW_EXTENSION([envelock],
    [envelock.c envelock_crypto.c envelock_file.c envelock_secret.c envelock_integrity.c envelock_licence.c envelock_clock.c envelock_trusted_time.c envelock_vm.c $ENVELOCK_BC_SOURCES],
    [$ext_shared], [], [-fvisibility=hidden $ENVELOCK_HARDEN_CFLAGS -DENVELOCK_HAVE_BYTECODE=$ENVELOCK_HAVE_BC $ENVELOCK_BCPOC_DEF])
fi
