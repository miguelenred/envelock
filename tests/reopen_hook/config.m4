PHP_ARG_ENABLE(reopen_hook, test-only compile hook, [  --enable-reopen-hook  Test-only extension])
if test "$PHP_REOPEN_HOOK" != "no"; then
  PHP_NEW_EXTENSION(reopen_hook, reopen_hook.c, $ext_shared)
fi
