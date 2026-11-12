PHP_ARG_ENABLE([rehook], [whether to enable the Envelock rehook test extension],
  [AS_HELP_STRING([--enable-rehook], [Enable the rehook test extension])], [no])

if test "$PHP_REHOOK" != "no"; then
  PHP_NEW_EXTENSION([rehook], [rehook.c], [$ext_shared])
fi
