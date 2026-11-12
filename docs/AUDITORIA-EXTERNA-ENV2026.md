# Auditoría externa 2026 — resolución de hallazgos (ENV-2026-01..33)

Segunda pasada de auditoría externa sobre Envelock 1.0.0 (sin publicar). Este documento registra, por
hallazgo, el defecto, la corrección aplicada y el test de regresión que lo protege. Regla seguida en
cada uno: reproducir en código → corregir → test que falla sin el fix → documentar.

Decisión del mantenedor sobre el bytecode (ENV-04): **integrarlo en producción (opción a)**, con la
**firma Ed25519 (verify-before-decrypt) como frontera de confianza** — la misma postura que OPcache
upstream. Las cotas del deserializador son defensa en profundidad, no una garantía de robustez frente a
toda imagen malformada-pero-firmada (que solo puede producir un firmante de confianza, el cual ya puede
enviar código fuente malicioso a su propio despliegue).

Estado de la suite tras las correcciones: **Python 503 passed / 6 skipped**, **nativa (PHP 8.3) 983
passed / 9 skipped**, 0 fallos.

## Encoder / CLI / recomendador (O-A)

| ID | Severidad | Defecto | Corrección | Test |
|----|-----------|---------|------------|------|
| ENV-11 | Alta | `recommend`/`preflight --strict` fallaban en abierto (`exit 0`) con `--source` inexistente o archivo suelto | `compatibility_findings`/`recommend_options` exigen que `--source` sea un directorio | `test_recommend_and_preflight_fail_closed_on_bad_source` |
| ENV-12 | Alta | El recomendador activaba `--bytecode` por defecto (incompatible con el loader estándar previo) y `--sealed` junto a `--exclude` de `.php` | `--bytecode` fuera del set por defecto hasta integrar el emisor; `--sealed` off si `exclude` tiene `.php` | `test_recommend_options_is_conservative_and_matches_the_cms_matrix` |
| ENV-13 | Alta | Patrones del recomendador case-sensitive, `eval` multilínea no detectado, metacaracteres de shell sin escapar | Patrones `IGNORECASE`, escaneo multilínea, `shlex.quote`+`glob.escape` | `test_recommend_robust_against_evasion_and_shell_metachars` |
| ENV-14 | **Crítica** | `--obfuscate-methods` corrompía métodos públicos de clases anónimas anidadas (Fatal error) | Pila de ámbitos anidados (`$nestedRanges`/`$inNested`) que excluye los cuerpos de clases anidadas | `test_obfuscate_methods_isolates_nested_anonymous_class_scope` (prueba negativa: 255≠109) |
| ENV-15 | Alta | `--obfuscate-properties` alteraba resultados silenciosamente (`$this->x` anidado reescrito con el mapa externo) | Mismo aislamiento de ámbitos anidados en el pase de propiedades | `test_obfuscate_properties_isolates_nested_anonymous_class_scope` |
| ENV-16 | Media | `--obfuscate-flatten` no resolvía alias `use function get_defined_vars as …` → fuga de `$__envlk_st` | `NameResolver` antes de la elegibilidad; se comprueba el nombre resuelto | `test_obfuscate_flatten_refuses_frame_function_reached_through_an_alias` |
| ENV-17 | Media | `secret_write` cambiaba el modo de directorios padre preexistentes (0755→0700) | No se re-chmod-ea un padre preexistente; solo se avisa si es accesible por grupo/otros | `test_secret_write_does_not_clamp_preexisting_parent` |
| ENV-18 | Media | `--expires` dependía de DST (`time.mktime`) | `calendar.timegm(strptime(...))` (UTC estable); `--days` acotado | `test_licence_expires_is_dst_free` |
| ENV-19 | Media | `verify` no detectaba un symlink/FIFO añadido; `inspect` no soportaba descriptores identity | `os.walk(followlinks=False)`+`lstat`; `inspect` muestra solo material público de identity | `test_verify_package_flags_added_symlink`, `test_inspect_identity_descriptor_shows_only_public` |
| ENV-20 | Baja | `server-install` solo root; `licence --force` con `unlink` no atómico; host_ipv4 con 127.0.1.1 | `--owner-user` para despliegue rootless; `write_public` (tmp+os.replace atómico); host_ipv4 unificado en ENV-30 | `test_server_install_allows_rootless_for_current_user`, `test_write_public_replaces_atomically_and_keeps_old_on_failure` |
| ENV-26 | Alta | `--virtualize` inyectaba locales privados vía argumentos extra del invocador; colapso de líneas | Se emite `\array_slice(\func_get_args(), 0, N)` (N = aridad declarada) y se preservan los saltos de línea | `test_virtualize_rewrite_trims_caller_args_and_preserves_lines` |
| ENV-29 | Alta | (1) `--vault-strings` dejaba secretos en claro al superar `GIVE_UP` reportando éxito; (2) `--obfuscate-flatten` corrompía funciones con InlineHTML | (1) fail-closed (`ValueError`); (2) `EnvFlattenEligibility` rechaza `Stmt\InlineHTML` | `test_vault_pathological_constant_context_file_fails_closed`, `test_obfuscate_flatten_refuses_a_function_with_inline_html` |
| ENV-33 | Baja | `remove_developer` dejaba `minimums` huérfanos; `audit-native.sh` con cobertura parcial | Purga de minimums del desarrollador eliminado; `audit-native.sh` cubre todas las unidades (ver ENV-33sh) | `test_developer_remove_purges_that_developers_minimums` |

## Bytecode a producción + endurecido (O-B)

| ID | Severidad | Defecto | Corrección | Test |
|----|-----------|---------|------------|------|
| ENV-02 | **Crítica** | El gate `nm -D` quedaba neutralizado por `-fvisibility=hidden`; `ENVELOCK_BCPOC` del entorno compilaba `bc_run` (RCE) en un loader de servidor | Flags de configure explícitos: `--enable-envelock-bcemit` (empaquetador, solo emit) / `--enable-envelock-bcrun-unsafe` (solo test). Sin env-var. Smoke test `function_exists` en los build scripts; `unset` defensivo | `test_server_loader_exposes_no_bytecode_emit_or_run_surface` |
| ENV-03 | **Crítica** | La capa de bytecode usa estado global por proceso sin TLS → carrera en SAPIs ZTS | `#error` bajo `ZTS` en el shim (82/83/84/85); `config.m4` detecta ZTS→source-only; build Windows `ts` source-only | `test_bytecode_layer_refuses_to_build_under_zts` |
| ENV-04 | **Crítica** | El deserializador confía en los offsets internos; una imagen malformada-pero-firmada podía desreferenciar punteros arbitrarios | Cotas activas fail-closed en `UNSERIALIZE_PTR/STR`, rama interned fail-closed, `free()` de mmap y overflow de `envelock_alloc` corregidos (82/83/84/85). **Frontera = la firma** (opción a). Residual de DoS documentado | `test_bytecode_loader_requires_empty_interned_region` + round-trip |
| ENV-09 | Media | El buffer `work` descifrado se filtraba sin limpiar en la ruta de error, y no se marcaba `MADV_DONTDUMP` en la de éxito | `OPENSSL_cleanse` en error + `envelock_bc_keep` (DONTDUMP) en éxito | tests de paquete bytecode |

Integración del emisor: build de empaquetador **emit-only** (expone `envelock_bc_emit`, no `bc_run`). El
recomendador vuelve a ofrecer `--bytecode` para proyectos compatibles (medido: preserva docblocks, así
que PrestaShop no se rompe); supersede `--sealed` (no envía fuente).

## Loader C — seguridad (O-C)

| ID | Severidad | Defecto | Corrección | Test |
|----|-----------|---------|------------|------|
| ENV-05 | **Crítica** | La bóveda cifrada O7 se exfiltraba vía `array_map('__envelock_lit', …)` (saltaba marcos C) | Se inspecciona el marco invocador directo; solo código de usuario (`ZEND_USER_CODE`) resuelve un literal | `test_php_vault_lit_resolves_only_for_a_direct_call` |
| ENV-06 | **Crítica** | Licencia `--domain` evadible con cabecera `Host` falsificada; truncamiento roto de IPv6 | Se usa `SERVER_NAME` (no `HTTP_HOST`); parsing de IPv6 entre corchetes en C y Python | `test_o8_domain_binding_follows_server_name_not_a_spoofed_host_header`, `test_domain_hash_parses_ipv6_brackets_and_strips_port` |
| ENV-07 | Alta | `__envelock_vm` permitía DoS inmune a `max_execution_time` y `OP_CALL` evadía el blocklist | Check `EG(vm_interrupt)` por instrucción; blocklist+by-ref en `OP_CALL`; solo invocación directa | `test_vm_runs_only_for_a_direct_call` |
| ENV-08 | Alta | `envelock_trusted_time` expuesta como función de usuario (DNS/TCP/TLS evadiendo php.ini); validaba `200` en cualquier parte | Retirada de `envelock_functions[]`; validación de la línea de estado `^HTTP/1.[01] <code>` | `test_o8_trusted_time_is_not_a_userland_function` |
| ENV-10 | Media | Estado del reloj abierto sin `O_NOFOLLOW`, modo 0644 | Ambas aperturas con `O_NOFOLLOW|O_CLOEXEC`, escritura 0600. (_Atomic/HMAC → residual) | suite de reloj |
| ENV-24 | **Crítica** | `--vault-strings` corrompía `$_SESSION` con `\x00` al limpiar in situ un `zend_string` compartido en RSHUTDOWN | La ruta cifrada devuelve una copia independiente (`RETURN_STRINGL`) | — (cubierto por regresión de vault/sesión) |
| ENV-25 | **Crítica** | En host multi-desarrollador, B podía firmar el manifiesto de A y borrar ficheros de seguridad | El manifiesto exige `signer_developer_index[s]==dev`; `lstat` (no symlink); rechazo de rutas con `..`/separador inicial/NUL/backslash | `test_php_enforce_manifest_rejects_another_developers_manifest` |
| ENV-28 | Alta | `--sealed` permitía ejecutar PHP en claro **fuera** de la raíz sellada (LFI/`/tmp`); O3 no cubría `zend_execute_internal` | Mientras `sealed_active`, se rechaza cualquier PHP no protegido (salvo allowlist); se comprueba `zend_execute_internal` en paranoid | `test_php_sealed_refuses_plain_php_outside_tree` + suite sealed |
| ENV-30 | Media | `machine_fingerprint` divergía entre C/Python (n==17, cap 64 antes de ordenar, túneles); `licence_parse` fail-open con bits desconocidos | Fingerprint unificado vía `/sys/class/net/<name>/device` (excluye veth/tun/tap/bridge); fail-closed de `fields & ~KNOWN` y bytes reservados | `test_o8_machine_fingerprint_agrees…`, `test_o8_licence_with_an_unknown_field_bit_is_refused` |
| ENV-31 | Media | `identity.bin`/`licence.bin` abiertos sin `O_NOFOLLOW`; `atol(INI_STR(...))` con NULL → SIGSEGV | `O_NOFOLLOW` en la apertura secreta; guardia NULL en los `INI_STR` numéricos | — |
| ENV-32 | Media | `trusted_time`: `strptime` dependiente de `LC_TIME`; overflow `timeout*1000`; truncamiento de `Host` | Parser de fecha por campos (locale-independiente); clamp de timeout; check de truncamiento del `Host` | — |

Residuales de O-C documentados (defensa en profundidad de bajo impacto): HMAC del registro del reloj,
`argtypes`/`restype` en el fingerprint Windows (ctypes), re-aplicar `mlock` tras `fork()`, validación
`dladdr` de `zend_compile_file` con `allow_opcache=1`.

## GUI (O-D)

| ID | Severidad | Defecto | Corrección | Test |
|----|-----------|---------|------------|------|
| ENV-21 | Media | `_run_pack` borraba la carpeta de salida antes de pedir contraseñas; ayuda PHP8 imprecisa | Se piden contraseñas antes de tocar la salida; texto de ayuda preciso | — |
| ENV-22 | Media | `recommend` corría síncrono y congelaba Tk | Se ejecuta en hilo vía `_run_async` | — |
| ENV-27 | Alta | `install_vc_redist`: TOCTOU en `%TEMP%`, validación X.509 débil, zip-bomb en `_extract_zip` | Cota de descompresión; HANDLE con `FileShare.Read` durante verify+UAC; `RevocationMode=Online` + check `Build()`; PowerShell por ruta absoluta | `test_extract_zip_refuses_a_zip_bomb`, `test_extract_zip_refuses_path_traversal` |

Residual: fijar thumbprints SHA-256 exactos de las raíces Microsoft (no fijados sin valores verificados;
`chain.Build` online + sujeto `O=Microsoft Corporation` anclado es la validación robusta aplicada).

## Scripts / docs (O-E)

| ID | Severidad | Defecto | Corrección | Test |
|----|-----------|---------|------------|------|
| ENV-01 | Alta | El ZIP omitía `third_party/php-parser`; `check_release` reportaba éxito | `check_release.py --require-complete` verifica los ficheros de entrada requeridos | `test_require_complete_flags_an_incomplete_release` |
| ENV-23 | Baja | Contradicciones documentales (ASSISTANT O6, CHANGELOG ENV-AUD-01/16, third_party, ROADMAP O9) | Documentación actualizada en este pase; ENV-AUD-01 queda cerrado por ENV-05 y ENV-AUD-16 por ENV-27 | — |
| ENV-33sh | Baja | `audit-native.sh` solo analizaba 3 unidades sin el bytecode | Analiza todas las unidades C + `opcache/php*` con `-DENVELOCK_HAVE_BYTECODE=1` | verificado manualmente |
