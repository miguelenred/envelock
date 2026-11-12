<?php
/*
 * Envelock pre-flight check for a hosting server (docs/HOSTING.md).
 *
 * Upload this file to the server and run it with the SAME PHP that will serve the protected site:
 *   - web:  open it in the browser (it reports the web SAPI, e.g. PHP-FPM or LiteSpeed), or
 *   - CLI:  php envelock-preflight.php   (reports the CLI, which often reads another php.ini).
 * Delete it afterwards: it prints details of the server configuration.
 *
 * It only reads settings; it changes nothing and loads nothing. FAIL = Envelock will not run as
 * configured, WARN = it runs only with a change or with limits, INFO = matters for some options.
 */

const ENVELOCK_PREFLIGHT_MIN_GLIBC = '2.28';   // what the prebuilt Linux loaders need (docs/HOSTING.md §2)

$rows = [];
$add = static function (string $level, string $what, string $detail) use (&$rows): void {
    $rows[] = [$level, $what, $detail];
};
$on = static function ($value): bool {
    return in_array(strtolower(trim((string) $value)), ['1', 'on', 'yes', 'true'], true);
};

// --- PHP and platform -------------------------------------------------------------------------
$minor = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$supported = in_array($minor, ['8.2', '8.3', '8.4', '8.5'], true);
$add($supported ? 'OK' : 'FAIL', 'PHP version', PHP_VERSION . ' (SAPI ' . PHP_SAPI . ')'
    . ($supported ? '' : ': Envelock supports PHP 8.2 to 8.5'));
$ts = PHP_ZTS ? 'ts' : 'nts';
$add(PHP_ZTS ? 'WARN' : 'OK', 'Thread safety', strtoupper($ts)
    . (PHP_ZTS ? ': source packages only, --bytecode packages are refused' : ''));
$machine = strtolower(php_uname('m'));
$x64 = PHP_INT_SIZE === 8 && in_array($machine, ['x86_64', 'amd64', 'x64'], true);
$loader = null;
if (PHP_OS_FAMILY === 'Windows') {
    $add($x64 ? 'OK' : 'FAIL', 'Platform', 'Windows ' . $machine . ($x64 ? '' : ': only x64 loaders are built'));
    $loader = "prebuilt/loader/windows-x64/php-$minor-$ts/php_envelock.dll";
    $dir = PHP_BINARY !== '' ? dirname(PHP_BINARY) : '';
    if ($dir !== '' && is_file($dir . DIRECTORY_SEPARATOR . 'libcrypto-3-x64.dll')) {
        $add('OK', 'OpenSSL 3 (libcrypto-3-x64.dll)', 'present in ' . $dir);
    } else {
        $add('WARN', 'OpenSSL 3 (libcrypto-3-x64.dll)', 'not found next to the PHP binary; it must be on '
            . 'the DLL search path (official php.net builds ship it in the PHP folder)');
    }
} elseif (PHP_OS_FAMILY === 'Linux') {
    $musl = glob('/lib/ld-musl-*') ?: [];
    if ($musl) {
        $add('FAIL', 'C library', 'musl (e.g. Alpine): no prebuilt loader; build one on this system (docs/BUILDING.md)');
    } else {
        $glibc = null;
        if (function_exists('shell_exec')) {
            $out = @shell_exec('getconf GNU_LIBC_VERSION 2>/dev/null');
            if (is_string($out) && preg_match('/glibc\s+([0-9.]+)/', $out, $m)) {
                $glibc = $m[1];
            }
        }
        if ($glibc === null) {
            $add('WARN', 'C library', 'glibc version unknown (shell_exec unavailable); run "ldd --version" over SSH; the prebuilt loaders need ' . ENVELOCK_PREFLIGHT_MIN_GLIBC . '+');
        } else {
            $ok = version_compare($glibc, ENVELOCK_PREFLIGHT_MIN_GLIBC, '>=');
            $add($ok ? 'OK' : 'FAIL', 'C library', "glibc $glibc" . ($ok ? '' : ': the prebuilt Linux loaders need '
                . ENVELOCK_PREFLIGHT_MIN_GLIBC . '+; build the loader on this server instead (docs/BUILDING.md)'));
        }
    }
    $add($x64 ? 'OK' : 'FAIL', 'Architecture', $machine . ($x64 ? '' : ': no prebuilt loader for it; build one on this system'));
    $add('OK', 'OpenSSL', 'nothing needed from the system: the prebuilt Linux loaders carry their own OpenSSL 3');
    $loader = $x64 ? "prebuilt/loader/linux-x86_64/php-$minor-" . (PHP_ZTS ? 'zts' : 'nts') . '/envelock.so' : null;
} else {
    $add('FAIL', 'Platform', PHP_OS_FAMILY . ': no prebuilt loader; build one on this system (docs/PLATAFORMAS.md)');
}
if ($loader !== null) {
    $add('INFO', 'Loader to use', $loader . ' (complete distribution)');
}

// --- Is the loader installed? -----------------------------------------------------------------
$installed = extension_loaded('envelock');
if ($installed) {
    $identity = (string) ini_get('envelock.identity');
    ob_start();
    phpinfo(INFO_MODULES);
    $store = preg_match('/Trust store\W*(loaded|not configured)/', strip_tags((string) ob_get_clean()), $m) ? $m[1] : '?';
    if ($identity === '') {
        $add('FAIL', 'Envelock loader', 'loaded, but envelock.identity is empty: set it in php.ini and restart PHP');
    } elseif ($store !== 'loaded') {
        $add('FAIL', 'Envelock loader', "loaded, but the identity file $identity was not accepted (owner, "
            . 'permissions or contents; the PHP error log says why); fix it and restart PHP');
    } else {
        $add('OK', 'Envelock loader', "loaded; identity file accepted ($identity)");
    }
} else {
    $add('WARN', 'Envelock loader', 'not loaded in this PHP: the server administrator adds "extension=" and '
        . '"envelock.identity=" to php.ini and restarts PHP (a .user.ini or .htaccess cannot do it)');
}

// --- OPcache ----------------------------------------------------------------------------------
$cli = in_array(PHP_SAPI, ['cli', 'phpdbg'], true);
if (!extension_loaded('Zend OPcache')) {
    $add('OK', 'OPcache', 'not loaded');
} else {
    $cfg = static function (string $name, bool $default) use ($on): bool {
        $value = get_cfg_var($name);
        return $value === false ? $default : $on($value);
    };
    $startup = $cfg('opcache.enable', true) && (!$cli || $cfg('opcache.enable_cli', false));
    $now = $on(ini_get('opcache.enable')) && (!$cli || $on(ini_get('opcache.enable_cli')));
    $allow = $installed && $on(ini_get('envelock.allow_opcache'));
    $blacklist = (string) ini_get('opcache.blacklist_filename');
    if (!$startup) {
        $add('OK', 'OPcache', 'loaded but off at startup for this SAPI');
    } elseif (!$now) {
        $add('OK', 'OPcache', 'on in php.ini but switched off for this site (per directory, vhost or pool): '
            . 'accepted by loaders built from 2026-11-11 on; older ones refused it (docs/HOSTING.md §3.3)');
    } elseif ($allow && $blacklist !== '') {
        $add('OK', 'OPcache', "on, envelock.allow_opcache=1, blacklist $blacklist (it must list the protected folder)");
    } else {
        $add('FAIL', 'OPcache', 'on: protected files are refused unless php.ini sets envelock.allow_opcache=1 and '
            . 'opcache.blacklist_filename lists the protected folder, or opcache.enable=0');
    }
    $persist = [];
    foreach (['opcache.file_cache', 'opcache.preload'] as $name) {
        if ((string) ini_get($name) !== '') {
            $persist[] = "$name=" . ini_get($name);
        }
    }
    if ($on(ini_get('opcache.file_cache_only'))) {
        $persist[] = 'opcache.file_cache_only=1';
    }
    if ($persist) {
        $add('FAIL', 'OPcache file cache / preload', implode(', ', $persist) . ': always refused, they persist decrypted code');
    }
}
if ($on(ini_get('zend.multibyte'))) {
    $add('FAIL', 'zend.multibyte', 'on: protected files are refused; set zend.multibyte=0');
}

// --- Extensions that make the loader refuse protected files ----------------------------------
$debuggers = ['xdebug', 'vld', 'uopz', 'runkit7', 'xhprof', 'tideways', 'tideways_xhprof', 'ddtrace',
              'spx', 'pcov', 'blackfire', 'memprof'];
$loaded = array_values(array_filter($debuggers, 'extension_loaded'));
if ($loaded || PHP_SAPI === 'phpdbg') {
    $add('FAIL', 'Debuggers / profilers', implode(', ', $loaded ?: ['phpdbg']) . ': protected files are refused '
        . 'unless envelock.allow_debuggers=1 (development machines only)');
}
$hooks = array_values(array_filter(['ionCube Loader', 'SourceGuardian'], 'extension_loaded'));
if ($hooks) {
    $add('FAIL', 'Other encoders\' loaders', implode(', ', $hooks) . ': a compile hook above Envelock\'s makes it '
        . 'refuse protected files; disable them for this PHP or this account (docs/HOSTING.md §3.4)');
}
$apm = array_values(array_filter(['newrelic', 'opentelemetry', 'excimer'], 'extension_loaded'));
if ($apm) {
    $add('INFO', 'Monitoring agents', implode(', ', $apm) . ': fine by default; refused only with envelock.paranoid=1');
}

// --- Settings that only some package options need ----------------------------------------------
$ffi = extension_loaded('ffi') ? (string) ini_get('ffi.enable') : 'not loaded';
$add('INFO', 'For --no-ffi packages', 'enable_dl=' . ($on(ini_get('enable_dl')) ? 'On' : 'Off') . ", ffi.enable=$ffi"
    . (($on(ini_get('enable_dl')) || $on($ffi) || ($cli && strtolower($ffi) === 'preload'))
        ? ' -> NOT ready: needs enable_dl=Off and FFI off' : ' -> ready'));
$prepend = trim((string) ini_get('auto_prepend_file') . ' ' . (string) ini_get('auto_append_file'));
$add('INFO', 'For --no-prepend packages', $prepend === '' ? 'no auto_prepend/append file -> ready'
    : "auto_prepend/append_file set ($prepend) -> NOT ready (e.g. a security plugin's firewall)");
$add('INFO', 'open_basedir / disable_functions', 'nothing special: protected files must be inside open_basedir '
    . 'like any PHP file (open_basedir=' . ((string) ini_get('open_basedir') !== '' ? ini_get('open_basedir') : 'none') . ')');

// --- Report -----------------------------------------------------------------------------------
if (!$cli) {
    header('Content-Type: text/plain; charset=utf-8');
}
$worst = 'OK';
foreach ($rows as [$level, $what, $detail]) {
    echo str_pad($level, 5), ' ', str_pad($what, 40), ' ', $detail, "\n";
    if ($level === 'FAIL' || ($level === 'WARN' && $worst === 'OK')) {
        $worst = $level;
    }
}
echo "\nResult: ", [
    'OK' => 'this PHP can run Envelock as configured.',
    'WARN' => 'this PHP can run Envelock once the WARN lines are dealt with.',
    'FAIL' => 'Envelock will not run here until the FAIL lines are fixed.',
][$worst], "\nDelete this file from the server now.\n";
exit($worst === 'FAIL' ? 1 : 0);
