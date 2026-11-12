#!/usr/bin/env python3
"""Envelock assistant: a small cross-platform window (Tkinter) over the encoder.

Project page: https://miguelenred.es/envelock (Apache-2.0; "Powered by Envelock" appreciated).

It only draws widgets and collects input; every operation goes through gui/actions.py, which
wraps the encoder. No cryptography happens here. Runs on Windows, Linux and macOS with any
Python 3.9+ that has Tkinter (bundled with the official installers) and the `cryptography`
package; the packaged executables bundle both so nothing needs installing.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from . import actions  # when imported as a package
except ImportError:                # when run as a plain script or frozen
    import importlib.util
    import sys
    if getattr(sys, "frozen", False):
        _base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "gui"
    else:
        _base = Path(__file__).resolve().parent
    _spec = importlib.util.spec_from_file_location("actions", _base / "actions.py")
    actions = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(actions)

# --- translations -----------------------------------------------------------------------------
# Two languages, chosen from a selector. Keys are stable; English and Spanish strings follow.
STRINGS = {
    "title": ("Envelock assistant", "Asistente de Envelock"),
    "language": ("Language", "Idioma"),
    "tab_pack": ("Encrypt a project", "Cifrar un proyecto"),
    "tab_keys": ("Keys", "Claves"),
    "tab_identity": ("Server identity", "Identidad del servidor"),
    "tab_rotate": ("Key rotation", "Rotación de claves"),
    "tab_inspect": ("Inspect", "Inspeccionar"),
    "browse": ("Browse…", "Examinar…"),
    "run": ("Run", "Ejecutar"),
    "done": ("Done", "Hecho"),
    "error": ("Error", "Error"),
    "working": ("Working…", "Trabajando…"),
    "busy": ("An operation is already running; please wait for it to finish.",
             "Ya hay una operación en curso; espera a que termine."),
    "close_busy": ("An operation is still running (it may be writing keys or files). Closing the "
                   "window now does not stop it: it finishes in the background before the program "
                   "exits.\n\nClose the window anyway?",
                   "Aún hay una operación en curso (puede estar escribiendo claves o ficheros). Cerrar "
                   "la ventana ahora no la detiene: termina en segundo plano antes de que el programa "
                   "salga.\n\n¿Cerrar la ventana de todos modos?"),
    "checking_php": ("Checking PHP…", "Comprobando PHP…"),
    "php_known": ("\n\nPHP was found in these usual folders. It is not used automatically (anyone on "
                  "this computer may be able to write there); if you trust one, choose it with Browse:"
                  "\n{paths}",
                  "\n\nSe encontró PHP en estas carpetas habituales. No se usa automáticamente "
                  "(cualquiera en este equipo podría escribir ahí); si confías en uno, elígelo con "
                  "Examinar:\n{paths}"),
    "password": ("Password", "Contraseña"),
    "password_confirm": ("Repeat password", "Repite la contraseña"),
    "password_mismatch": ("The passwords do not match", "Las contraseñas no coinciden"),
    "ask_password_for": ("Password for {name}", "Contraseña de {name}"),
    "field_required": ("Fill in: {name}", "Rellena: {name}"),
    "wrong_file_kind": ("That file looks like {got}. Here you must choose {want}.",
                        "Ese fichero parece {got}. Aquí tienes que elegir {want}."),
    "kind_owner": ("a signing key (owner)", "una clave de firma (owner)"),
    "kind_recipient": ("a server key (recipient)", "una clave de servidor (recipient)"),
    "kind_public": ("a public key (.pub.json)", "una clave pública (.pub.json)"),
    "kind_developer": ("a developer descriptor", "un descriptor de desarrollador"),
    "kind_encrypted": ("an encrypted key", "una clave cifrada"),
    "kind_unknown": ("not an Envelock key file", "no es un fichero de clave de Envelock"),
    "out_exists_not_empty": ("The output folder already exists and is not empty. Choose another, "
                             "or empty it.", "La carpeta de salida ya existe y no está vacía. Elige "
                             "otra, o vacíala."),
    # pack tab
    "pack_help": ("Encrypt your PHP project for one or more servers. Encrypt only your own code; "
                  "leave vendor/ out and deploy it separately.\n"
                  "Example names: owner → owner.enc.json · server → servidor1.pub.json · "
                  "output → \"<project> cifrado\" (a new, empty or non-existent folder).",
                  "Cifra tu proyecto PHP para uno o varios servidores. Cifra solo tu código; "
                  "deja vendor/ fuera y despliégalo aparte.\n"
                  "Ejemplos de nombres: owner → owner.enc.json · servidor → servidor1.pub.json · "
                  "salida → \"<proyecto> cifrado\" (una carpeta nueva, vacía o que no exista)."),
    "owner_file": ("Signing key (owner)", "Clave de firma (owner)"),
    "recipients": ("Server public keys", "Claves públicas de los servidores"),
    "recipients_help": ("Add the PUBLIC key (.pub.json) of each target server — the file you made "
                        "with 'Export public key', not the private .enc.json.",
                        "Añade la clave PÚBLICA (.pub.json) de cada servidor de destino — el fichero "
                        "que creaste con 'Exportar clave pública', no el privado .enc.json."),
    "add": ("Add", "Añadir"),
    "remove": ("Remove", "Quitar"),
    "project_id": ("Project ID", "ID del proyecto"),
    "new_project": ("New", "Nuevo"),
    "source": ("Project folder", "Carpeta del proyecto"),
    "output": ("Output folder (new)", "Carpeta de salida (nueva)"),
    "options": ("Options", "Opciones"),
    "opt_strip": ("Remove comments (less memory)", "Quitar comentarios (menos memoria)"),
    "opt_obf": ("Obfuscate local variables", "Ofuscar variables locales"),
    "opt_compact": ("Compact (remove formatting; no line numbers)",
                    "Compactar (quita formato; sin números de línea)"),
    "opt_encstr": ("Encode string literals (hide SQL, messages, paths)",
                   "Codificar cadenas (oculta SQL, mensajes, rutas)"),
    "opt_methods": ("Rename private methods (test the package)",
                    "Renombrar métodos privados (prueba el paquete)"),
    "opt_props": ("Rename private properties (HIGH RISK: breaks serialized data; test)",
                  "Renombrar propiedades privadas (ALTO RIESGO: rompe datos serializados; prueba)"),
    "opt_flow": ("Obfuscate control flow (opaque-predicate dead branches; test the package)",
                 "Ofuscar el flujo (ramas muertas con predicado opaco; prueba el paquete)"),
    "opt_vault": ("Vault string literals (keep SQL/messages out of the compiled code; test)",
                  "Guardar cadenas en bóveda (saca SQL/mensajes del código compilado; prueba)"),
    "opt_inc": ("Include protection", "Protección de includes"),
    "opt_prepend": ("Refuse auto_prepend/append", "Rechazar auto_prepend/append"),
    "opt_ffi": ("Refuse FFI/dl() (blocks memory reads; only if app needs neither)",
                "Rechazar FFI/dl() (bloquea lectura de memoria; solo si la app no los usa)"),
    "opt_sealed": ("Sealed tree (refuse plain PHP under it and eval(); all .php must be protected)",
                   "Árbol sellado (rechaza PHP plano bajo él y eval(); todo .php debe ir protegido)"),
    "opt_enforce_manifest": ("Signed manifest at runtime — default (integrity + ~5x faster; uncheck to opt out)",
                             "Manifiesto firmado en runtime — por defecto (integridad + ~5x; desmárcalo para desactivar)"),
    "opt_allow_downgrade": ("Allow lowering an existing minimum",
                            "Permitir bajar un mínimo ya fijado"),
    "exclude": ("Exclude, e.g. vendor/*, tests/*", "Excluir, p. ej. vendor/*, tests/*"),
    "assets": ("Copy as-is, e.g. *.css, *.png", "Copiar tal cual, p. ej. *.css, *.png"),
    "php_path": ("PHP 8 (for the source-transformation options)", "PHP 8 (para las opciones que transforman el código)"),
    "php_not_found": ("The source-transformation options (remove comments, compact, obfuscate, obfuscate "
                      "flow/methods/properties, encode strings, vault strings) need PHP 8 (php.exe), "
                      "which was not found at: {cmd}\n\nClick Browse next to 'PHP 8' and choose your "
                      "php.exe (for example C:\\wamp64\\bin\\php\\php8.3.x\\php.exe), or untick those options.",
                      "Las opciones que transforman el código (quitar comentarios, compactar, ofuscar, "
                      "ofuscar flujo/métodos/propiedades, codificar cadenas, bóveda de cadenas) necesitan "
                      "PHP 8 (php.exe), y no se encontró en: {cmd}\n\nPulsa Examinar junto a 'PHP 8' y "
                      "elige tu php.exe (por ejemplo C:\\wamp64\\bin\\php\\php8.3.x\\php.exe), o desmárcalas."),
    "php_old": ("{cmd} is PHP {detail}; these options need PHP 8 or newer. Choose a PHP 8 php.exe, "
                "or untick them.",
                "{cmd} es PHP {detail}; estas opciones necesitan PHP 8 o superior. Elige un php.exe "
                "de PHP 8, o desmárcalas."),
    "php_no_tokenizer": ("{cmd} (PHP {detail}) lacks the 'tokenizer' extension these options need. "
                         "Enable it in its php.ini, or choose another PHP.",
                         "{cmd} (PHP {detail}) no tiene la extensión 'tokenizer' que necesitan estas "
                         "opciones. Actívala en su php.ini, o elige otro PHP."),
    "php_error": ("{cmd} could not be run: {detail}", "No se pudo ejecutar {cmd}: {detail}"),
    "php_no_vcruntime": ("{cmd} cannot start: Microsoft's 'Visual C++ Redistributable' is missing.",
                         "{cmd} no arranca: falta el 'Visual C++ Redistributable' de Microsoft."),
    "php_offer_download": ("'Remove comments' and 'Obfuscate' need PHP 8, and there is no usable one "
                           "({cmd}).\n\nDownload the official PHP 8 for Windows from php.net over "
                           "HTTPS (about 35 MB), compare it with the SHA-256 that php.net's own "
                           "release list gives (this detects a damaged or altered download; it is not "
                           "a separate signature) and save it next to the assistant?",
                           "'Quitar comentarios' y 'Ofuscar' necesitan PHP 8 y no hay uno utilizable "
                           "({cmd}).\n\n¿Descargo el PHP 8 oficial para Windows desde php.net por "
                           "HTTPS (unos 35 MB), lo comparo con el SHA-256 que da la propia lista de "
                           "versiones de php.net (detecta una descarga dañada o alterada; no es una "
                           "firma aparte) y lo guardo junto al asistente?"),
    "php_folder_not_writable": ("The assistant's folder cannot be written ({folder}), probably because "
                                "it is protected. Save PHP in your user folder instead?\n\n{alt}",
                                "No se puede escribir en la carpeta del asistente ({folder}), "
                                "seguramente porque está protegida. ¿Guardo PHP en tu carpeta de "
                                "usuario?\n\n{alt}"),
    "php_downloading": ("Downloading PHP 8 from php.net…", "Descargando PHP 8 desde php.net…"),
    "php_ready": ("PHP {version} is ready:\n{path}", "PHP {version} listo:\n{path}"),
    "vc_offer": ("PHP needs Microsoft's 'Visual C++ Redistributable', which is not installed.\n\n"
                 "Download it from Microsoft and install it? It runs only if Microsoft's signature is "
                 "valid, and Windows will ask for administrator permission.",
                 "PHP necesita el 'Visual C++ Redistributable' de Microsoft, que no está instalado."
                 "\n\n¿Lo descargo de Microsoft y lo instalo? Solo se ejecuta si la firma de "
                 "Microsoft es válida, y Windows pedirá permiso de administrador."),
    "vc_installing": ("Installing Microsoft Visual C++…", "Instalando Microsoft Visual C++…"),
    "vc_failed": ("The Visual C++ installation did not finish (code {code}). If you cancelled the "
                  "administrator prompt, try again.",
                  "La instalación de Visual C++ no terminó (código {code}). Si cancelaste el permiso "
                  "de administrador, vuelve a intentarlo."),
    "php_install_hint": ("'Remove comments' and 'Obfuscate' need PHP 8 with the tokenizer, and there "
                         "is no usable one ({cmd}).\n\nInstall it with:\n    {command}\n\nthen try "
                         "again, or untick those two options.",
                         "'Quitar comentarios' y 'Ofuscar' necesitan PHP 8 con el tokenizer y no hay "
                         "uno utilizable ({cmd}).\n\nInstálalo con:\n    {command}\n\ny vuelve a "
                         "intentarlo, o desmarca esas dos opciones."),
    "encrypt": ("Encrypt the file with a password", "Cifrar el fichero con contraseña"),
    "pack_ok": ("Encrypted {n} file(s), copied {a} asset(s).\nProject {p}\nSerial {s}",
                "Cifrados {n} fichero(s), copiados {a} recurso(s).\nProyecto {p}\nSerial {s}"),
    "asset_not_copied": ("\n\nNOT copied: {asset} — {reason}.",
                         "\n\nNO copiado: {asset} — {reason}."),
    # keys tab
    "keys_help": ("Create your keys once. The owner signs; each server has its own recipient key. "
                  "Share only the public (.pub) files and keep the private ones safe.",
                  "Crea tus claves una vez. El owner firma; cada servidor tiene su clave recipient. "
                  "Comparte solo los ficheros públicos (.pub) y guarda bien los privados."),
    "create_owner": ("Create signing key (owner)", "Crear clave de firma (owner)"),
    "with_recovery": ("Also create a recovery key", "Crear también clave de recuperación"),
    "create_recipient": ("Create server key (recipient)", "Crear clave de servidor (recipient)"),
    "label": ("Label", "Etiqueta"),
    "export_public": ("Export public key (from a recipient)", "Exportar clave pública (de un recipient)"),
    "export_developer": ("Export developer descriptor (from owner)", "Exportar descriptor de desarrollador (del owner)"),
    "recipient_file": ("Recipient file", "Fichero recipient"),
    "out_file": ("Save to", "Guardar en"),
    "create": ("Create", "Crear"),
    # identity tab
    "identity_help": ("Build the secret identity file that goes on the server. It carries the "
                      "private key that decrypts and the trusted signer.",
                      "Construye el fichero de identidad secreto que va en el servidor. Lleva la "
                      "clave privada que descifra y el firmante de confianza."),
    "identity_file": ("Identity file (.bin)", "Fichero de identidad (.bin)"),
    "id_add": ("Build the server identity", "Crear la identidad del servidor"),
    "id_add_help": ("This builds the secret .bin that goes on the server. Give that server's "
                    "recipient key (its private .enc.json) and your owner (.enc.json); it stores "
                    "the private key that decrypts and your signer as trusted. It asks for both "
                    "passwords. Then copy only the .bin to the server.",
                    "Crea el .bin secreto que va en el servidor. Indica la clave recipient de ese "
                    "servidor (su .enc.json privado) y tu owner (.enc.json); guarda la clave "
                    "privada que descifra y tu firmante como de confianza. Pedirá las dos "
                    "contraseñas. Luego copia solo el .bin al servidor."),
    "id_remove_recipient": ("Remove recipient", "Quitar recipient"),
    "id_set_dev": ("Add/update trusted developer", "Añadir/actualizar desarrollador de confianza"),
    "id_remove_dev": ("Remove developer (by id)", "Quitar desarrollador (por id)"),
    "developer_file": ("Developer descriptor", "Descriptor de desarrollador"),
    "developer_id": ("Developer id", "Id de desarrollador"),
    "public_file": ("Server public key", "Clave pública del servidor"),
    "id_min": ("Refuse releases older than a package", "Rechazar releases anteriores a un paquete"),
    "package_dir": ("Packaged folder", "Carpeta cifrada"),
    "restart_note": ("Remember to restart PHP on the server after changing the identity file.",
                     "Recuerda reiniciar PHP en el servidor tras cambiar el fichero de identidad."),
    # rotate tab
    "rotate_help": ("Rotate a stolen or lost key without recompiling the loader.",
                    "Rota una clave robada o perdida sin recompilar el cargador."),
    "new_recovery": ("Replace the recovery key (in place)", "Reemplazar la clave de recuperación (en el sitio)"),
    "promote_recovery": ("Primary stolen: promote the recovery key", "Primaria robada: promover la recuperación"),
    "new_owner_file": ("New owner file", "Nuevo fichero owner"),
    "warning": ("Warning", "Aviso"),
    "promote_plaintext_warn": (
        "No password given: the new owner file will hold the NEW private signing keys in PLAIN "
        "TEXT, even if its name ends in .enc.json. Write it unencrypted anyway?",
        "Sin contraseña: el nuevo fichero owner guardará las NUEVAS claves privadas de firma en "
        "TEXTO PLANO, aunque su nombre acabe en .enc.json. ¿Escribirlo sin cifrar de todos modos?"),
    # inspect tab
    "inspect_help": ("Show the non-secret metadata of a package, identity file or descriptor.",
                     "Muestra los metadatos no secretos de un paquete, identidad o descriptor."),
    "file": ("File", "Fichero"),
    "inspect": ("Inspect", "Inspeccionar"),
    "tab_recommend": ("Recommend", "Recomendar"),
    "recommend_help": (
        "Analyse the project and recommend the STRONGEST protection that is safe for it, in three groups: "
        "options to enable; options to enable but CHECK FIRST, because they depend on the server or on "
        "code the analysis cannot see (each says why and how to check); and options not to enable, each "
        "with the reason. Read-only; it changes nothing.",
        "Analiza el proyecto y recomienda la MÁXIMA protección segura para él, en tres grupos: opciones "
        "que activar; opciones que activar pero COMPROBAR ANTES, porque dependen del servidor o de código "
        "que el análisis no ve (cada una dice por qué y cómo comprobarlo); y opciones que no activar, cada "
        "una con su motivo. Solo lectura; no cambia nada."),
    "recommend_btn": ("Analyse and recommend", "Analizar y recomendar"),
}


# File-type filters for the browse dialogs, and the extension hint shown in each label.
ANY_FILES = [("All files", "*.*")]
_JSON = [("JSON key", "*.json")] + ANY_FILES
_PUB = [("Public key", "*.pub.json"), ("JSON", "*.json")] + ANY_FILES
_BIN = [("Identity file", "*.bin")] + ANY_FILES
FILETYPES = {
    "owner_file": (_JSON, ".json"),
    "recipient_file": (_JSON, ".json"),
    "developer_file": (_JSON, ".json"),
    "public_file": (_PUB, ".pub.json"),
    "out_file": (_JSON, ".json"),
    "new_owner_file": (_JSON, ".json"),
    "identity_file": (_BIN, ".bin"),
    "file": (ANY_FILES, ""),
    "php_path": ([("PHP", "php.exe"), ("PHP", "php")] + ANY_FILES, ""),
}

# When opening a file for one of these fields, the kind must be one of these (an encrypted file
# hides its real kind, so it is accepted here and verified later when the password is given).
EXPECT_KIND = {
    "owner_file": {"envelock-owner", "envelock-encrypted"},
    "recipient_file": {"envelock-recipient", "envelock-encrypted"},
    "developer_file": {"envelock-developer-public"},
    "public_file": {"envelock-recipient-public"},
}
# Human name of a detected kind, for the "wrong file" warning.
KIND_STRING = {
    "envelock-owner": "kind_owner", "envelock-recipient": "kind_recipient",
    "envelock-recipient-public": "kind_public", "envelock-developer-public": "kind_developer",
    "envelock-encrypted": "kind_encrypted", None: "kind_unknown",
}


class Assistant(tk.Tk):
    def __init__(self):
        super().__init__()
        self.lang = 0                       # 0 = English, 1 = Spanish
        self._php = None                    # detected PHP 8 CLI, kept across language switches
        self._php_var = None                # the "PHP 8" field of the current Encrypt tab
        self._busy = False                  # one operation at a time (ENV-18: no concurrent runs)
        self._queue: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
        self._build()
        self.after(100, self._drain)
        # Closing mid-operation must not kill a worker writing keys or a package (T-13).
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # Look once for a PHP 8 CLI (the assistant's own download, else PATH) without blocking the
        # window. It only probes PHP (read-only), so it may be cut short at exit.
        self._detector = threading.Thread(target=self._detect_php, daemon=True)
        self._detector.start()

    def _on_close(self):
        """Close the window; while an operation runs, only after the user confirms. The worker is
        not a daemon thread, so it still completes (and cleans up its temporary files) before the
        program exits instead of being killed halfway."""
        if self._busy and not messagebox.askyesno(self.t("warning"), self.t("close_busy")):
            return
        self.destroy()

    def _idle(self) -> bool:
        """True when no operation runs; else tell the user and return False. Every action handler
        checks this FIRST, before any dialog, PHP probe or file change (T-12)."""
        if self._busy:
            messagebox.showinfo(self.t("working"), self.t("busy"))
            return False
        return True

    def _detect_php(self):
        try:
            found = actions.find_php()
        except Exception:                 # detection is only a convenience: Run checks PHP again
            return
        if found:
            self._queue.put(("silent", found, self._apply_php))

    def _apply_php(self, found):
        """Remember the detected PHP and fill the field, unless the user chose another one."""
        self._php = found
        var = self._php_var
        try:
            if var is not None and var.get().strip() in ("", "php"):
                var.set(found)
        except tk.TclError:                           # the tab was rebuilt meanwhile
            pass

    def t(self, key: str, **kw) -> str:
        text = STRINGS[key][self.lang]
        return text.format(**kw) if kw else text

    # --- layout -------------------------------------------------------------------------------
    def _build(self):
        self.title(self.t("title"))
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text=self.t("language") + ":").pack(side="left")
        choice = ttk.Combobox(top, values=["English", "Español"], state="readonly", width=12)
        choice.current(self.lang)
        choice.pack(side="left", padx=6)
        choice.bind("<<ComboboxSelected>>", lambda e: self._switch_language(choice.current()))
        # Project page (Apache-2.0; "Powered by Envelock" acknowledgements appreciated).
        ttk.Label(top, text="Envelock · miguelenred.es/envelock").pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=4)
        for name, builder in (("tab_pack", self._tab_pack), ("tab_recommend", self._tab_recommend),
                              ("tab_keys", self._tab_keys),
                              ("tab_identity", self._tab_identity), ("tab_rotate", self._tab_rotate),
                              ("tab_inspect", self._tab_inspect)):
            frame = ttk.Frame(self.nb, padding=10)
            self.nb.add(frame, text=self.t(name))
            builder(frame)

        self.status = ttk.Label(self, relief="sunken", anchor="w", padding=4)
        self.status.pack(fill="x", side="bottom")

        # Size the window to fit its tallest tab, so nothing is cut off, with sensible minimums.
        self.update_idletasks()
        width = max(self.winfo_reqwidth(), 800)
        height = max(self.winfo_reqheight() + 20, 600)
        self.geometry(f"{width}x{height}")
        self.minsize(min(width, 700), min(height, 600))

    def _switch_language(self, index: int):
        self.lang = index
        for widget in list(self.children.values()):
            widget.destroy()
        self._build()

    # --- helpers ------------------------------------------------------------------------------
    def _row(self, parent, key, kind="entry"):
        """A labelled row; returns the variable. kind: entry | dir | file | savefile. When the
        field expects a file, the label shows the extension and the browse dialog filters by it."""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=3)
        ftypes, hint = FILETYPES.get(key, (None, ""))
        label = self.t(key) + (f"  ({hint})" if hint and kind != "entry" else "")
        ttk.Label(frame, text=label, width=38, anchor="w").pack(side="left")
        var = tk.StringVar()
        ttk.Entry(frame, textvariable=var).pack(side="left", fill="x", expand=True)
        if kind != "entry":
            ttk.Button(frame, text=self.t("browse"),
                       command=lambda: self._pick(var, kind, ftypes, key)).pack(side="left", padx=4)
        return var

    def _pick(self, var, kind, ftypes=None, key=None):
        if kind == "dir":
            path = filedialog.askdirectory()
        elif kind == "savefile":
            # Offer the suggested file name already shown in the field.
            current = Path(var.get()).name if var.get() else ""
            path = filedialog.asksaveasfilename(filetypes=ftypes or ANY_FILES,
                                                defaultextension=".json", initialfile=current)
        else:
            path = filedialog.askopenfilename(filetypes=ftypes or ANY_FILES)
            if path and not self._kind_ok(path, EXPECT_KIND.get(key)):
                return
        if path:
            var.set(path)

    def _wrong_kind_message(self, path, allowed):
        """The warning text if a chosen file is the wrong kind for the field, else None (pure,
        no dialog, so it is testable). Encrypted files pass: their kind is verified later."""
        if not allowed:
            return None
        got = actions.file_kind(Path(path))
        if got in allowed:
            return None
        wants = {"envelock-owner": "kind_owner", "envelock-recipient": "kind_recipient",
                 "envelock-recipient-public": "kind_public",
                 "envelock-developer-public": "kind_developer"}
        want_key = next((wants[k] for k in wants if k in allowed), "kind_unknown")
        return self.t("wrong_file_kind",
                      got=self.t(KIND_STRING.get(got, "kind_unknown")), want=self.t(want_key))

    def _kind_ok(self, path, allowed) -> bool:
        """Warn and reject if a chosen file is clearly the wrong kind for the field."""
        message = self._wrong_kind_message(path, allowed)
        if message:
            messagebox.showwarning(self.t("error"), message)
        return message is None

    def _ask_password(self, name: str, confirm: bool) -> bytes | None:
        """Modal password prompt; returns bytes, or None if cancelled."""
        dialog = tk.Toplevel(self)
        dialog.title(self.t("password"))
        dialog.transient(self)
        dialog.grab_set()
        result = {"value": None}
        ttk.Label(dialog, text=self.t("ask_password_for", name=name), padding=8).pack()
        first = tk.StringVar()
        second = tk.StringVar()
        ttk.Entry(dialog, textvariable=first, show="•", width=32).pack(padx=10, pady=2)
        if confirm:
            ttk.Label(dialog, text=self.t("password_confirm")).pack()
            ttk.Entry(dialog, textvariable=second, show="•", width=32).pack(padx=10, pady=2)

        def ok():
            if confirm and first.get() != second.get():
                messagebox.showerror(self.t("error"), self.t("password_mismatch"), parent=dialog)
                return
            result["value"] = first.get().encode()
            dialog.destroy()

        ttk.Button(dialog, text="OK", command=ok).pack(pady=8)
        dialog.bind("<Return>", lambda e: ok())
        self.wait_window(dialog)
        return result["value"]

    def _need(self, **fields) -> bool:
        for key, var in fields.items():
            if not var.get().strip():
                messagebox.showerror(self.t("error"), self.t("field_required", name=self.t(key)))
                return False
        return True

    def _run_async(self, work, on_ok, status: str = "working"):
        """Run work() off the UI thread; report through the queue. One operation at a time: while
        one runs, another is refused, so two clicks cannot pack, write a key or rotate at once and
        race on the same files (ENV-18)."""
        if not self._idle():
            return
        self._busy = True
        self.status.config(text=self.t(status))

        def task():
            try:
                self._queue.put(("ok", work(), on_ok))
            except Exception as error:                        # surfaced to the user as-is
                self._queue.put(("error", str(error), None))
        # Not a daemon: closing the window must not kill an operation halfway (a key file's
        # .tmp-XXXX holding private keys, a half-written package, a .php-* extraction folder).
        self._worker = threading.Thread(target=task, daemon=False)
        self._worker.start()

    def _check_php_async(self, cmd: str, then):
        """Probe a PHP (up to 30 s) off the UI thread, then call then(reason, detail) on it."""
        self._run_async(lambda: actions.check_php(cmd), lambda result: then(*result),
                        status="checking_php")

    def _known_php_hint(self) -> str:
        """The usual-folder PHPs, listed for the user to choose (never run automatically)."""
        try:
            paths = actions.known_php_locations()
        except OSError:
            paths = []
        return self.t("php_known", paths="\n".join(paths[:6])) if paths else ""

    def _drain(self):
        # Reschedule in a finally: a callback that raises must never kill the drain loop (which
        # would leave _busy stuck True and freeze the UI). Each item is dispatched in its own
        # try/except so one bad callback cannot stop the rest or the reschedule.
        try:
            while True:
                try:
                    status, payload, on_ok = self._queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    if status == "silent":           # background result, no status change
                        on_ok(payload)
                    elif status == "ok":
                        self._busy = False           # cleared before on_ok, which may start the next op
                        self.status.config(text=self.t("done"))
                        (on_ok or (lambda r: None))(payload)
                    else:
                        self._busy = False
                        self.status.config(text=self.t("error"))
                        messagebox.showerror(self.t("error"), payload)
                except Exception as error:           # a callback failing never wedges the UI
                    self._busy = False
                    try:
                        messagebox.showerror(self.t("error"), str(error))
                    except Exception:  # nosec B110 # last resort: if even the dialog fails (Tk teardown), nothing else to do; finally still reschedules
                        pass
        finally:
            self.after(100, self._drain)

    def _fix_php(self, reason: str, cmd: str, php_var, retry) -> bool:
        """Offer to fix a missing or unusable PHP: on Windows download the official PHP 8 (next to
        the assistant) or install Microsoft's Visual C++ runtime; elsewhere show the install
        command. Returns True when it took over (a fix running in the background calls retry())."""
        import sys
        if sys.platform != "win32":
            if reason in ("not_found", "old", "no_tokenizer"):
                messagebox.showinfo(self.t("error"), self.t(
                    "php_install_hint", cmd=cmd, command=actions.php_install_hint())
                    + self._known_php_hint())
                return True
            return False
        if reason == "no_vcruntime":
            if not messagebox.askyesno(self.t("title"), self.t("vc_offer")):
                return False

            def install():
                import tempfile
                with tempfile.TemporaryDirectory() as work:
                    code = actions.install_vc_redist(Path(work))
                if not actions.vc_redist_installed(code):
                    raise ValueError(self.t("vc_failed", code=code))
            self._run_async(install, lambda _: retry(), status="vc_installing")
            return True
        if reason not in ("not_found", "old", "no_tokenizer"):   # another failure: just explain
            return False
        if not messagebox.askyesno(self.t("title"), self.t("php_offer_download", cmd=cmd)
                                   + self._known_php_hint()):
            return False
        dest = actions.php_home()
        if not actions.is_writable(dest):
            alt = actions.user_php_home()
            if not messagebox.askyesno(self.t("title"), self.t(
                    "php_folder_not_writable", folder=dest, alt=alt)):
                return True
            dest = alt

        def done(exe):
            self._php = str(exe)
            php_var.set(str(exe))
            messagebox.showinfo(self.t("done"), self.t("php_ready", version=exe.parent.name, path=exe))
            retry()
        self._run_async(lambda: actions.download_php(dest), done, status="php_downloading")
        return True

    def _encrypt_password(self, encrypt_var, name, confirm=True):
        """None if 'encrypt' is unticked, else the prompted password (raises on cancel)."""
        if not encrypt_var.get():
            return None
        pw = self._ask_password(name, confirm)
        if pw is None:
            raise ValueError("cancelled")
        return pw

    def _password_for(self, path_str):
        """Ask for a password only if the file is encrypted."""
        path = Path(path_str)
        if path.exists() and actions.is_encrypted(path):
            pw = self._ask_password(path.name, False)
            if pw is None:
                raise ValueError("cancelled")
            return pw
        return None

    # --- tabs ---------------------------------------------------------------------------------
    def _tab_pack(self, f):
        ttk.Label(f, text=self.t("pack_help"), wraplength=660, foreground="#555").pack(anchor="w", pady=(0, 8))
        owner = self._row(f, "owner_file", "file")

        recip_frame = ttk.LabelFrame(f, text=self.t("recipients") + "  (.pub.json)", padding=6)
        recip_frame.pack(fill="x", pady=4)
        ttk.Label(recip_frame, text=self.t("recipients_help"), wraplength=560,
                  foreground="#555").pack(anchor="w")
        inner = ttk.Frame(recip_frame)
        inner.pack(fill="x")
        recip_list = tk.Listbox(inner, height=3)
        recip_list.pack(side="left", fill="x", expand=True)
        buttons = ttk.Frame(inner)
        buttons.pack(side="left", padx=4)

        def add_recipient():
            path = filedialog.askopenfilename(filetypes=_PUB)
            if path and self._kind_ok(path, {"envelock-recipient-public"}):
                recip_list.insert("end", path)
        ttk.Button(buttons, text=self.t("add"), command=add_recipient).pack(fill="x")
        ttk.Button(buttons, text=self.t("remove"),
                   command=lambda: [recip_list.delete(i) for i in reversed(recip_list.curselection())]).pack(fill="x")

        proj_frame = ttk.Frame(f)
        proj_frame.pack(fill="x", pady=3)
        ttk.Label(proj_frame, text=self.t("project_id"), width=38, anchor="w").pack(side="left")
        project = tk.StringVar()
        ttk.Entry(proj_frame, textvariable=project).pack(side="left", fill="x", expand=True)
        ttk.Button(proj_frame, text=self.t("new_project"),
                   command=lambda: project.set(actions.new_project())).pack(side="left", padx=4)

        source = self._row(f, "source", "dir")
        output = self._row(f, "output", "dir")
        # When the project folder is chosen, suggest a sibling "<name> cifrado" as the output,
        # unless the user already typed one.
        def suggest_output(*_):
            src = source.get().strip()
            if src and not output.get().strip():
                p = Path(src)
                output.set(str(p.with_name(p.name + " cifrado")))
        source.trace_add("write", suggest_output)

        opts = ttk.LabelFrame(f, text=self.t("options"), padding=6)
        opts.pack(fill="x", pady=4)
        strip = tk.BooleanVar()
        obf = tk.BooleanVar()
        comp = tk.BooleanVar()
        enc = tk.BooleanVar()
        meth = tk.BooleanVar()
        prop = tk.BooleanVar()
        flow = tk.BooleanVar()
        vault = tk.BooleanVar()
        inc = tk.BooleanVar()
        prep = tk.BooleanVar()
        ffi = tk.BooleanVar()
        seal = tk.BooleanVar()
        enfman = tk.BooleanVar(value=True)   # runtime manifest on by default (parity with the CLI)
        for var, key in ((strip, "opt_strip"), (obf, "opt_obf"), (comp, "opt_compact"),
                         (enc, "opt_encstr"), (meth, "opt_methods"), (prop, "opt_props"),
                         (flow, "opt_flow"), (vault, "opt_vault"), (inc, "opt_inc"), (prep, "opt_prepend"),
                         (ffi, "opt_ffi"), (seal, "opt_sealed"), (enfman, "opt_enforce_manifest")):
            ttk.Checkbutton(opts, text=self.t(key), variable=var).pack(anchor="w")
        exclude = self._row(opts, "exclude")
        assets = self._row(opts, "assets")
        php = self._row(opts, "php_path", "file")
        php.set(self._php or "php")
        self._php_var = php

        def run():
            if not self._idle():
                return
            if not self._need(owner_file=owner, source=source, output=output, project_id=project):
                return
            recipients = list(recip_list.get(0, "end"))
            if not recipients:
                messagebox.showerror(self.t("error"), self.t("field_required", name=self.t("recipients")))
                return
            # The source transformations run the user's PHP: check it before anything else, off
            # the UI thread (the probe may take up to 30 s), then continue in php_checked.
            if (strip.get() or obf.get() or comp.get() or enc.get() or meth.get()
                    or prop.get() or flow.get() or vault.get()):
                cmd = php.get().strip() or "php"

                def php_checked(reason, detail):
                    if reason != "ok":
                        # Offer a download / runtime install (it re-runs this when ready); else explain.
                        if not self._fix_php(reason, cmd, php, run):
                            hint = self._known_php_hint() if reason == "not_found" else ""
                            messagebox.showerror(self.t("error"),
                                                 self.t("php_" + reason, cmd=cmd, detail=detail) + hint)
                        return
                    proceed(recipients)
                self._check_php_async(cmd, php_checked)
                return
            proceed(recipients)

        def proceed(recipients):
            # Ask for (and decrypt) the key passwords FIRST, before touching the output folder: the
            # old order removed an existing empty output folder and only then prompted, so cancelling
            # the password dialog deleted a folder the user had just created (ENV-2026-21).
            try:
                owner_pw = self._password_for(owner.get())
                # A recipient should be a public .pub.json (no password). If an encrypted private
                # recipient was chosen by mistake, ask for its password instead of failing.
                recipient_pws = [self._password_for(r) for r in recipients]
            except ValueError:
                return
            if not self._idle():          # nothing may have started meanwhile: check before rmdir
                return
            # The output must be a new folder. The folder picker can only select an existing one,
            # so accept an existing EMPTY folder (remove it so pack recreates it); refuse a
            # non-empty one with a clear message.
            out_path = Path(output.get())
            if out_path.exists():
                try:
                    out_path.rmdir()               # succeeds only if it is empty
                except OSError:
                    messagebox.showerror(self.t("error"), self.t("out_exists_not_empty"))
                    return

            def work():
                return actions.pack(
                    Path(owner.get()), owner_pw, [Path(r) for r in recipients], project.get().strip(),
                    Path(source.get()), Path(output.get()), recipient_passwords=recipient_pws,
                    assets=_split(assets.get()), exclude=_split(exclude.get()),
                    strip_comments=strip.get(), obfuscate=obf.get(), compact=comp.get(),
                    encode_strings=enc.get(), obfuscate_methods=meth.get(),
                    obfuscate_properties=prop.get(),
                    obfuscate_flow=flow.get(), vault_strings=vault.get(),
                    include_protection=inc.get(), no_prepend=prep.get(), no_ffi=ffi.get(),
                    sealed=seal.get(), enforce_manifest=enfman.get(), php=php.get() or "php")

            self._run_async(work, lambda info: messagebox.showinfo(
                self.t("done"), self.t("pack_ok", n=info["protected_files"], a=info["copied_assets"],
                                       p=info["project_id"], s=info["serial"])
                + "".join(self.t("asset_not_copied", asset=m["asset"], reason=m["reason"])
                          for m in info.get("assets_not_copied", []))))

        ttk.Button(f, text=self.t("run"), command=run).pack(pady=8)

    def _tab_keys(self, f):
        ttk.Label(f, text=self.t("keys_help"), wraplength=660, foreground="#555").pack(anchor="w", pady=(0, 8))

        box = ttk.LabelFrame(f, text=self.t("create_owner"), padding=6)
        box.pack(fill="x", pady=4)
        owner_out = self._row(box, "out_file", "savefile")
        owner_out.set("owner.enc.json")
        recovery = tk.BooleanVar(value=True)
        ttk.Checkbutton(box, text=self.t("with_recovery"), variable=recovery).pack(anchor="w")
        enc1 = self._encrypt_check(box)
        ttk.Button(box, text=self.t("create"), command=lambda: self._do_create_owner(
            owner_out, recovery, enc1)).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("create_recipient"), padding=6)
        box.pack(fill="x", pady=4)
        rec_out = self._row(box, "out_file", "savefile")
        rec_out.set("servidor1.enc.json")
        label = self._row(box, "label")
        # Suggest "<label>.enc.json" while the save field is still a bare suggestion (no folder).
        label.trace_add("write", lambda *a: _suggest(rec_out, label.get(), ".enc.json"))
        enc2 = self._encrypt_check(box)
        ttk.Button(box, text=self.t("create"), command=lambda: self._do_create_recipient(
            rec_out, label, enc2)).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("export_public"), padding=6)
        box.pack(fill="x", pady=4)
        rec_in = self._row(box, "recipient_file", "file")
        pub_out = self._row(box, "out_file", "savefile")
        pub_out.set("servidor1.pub.json")
        # Suggest "<recipient name>.pub.json" from the chosen recipient file.
        rec_in.trace_add("write", lambda *a: _suggest(
            pub_out, Path(rec_in.get()).name.split(".")[0], ".pub.json"))
        ttk.Button(box, text=self.t("create"), command=lambda: self._do_export_public(
            rec_in, pub_out)).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("export_developer"), padding=6)
        box.pack(fill="x", pady=4)
        own_in = self._row(box, "owner_file", "file")
        dev_out = self._row(box, "out_file", "savefile")
        dev_out.set("developer.json")
        ttk.Button(box, text=self.t("create"), command=lambda: self._do_export_developer(
            own_in, dev_out)).pack(anchor="e")

    def _encrypt_check(self, parent):
        var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text=self.t("encrypt"), variable=var).pack(anchor="w")
        return var

    def _do_create_owner(self, out, recovery, enc):
        if not self._idle():
            return
        if not self._need(out_file=out):
            return
        try:
            pw = self._encrypt_password(enc, Path(out.get()).name)
        except ValueError:
            return
        self._run_async(lambda: actions.create_owner(Path(out.get()), recovery.get(), pw, enc.get()),
                        lambda r: messagebox.showinfo(self.t("done"), self.t("done")))

    def _do_create_recipient(self, out, label, enc):
        if not self._idle():
            return
        if not self._need(out_file=out, label=label):
            return
        try:
            pw = self._encrypt_password(enc, Path(out.get()).name)
        except ValueError:
            return
        self._run_async(lambda: actions.create_recipient(Path(out.get()), label.get(), pw, enc.get()),
                        lambda r: messagebox.showinfo(self.t("done"), self.t("done")))

    def _do_export_public(self, rec_in, pub_out):
        if not self._idle():
            return
        if not self._need(recipient_file=rec_in, out_file=pub_out):
            return
        try:
            pw = self._password_for(rec_in.get())
        except ValueError:
            return
        self._run_async(lambda: actions.export_public(Path(rec_in.get()), pw, Path(pub_out.get())),
                        lambda r: messagebox.showinfo(self.t("done"), self.t("done")))

    def _do_export_developer(self, own_in, dev_out):
        if not self._idle():
            return
        if not self._need(owner_file=own_in, out_file=dev_out):
            return
        try:
            pw = self._password_for(own_in.get())
        except ValueError:
            return
        self._run_async(lambda: actions.export_developer(Path(own_in.get()), pw, Path(dev_out.get())),
                        lambda r: messagebox.showinfo(self.t("done"), self.t("done")))

    def _tab_identity(self, f):
        ttk.Label(f, text=self.t("identity_help"), wraplength=660, foreground="#555").pack(anchor="w", pady=(0, 6))
        identity = self._row(f, "identity_file", "savefile")
        identity.set("identity-servidor1.bin")

        box = ttk.LabelFrame(f, text=self.t("id_add"), padding=6)
        box.pack(fill="x", pady=3)
        ttk.Label(box, text=self.t("id_add_help"), wraplength=560, foreground="#555").pack(anchor="w")
        rec = self._row(box, "recipient_file", "file")
        own = self._row(box, "owner_file", "file")

        def add():
            if not self._idle():
                return
            if not self._need(identity_file=identity, recipient_file=rec, owner_file=own):
                return
            try:
                rpw, opw = self._password_for(rec.get()), self._password_for(own.get())
            except ValueError:
                return
            self._run_async(lambda: actions.identity_add_recipient(
                Path(identity.get()), Path(rec.get()), rpw, Path(own.get()), opw), self._identity_ok)
        ttk.Button(box, text=self.t("add"), command=add).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("id_set_dev"), padding=6)
        box.pack(fill="x", pady=3)
        dev = self._row(box, "developer_file", "file")
        ttk.Button(box, text=self.t("add"), command=lambda: self._idle() and self._need(
            identity_file=identity, developer_file=dev) and self._run_async(
            lambda: actions.identity_set_developer(Path(identity.get()), Path(dev.get())),
            self._identity_ok)).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("id_remove_recipient"), padding=6)
        box.pack(fill="x", pady=3)
        pub = self._row(box, "public_file", "file")
        ttk.Button(box, text=self.t("remove"), command=lambda: self._idle() and self._need(
            identity_file=identity, public_file=pub) and self._run_async(
            lambda: actions.identity_remove_recipient(Path(identity.get()), Path(pub.get())),
            self._identity_ok)).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("id_remove_dev"), padding=6)
        box.pack(fill="x", pady=3)
        dev_id = self._row(box, "developer_id")
        ttk.Button(box, text=self.t("remove"), command=lambda: self._idle() and self._need(
            identity_file=identity, developer_id=dev_id) and self._run_async(
            lambda: actions.identity_remove_developer(Path(identity.get()), dev_id.get()),
            self._identity_ok)).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("id_min"), padding=6)
        box.pack(fill="x", pady=3)
        pkg = self._row(box, "package_dir", "dir")
        mindown = tk.BooleanVar()
        ttk.Checkbutton(box, text=self.t("opt_allow_downgrade"), variable=mindown).pack(anchor="w")
        ttk.Button(box, text=self.t("run"), command=lambda: self._idle() and self._need(
            identity_file=identity, package_dir=pkg) and self._run_async(
            lambda: actions.identity_set_minimum(Path(identity.get()), package=Path(pkg.get()),
                                                 allow_downgrade=mindown.get()),
            self._identity_ok)).pack(anchor="e")

    def _identity_ok(self, _result):
        messagebox.showinfo(self.t("done"), self.t("done") + "\n\n" + self.t("restart_note"))

    def _tab_rotate(self, f):
        ttk.Label(f, text=self.t("rotate_help"), wraplength=660, foreground="#555").pack(anchor="w", pady=(0, 6))

        box = ttk.LabelFrame(f, text=self.t("new_recovery"), padding=6)
        box.pack(fill="x", pady=3)
        own = self._row(box, "owner_file", "file")

        def new_rec():
            if not self._idle():
                return
            if not self._need(owner_file=own):
                return
            try:
                pw = self._password_for(own.get())
            except ValueError:
                return
            self._run_async(lambda: actions.rotate_new_recovery(Path(own.get()), pw, pw is not None),
                            lambda r: messagebox.showinfo(self.t("done"), self.t("done")))
        ttk.Button(box, text=self.t("run"), command=new_rec).pack(anchor="e")

        box = ttk.LabelFrame(f, text=self.t("promote_recovery"), padding=6)
        box.pack(fill="x", pady=3)
        own2 = self._row(box, "owner_file", "file")
        out = self._row(box, "new_owner_file", "savefile")
        out.set("owner-nuevo.enc.json")

        def promote():
            if not self._idle():
                return
            if not self._need(owner_file=own2, new_owner_file=out):
                return
            try:
                pw = self._password_for(own2.get())
                # The new owner file holds fresh private signing keys: always offer to encrypt it,
                # regardless of whether the source was encrypted (ENV-AUD-16). Writing it in plain
                # text requires an explicit, informed confirmation.
                outpw = self._ask_password(Path(out.get()).name, True)
                if outpw is None:
                    return                                      # cancelled
                if outpw == b"":
                    if not messagebox.askyesno(self.t("warning"), self.t("promote_plaintext_warn")):
                        return
                    outpw = None                                # unencrypted, knowingly
            except ValueError:
                return
            self._run_async(lambda: actions.rotate_promote_recovery(
                Path(own2.get()), pw, Path(out.get()), outpw, outpw is not None),
                lambda r: messagebox.showinfo(self.t("done"), self.t("done")))
        ttk.Button(box, text=self.t("run"), command=promote).pack(anchor="e")

    def _tab_inspect(self, f):
        ttk.Label(f, text=self.t("inspect_help"), wraplength=660, foreground="#555").pack(anchor="w", pady=(0, 6))
        path = self._row(f, "file", "file")
        out = tk.Text(f, height=16, wrap="none")
        out.pack(fill="both", expand=True, pady=6)

        def show():
            if not self._idle():
                return
            if not self._need(file=path):
                return
            import json
            target = Path(path.get())

            def done(data):
                out.delete("1.0", "end")
                out.insert("1.0", data)
            # inspect_path reads (and checks) a whole package or identity file: off the UI thread
            # like Recommend (T-14); an error reaches the user through the queue as before.
            self._run_async(lambda: json.dumps(actions.inspect(target), indent=2), done)
        ttk.Button(f, text=self.t("inspect"), command=show).pack(anchor="e")

    def _tab_recommend(self, f):
        ttk.Label(f, text=self.t("recommend_help"), wraplength=660, foreground="#555").pack(
            anchor="w", pady=(0, 6))
        source = self._row(f, "source", "dir")
        out = tk.Text(f, height=18, wrap="word")
        out.pack(fill="both", expand=True, pady=6)

        def show():
            if not self._idle():
                return
            if not self._need(source=source):
                return
            src = Path(source.get())

            # Analyse OFF the UI thread (ENV-2026-22): recommend() walks the whole tree and ran
            # synchronously on Tk's event loop, freezing the window on a large project. _run_async
            # marshals the result back to the UI thread through the queue, like packing does.
            def work():
                return actions.recommend(src)["report"]

            def done(report):
                out.delete("1.0", "end")
                out.insert("1.0", report)

            self._run_async(work, done, status="working")
        ttk.Button(f, text=self.t("recommend_btn"), command=show).pack(anchor="e")


def _split(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def _suggest(var, base: str, ext: str):
    """Set var to '<base><ext>' only while it still holds a bare suggestion (no folder chosen),
    so a path the user actually picked is never overwritten."""
    base = base.strip()
    current = var.get()
    if base and "/" not in current and "\\" not in current:
        var.set(base + ext)


def main():
    import sys
    actions.release_bundle_search_paths()   # before starting PHP or PowerShell from the executable
    if "--e2e" in sys.argv:
        # Headless end-to-end (create keys, pack, open) — used to test the frozen executable.
        index = sys.argv.index("--e2e") + 1
        if index >= len(sys.argv) or sys.argv[index].startswith("-"):
            # A plain SystemExit, not an IndexError: a windowed build would otherwise sit on
            # PyInstaller's "unhandled exception" dialog instead of exiting.
            raise SystemExit("usage: envelock-assistant --e2e <workdir>")
        if getattr(sys, "frozen", False):
            _b = Path(getattr(sys, "_MEIPASS")) / "gui"
        else:
            _b = Path(__file__).resolve().parent
        import importlib.util
        _s = importlib.util.spec_from_file_location("_e2e", _b / "_e2e.py")
        _m = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(_m)
        _m.run(sys.argv[index])
        return
    if "--selftest" in sys.argv:
        # Headless check that the (possibly frozen) bundle wires up: encoder import, actions and
        # the window build, without entering the event loop. Prints OK and exits 0.
        app = Assistant()
        if len(app.nb.tabs()) != 6:
            raise SystemExit("selftest failed: unexpected tab count")
        app._switch_language(1)
        app._detector.join(60)            # let the PHP search finish (no half-run process at exit)
        app.destroy()
        print("selftest ok:", actions.new_project(), "| php:", actions.find_php() or "not found")
        return
    Assistant().mainloop()


if __name__ == "__main__":
    main()
