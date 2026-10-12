#!/usr/bin/env python3
"""n8Mouse+ - share one keyboard + mouse and the text clipboard across several
computers on the LAN. Free and open source (MIT).

  host   = the machine with the physical keyboard and mouse (Windows for now)
  client = every other machine (macOS or Windows)

Install once per machine:
  n8mouse setup host                  on the PC with the keyboard and mouse
  n8mouse setup client <CODE> [ip]    on every other machine
  n8mouse uninstall                   remove start-at-login and firewall rules

After setup it starts at login by itself. Manual run:
  n8mouse                             run in the role chosen at setup
  n8mouse host | n8mouse client <host-ip> [name]

Host hotkeys:  ScrollLock = back to host    Ctrl+Alt+1..9 = jump to screen N
"""
import base64
import hashlib
import json
import os
import queue
import secrets
import select
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

VERSION = "0.5.2"
APP_ID = "com.n8mouse.agent"
DEFAULT_CONFIG = {
    "role": "",              # host | client, set by setup
    "host_ip": "",           # client: where the host is
    "secret": "",            # pairing code, created by 'setup host'; same on every machine
    "port": 24800,
    "layout": {},            # empty = auto: host, then clients to the right in connect order
    "mac_ctrl_is_cmd": True, # PC host -> Mac client: Ctrl acts as Cmd, Win key acts as Ctrl
    "speed": 1.0,            # client pointer speed multiplier
    "scroll_pixels": 40,     # Mac client: pixels per wheel notch
    "clip_max_mb": 50,       # largest image or file copy and paste will carry
}
PING_EVERY = 2.0
DEAD_AFTER = 6.0
CLIP_POLL = 0.5
CLIP_MAX = 1_000_000
OPP = {"left": "right", "right": "left", "top": "bottom", "bottom": "top"}
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LEN = 16                # ~80 bits
MAX_LINE = 8_000_000         # largest single message (bytes)
MAX_HANDSHAKES = 16          # concurrent unauthenticated connections on the host
FAIL_LIMIT, FAIL_WINDOW = 5, 60.0   # wrong-code attempts per IP before a cool-down


def config_dir():
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "n8mouse")


def config_path():
    legacy = os.path.join(os.path.dirname(os.path.abspath(__file__)), "n8mouse.json")
    return legacy if os.path.exists(legacy) else os.path.join(config_dir(), "n8mouse.json")


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    path = config_path()
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg.update(json.load(f))
        except (OSError, ValueError) as e:
            sys.exit("cannot read %s: %s" % (path, e))
    return cfg


def save_config(cfg):
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    if sys.platform != "win32":
        os.chmod(path, 0o600)                      # holds the pairing code
    return path


def machine_name():
    return socket.gethostname().split(".")[0]


def norm_code(code):
    return "".join(ch for ch in str(code).upper() if ch.isalnum())


def new_code():
    return show_code("".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN)))


def show_code(code):
    c = norm_code(code)
    return "-".join(c[i:i + 4] for i in range(0, len(c), 4))


def code_ok(code):
    c = norm_code(code)
    return len(c) == CODE_LEN and all(ch in CODE_ALPHABET for ch in c)


def clean_name(name):
    return "".join(ch for ch in str(name) if ch.isalnum() or ch in "-_.")[:64] or "unnamed"


# ==========================================================================
# security: TLS 1.3 with a key derived from the pairing code
# ==========================================================================
_PSK_CACHE = {}


def require_tls():
    if sys.version_info < (3, 13) or not getattr(ssl, "HAS_PSK", False):
        sys.exit("n8Mouse+ needs Python 3.13 or newer (encrypted connections). "
                 "This is Python %d.%d." % sys.version_info[:2])


def psk_for(code):
    """32-byte key from the pairing code. scrypt makes guessing expensive even
    for someone who recorded a handshake."""
    c = norm_code(code)
    if c not in _PSK_CACHE:
        _PSK_CACHE[c] = hashlib.scrypt(c.encode(), salt=b"n8mouse-psk-v1",
                                       n=2 ** 14, r=8, p=1, dklen=32)
    return _PSK_CACHE[c]


def tls_context(server, code):
    """Both sides must hold the same pairing code or the handshake fails.
    The code itself never crosses the network; all traffic is encrypted."""
    psk = psk_for(code)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                # authentication is the shared key
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if server:
        ctx.set_psk_server_callback(lambda identity: psk if identity == "n8mouse" else b"")
    else:
        ctx.set_psk_client_callback(lambda hint: ("n8mouse", psk))
    return ctx


# ==========================================================================
# transport and clipboard (shared)
# ==========================================================================
class Link:
    """Newline-delimited JSON over an encrypted socket, with a heartbeat.
    Sends are queued so input hooks never wait on the network. One lock
    serialises TLS reads and writes (an SSL connection is not thread-safe)."""

    def __init__(self, sock):
        self.sock = sock
        self.alive = True
        self.q = queue.Queue()
        self.io = threading.Lock()
        self.last_rx = time.monotonic()
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        sock.setblocking(False)                        # never hold the lock while waiting
        threading.Thread(target=self._writer, daemon=True).start()
        threading.Thread(target=self._pinger, daemon=True).start()

    def send(self, **msg):
        if self.alive:
            self.q.put(msg)

    def _pinger(self):
        while self.alive:
            time.sleep(PING_EVERY)
            self.send(t="ping")

    def _writer(self):
        while self.alive:
            msg = self.q.get()
            if msg is None:
                break
            try:
                self._send_all((json.dumps(msg, separators=(",", ":")) + "\n").encode())
            except OSError:
                break
        self.close()

    def _send_all(self, data):
        view, deadline = memoryview(data), time.monotonic() + 5
        while view:
            try:
                with self.io:
                    sent = self.sock.send(view)
                view = view[sent:]
            except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError):
                if time.monotonic() > deadline:
                    raise OSError("send timed out")
                select.select([], [self.sock], [], 0.05)

    def messages(self):
        buf = b""
        while self.alive:
            try:
                pending = self.sock.pending() if hasattr(self.sock, "pending") else 0
            except (OSError, ValueError):
                break
            if not pending:
                try:
                    ready, _, _ = select.select([self.sock], [], [], 0.5)
                except (OSError, ValueError):
                    break
                if not ready:
                    if time.monotonic() - self.last_rx > DEAD_AFTER:
                        break                          # heartbeat lost
                    continue
            try:
                with self.io:
                    chunk = self.sock.recv(65536)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                continue                               # TLS housekeeping, no data yet
            except OSError:
                break
            if not chunk:
                break
            self.last_rx = time.monotonic()
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if isinstance(msg, dict) and msg.get("t") != "ping":
                    yield msg
            if len(buf) > MAX_LINE:
                break                                  # oversized message
        self.close()

    def close(self):
        if self.alive:
            self.alive = False
            self.q.put(None)
            try:
                self.sock.close()
            except OSError:
                pass


class Clip:
    """Text clipboard sync by polling. Remembers the last value so a received
    clip is never echoed back."""

    def __init__(self):
        import pyperclip
        self.pc = pyperclip
        self.lock = threading.Lock()
        self.rich = None                 # the image and file watcher, when there is one
        self.last = self._read()

    def _read(self):
        try:
            return self.pc.paste()
        except Exception:
            return None

    def set(self, text):
        with self.lock:
            try:
                self.pc.copy(text)
            except Exception:
                return
            self.last = text
        if self.rich is not None:
            self.rich.took_text()

    def unsent(self):
        """True when the clipboard holds text that has not been sent yet."""
        with self.lock:
            cur = self._read()
            return bool(cur) and cur != self.last and len(cur) <= CLIP_MAX

    def resync(self):
        """Forget whatever is on the clipboard now, so it is not sent as new text."""
        with self.lock:
            self.last = self._read()

    def watch(self, alive, on_change, rich=None):
        while alive():
            time.sleep(CLIP_POLL)
            if rich is not None:
                try:
                    held = rich.scan()
                except Exception as e:
                    held = False
                    print("clipboard: %s" % e)
                if held:                               # an image or a file is on it: not text
                    continue
            with self.lock:
                cur = self._read()
                if not cur or cur == self.last or len(cur) > CLIP_MAX:
                    continue
                self.last = cur
            if rich is not None:
                rich.local_at = time.monotonic()
            on_change(cur)


# ==========================================================================
# images and files on the clipboard (v0.5)
# ==========================================================================
RICH_CHUNK = 256 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic"}
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}


def safe_name(name):
    """A bare file name from whatever a peer sent: no folders, no odd characters."""
    name = str(name or "").replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*').strip(" .")[:150]
    if name.split(".")[0].upper() in WIN_RESERVED:
        name = "_" + name
    return name or "clipboard-file"


def ver_tuple(v):
    out = []
    for part in str(v).split(".")[:3]:
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def make_blob(kind, name, data):
    return {"id": secrets.token_hex(8), "kind": kind, "name": safe_name(name), "data": data,
            "sha": hashlib.sha256(data).hexdigest()}


def send_blob(link, blob):
    """Queue one image or file on a transfer link, in small pieces."""
    data = blob["data"]
    link.send(t="bstart", id=blob["id"], kind=blob["kind"], name=blob["name"], size=len(data), sha=blob["sha"])
    for i in range(0, len(data), RICH_CHUNK):
        link.send(t="bdata", id=blob["id"], d=base64.b64encode(data[i:i + RICH_CHUNK]).decode("ascii"))
    link.send(t="bend", id=blob["id"])


class BlobRx:
    """Puts a transfer back together. Refuses anything over the size cap, anything that
    grows past what was announced, and anything whose checksum does not match."""

    def __init__(self, maxbytes):
        self.max = maxbytes
        self.cur = None

    def feed(self, m):
        t = m.get("t")
        if t == "bstart":
            self.cur = None
            kind, size = m.get("kind"), m.get("size")
            if kind not in ("image", "file") or not isinstance(size, int) or not 0 < size <= self.max:
                raise ValueError("kind or size not allowed")
            self.cur = {"id": str(m.get("id"))[:32], "kind": kind, "name": safe_name(m.get("name")),
                        "size": size, "sha": str(m.get("sha")), "parts": [], "got": 0,
                        "t0": time.monotonic()}
        elif t == "bdata" and self.cur and m.get("id") == self.cur["id"]:
            d = base64.b64decode(str(m.get("d", "")), validate=True)
            self.cur["got"] += len(d)
            if self.cur["got"] > self.cur["size"]:
                self.cur = None
                raise ValueError("more data than announced")
            self.cur["parts"].append(d)
        elif t == "bend" and self.cur and m.get("id") == self.cur["id"]:
            c, self.cur = self.cur, None
            data = b"".join(c["parts"])
            if len(data) != c["size"] or hashlib.sha256(data).hexdigest() != c["sha"]:
                raise ValueError("size or checksum mismatch")
            return {"id": c["id"], "kind": c["kind"], "name": c["name"], "data": data, "sha": c["sha"],
                    "t0": c["t0"]}
        return None


def dib_to_png(dib):
    """Windows bitmap (CF_DIB) -> PNG bytes. Needs Pillow; returns None without it."""
    try:
        import io
        from PIL import BmpImagePlugin
        out = io.BytesIO()
        BmpImagePlugin.DibImageFile(io.BytesIO(dib)).save(out, "PNG")
        return out.getvalue()
    except Exception:
        return None


def png_to_dib(png):
    """PNG bytes -> Windows bitmap (CF_DIB). Needs Pillow; returns None without it."""
    try:
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(png))
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA" if "A" in img.getbands() or "transparency" in img.info else "RGB")
        if img.mode == "RGBA":                           # most Windows apps ignore alpha in a DIB
            from PIL import Image as I
            flat = I.new("RGB", img.size, (255, 255, 255))
            flat.paste(img, mask=img.split()[3])
            img = flat
        out = io.BytesIO()
        img.save(out, "BMP")
        return out.getvalue()[14:]                       # drop the 14-byte file header
    except Exception:
        return None


class ClipboardBusy(OSError):
    """Another program has the clipboard open right now. Try again shortly."""


def blob_label(blob):
    return "an image" if blob["kind"] == "image" else blob["name"]


def just_a_link(text):
    """A browser's 'copy image' also puts the picture's address on the clipboard as text."""
    t = str(text or "").strip()
    return 0 < len(t) < 4096 and not any(ch.isspace() for ch in t) \
        and t.lower().startswith(("http://", "https://", "file://", "data:"))


def pack_dropfiles(path):
    """CF_HDROP payload for one file path."""
    import struct
    return struct.pack("<IiiII", 20, 0, 0, 0, 1) + (path + "\0\0").encode("utf-16-le")


class WinRich:
    """Windows clipboard: images and single files, through ctypes."""
    CF_DIB, CF_UNICODETEXT, CF_HDROP = 8, 13, 15

    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        self.c = ctypes
        self.u = ctypes.WinDLL("user32", use_last_error=True)
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.sh = ctypes.WinDLL("shell32", use_last_error=True)
        self._hwnd = None
        u, k, sh, vp = self.u, self.k, self.sh, ctypes.c_void_p
        u.OpenClipboard.argtypes = [vp]
        u.CreateWindowExW.restype = vp
        u.CreateWindowExW.argtypes = [w.DWORD, ctypes.c_wchar_p, ctypes.c_wchar_p, w.DWORD,
                                      ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, vp, vp, vp, vp]
        u.DestroyWindow.argtypes = [vp]
        u.GetClipboardData.restype, u.GetClipboardData.argtypes = vp, [w.UINT]
        u.SetClipboardData.restype, u.SetClipboardData.argtypes = vp, [w.UINT, vp]
        u.IsClipboardFormatAvailable.argtypes = [w.UINT]
        u.RegisterClipboardFormatW.restype, u.RegisterClipboardFormatW.argtypes = w.UINT, [ctypes.c_wchar_p]
        k.GlobalAlloc.restype, k.GlobalAlloc.argtypes = vp, [w.UINT, ctypes.c_size_t]
        k.GlobalLock.restype, k.GlobalLock.argtypes = vp, [vp]
        k.GlobalUnlock.argtypes = [vp]
        k.GlobalFree.argtypes = [vp]
        k.GlobalSize.restype, k.GlobalSize.argtypes = ctypes.c_size_t, [vp]
        sh.DragQueryFileW.restype, sh.DragQueryFileW.argtypes = w.UINT, [vp, w.UINT, ctypes.c_wchar_p, w.UINT]
        self.PNG = u.RegisterClipboardFormatW("PNG")
        self.DROPEFFECT = u.RegisterClipboardFormatW("Preferred DropEffect")

    def seq(self):
        return self.u.GetClipboardSequenceNumber()

    def _open(self, own=False):
        """own=True opens with a window of ours: Windows needs an owner before it
        reliably accepts new clipboard data."""
        self._hwnd = self.u.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None) if own else None
        for _ in range(40):
            if self.u.OpenClipboard(self._hwnd):
                return True
            time.sleep(0.03)
        self._drop()
        return False

    def _drop(self):
        if self._hwnd:
            self.u.DestroyWindow(self._hwnd)
            self._hwnd = None

    def _close(self):
        self.u.CloseClipboard()
        self._drop()

    def _begin_write(self):
        if not self._open(own=True):
            raise OSError("the Windows clipboard is busy")
        if not self.u.EmptyClipboard():
            err = self.c.get_last_error()
            self._close()
            raise OSError("could not clear the Windows clipboard (error %d)" % err)

    def _get(self, fmt):
        h = self.u.GetClipboardData(fmt)
        if not h:
            return None
        p = self.k.GlobalLock(h)
        if not p:
            return None
        try:
            return self.c.string_at(p, self.k.GlobalSize(h))
        finally:
            self.k.GlobalUnlock(h)

    def _put(self, fmt, data):
        h = self.k.GlobalAlloc(0x0002, len(data))        # GMEM_MOVEABLE
        if not h:
            return False
        p = self.k.GlobalLock(h)
        self.c.memmove(p, data, len(data))
        self.k.GlobalUnlock(h)
        if not self.u.SetClipboardData(fmt, h):
            self._err = self.c.get_last_error()
            self.k.GlobalFree(h)
            return False
        return True

    def read(self, maxbytes):
        """('file', path) | ('image', png bytes) | None."""
        if not self._open():
            raise ClipboardBusy("the Windows clipboard is busy")
        path = png = dib = None
        try:
            if self.u.IsClipboardFormatAvailable(self.CF_HDROP):
                h = self.u.GetClipboardData(self.CF_HDROP)
                if h and self.sh.DragQueryFileW(h, 0xFFFFFFFF, None, 0) == 1:
                    buf = self.c.create_unicode_buffer(32768)
                    self.sh.DragQueryFileW(h, 0, buf, 32768)
                    path = buf.value
                else:
                    return None                           # several files or none: not supported
            elif self.u.IsClipboardFormatAvailable(self.CF_UNICODETEXT):
                return None                               # text wins (Excel and Word also add a picture)
            elif self.u.IsClipboardFormatAvailable(self.PNG):
                png = self._get(self.PNG)
            elif self.u.IsClipboardFormatAvailable(self.CF_DIB):
                dib = self._get(self.CF_DIB)
        finally:
            self._close()
        if path:
            return ("file", path)
        if dib and len(dib) <= 4 * maxbytes:
            png = dib_to_png(dib)
        return ("image", png) if png else None

    def write_image(self, png):
        dib = png_to_dib(png)
        self._begin_write()
        try:
            ok = self._put(self.PNG, png)
            if dib:
                ok = self._put(self.CF_DIB, dib) or ok
            if not ok:
                raise OSError("Windows refused the image (error %d)" % getattr(self, "_err", 0))
        finally:
            self._close()

    def as_png(self, data):
        """Picture file bytes -> PNG bytes, or None if it is not a picture we can read."""
        if data[:8] == PNG_MAGIC:
            return data
        try:
            import io
            from PIL import Image
            out = io.BytesIO()
            Image.open(io.BytesIO(data)).save(out, "PNG")
            return out.getvalue()
        except Exception:
            return None

    def write_file(self, path, png=None):
        """The file itself, plus its picture when it is one, so it pastes into
        folders and into picture apps alike."""
        import struct
        dib = png_to_dib(png) if png else None
        self._begin_write()
        try:
            if not self._put(self.CF_HDROP, pack_dropfiles(path)):
                raise OSError("Windows refused the file (error %d)" % getattr(self, "_err", 0))
            self._put(self.DROPEFFECT, struct.pack("<I", 1))   # copy, not move
            if png:
                self._put(self.PNG, png)
            if dib:
                self._put(self.CF_DIB, dib)
        finally:
            self._close()


class MacRich:
    """macOS clipboard: images and single files, through AppKit."""

    def __init__(self):
        import AppKit
        import Foundation
        self.A, self.F = AppKit, Foundation

    def _pb(self):
        return self.A.NSPasteboard.generalPasteboard()

    def seq(self):
        return int(self._pb().changeCount())

    def read(self, maxbytes):
        pb = self._pb()
        urls = pb.readObjectsForClasses_options_(
            [self.F.NSURL], {self.A.NSPasteboardURLReadingFileURLsOnlyKey: True})
        if urls:
            return ("file", str(urls[0].path())) if len(urls) == 1 else None
        text = pb.stringForType_("public.utf8-plain-text")
        if text and not just_a_link(text):
            return None                                   # text wins
        d = pb.dataForType_("public.png")
        if d is None:
            tiff = pb.dataForType_("public.tiff")
            if tiff is None or tiff.length() > 4 * maxbytes:
                return None
            rep = self.A.NSBitmapImageRep.imageRepWithData_(tiff)
            d = rep.representationUsingType_properties_(self.A.NSBitmapImageFileTypePNG, {}) if rep else None
        return ("image", bytes(d)) if d is not None else None

    def write_image(self, png):
        pb = self._pb()
        pb.clearContents()
        pb.setData_forType_(self.F.NSData.dataWithBytes_length_(png, len(png)), "public.png")

    def as_png(self, data):
        if data[:8] == PNG_MAGIC:
            return data
        rep = self.A.NSBitmapImageRep.imageRepWithData_(self.F.NSData.dataWithBytes_length_(data, len(data)))
        d = rep.representationUsingType_properties_(self.A.NSBitmapImageFileTypePNG, {}) if rep else None
        return bytes(d) if d is not None else None

    def write_file(self, path, png=None):
        pb = self._pb()
        pb.clearContents()
        pb.writeObjects_([self.F.NSURL.fileURLWithPath_(path)])
        if png:
            pb.addTypes_owner_(["public.png"], None)
            pb.setData_forType_(self.F.NSData.dataWithBytes_length_(png, len(png)), "public.png")


def rich_backend():
    try:
        if sys.platform == "win32":
            return WinRich()
        if sys.platform == "darwin":
            return MacRich()
    except Exception as e:
        print("image and file paste is off (%s)" % e)
    return None


class RichClip:
    """Watches this computer's clipboard for an image or a single file, and puts
    received ones onto it. Everything here fails soft: a clipboard problem must
    never disturb the keyboard and mouse.

    It remembers the checksum of the last item it sent or received, so reading
    that same item back off the clipboard is never mistaken for a new copy."""

    def __init__(self, cfg, backend="auto", clip=None):
        try:
            self.max = int(float(cfg.get("clip_max_mb", 50)) * 1_000_000)
        except (TypeError, ValueError):
            self.max = 50_000_000
        self.b = rich_backend() if backend == "auto" else backend
        self.clip = clip                 # the text clipboard, told to stand down for images and files
        self.on_change = None            # called with a new blob, or None when it is no longer one
        self.known = None                # checksum of the last item sent or received
        self.holding = False             # the clipboard holds an image or file right now
        self.local_at = 0.0              # when something was last copied on this computer
        self.lock = threading.Lock()
        if clip is not None:
            clip.rich = self
        self.dir = os.path.join(config_dir(), "clipboard")
        self.last = self._seq()
        self._tidy(0, 86400)

    def _tidy(self, keep, older_than=0):
        """Remove received files, except the newest `keep` and anything newer than `older_than` seconds."""
        try:
            items = [os.path.join(self.dir, f) for f in os.listdir(self.dir)]
            items.sort(key=os.path.getmtime)
            for p in items[:max(0, len(items) - keep)]:
                if time.time() - os.path.getmtime(p) < older_than:
                    continue
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    os.remove(p)
        except OSError:
            pass

    def _seq(self):
        try:
            return self.b.seq() if self.b else None
        except Exception:
            return None

    def _read_blob(self):
        """A blob, or None. Sets self.holding."""
        item = self.b.read(self.max)
        if not item:
            self.holding = False
            return None
        kind, val = item
        self.holding = True
        if kind == "file":
            if not os.path.isfile(val):
                self.holding = False                  # a folder
                return None
            size = os.path.getsize(val)
            if not 0 < size <= self.max:
                print("clipboard: %s is %.0f MB, over the %d MB limit - not sent"
                      % (os.path.basename(val), size / 1e6, self.max // 1_000_000))
                return None
            with open(val, "rb") as f:
                return make_blob("file", os.path.basename(val), f.read())
        if not 0 < len(val) <= self.max:
            print("clipboard: image is over the %d MB limit - not sent" % (self.max // 1_000_000))
            return None
        return make_blob("image", "image.png", val)

    def poll(self):
        """(changed, blob). blob is None when there is nothing new to send."""
        if not self.b:
            return False, None
        with self.lock:
            s = self._seq()
            if s is None or s == self.last:
                return False, None
            prev, self.last = self.last, s
            try:
                blob = self._read_blob()
            except ClipboardBusy:
                self.last = prev                          # look again on the next pass
                return False, None
            except Exception as e:
                self.holding = False
                print("clipboard: could not read image or file (%s)" % e)
                return True, None
            if blob is None:
                self.known = None
                return True, None
            if blob["sha"] == self.known:                 # our own item read back: not a new copy
                return False, None
            self.known = blob["sha"]
            self.local_at = time.monotonic()
            return True, blob

    def took_text(self):
        """Text from another computer was just put on this clipboard: not a local copy."""
        with self.lock:
            self.last, self.known, self.holding = self._seq(), None, False

    def newer_here(self, since):
        """True when something was copied on this computer after `since`, so an item
        that was already on its way must not replace it."""
        changed, blob = self.poll()
        if changed and (blob is not None or (self.clip is not None and self.clip.unsent())):
            if self.on_change:
                self.on_change(blob)
            return True
        if self.clip is not None and self.clip.unsent():
            return True
        return since is not None and self.local_at > since

    def scan(self):
        """Look at the clipboard now and report any new image or file.
        True when the clipboard holds an image or file (so it is not text)."""
        changed, blob = self.poll()
        if changed and self.on_change:
            self.on_change(blob)
        if self.holding and self.clip is not None:
            self.clip.resync()
        return self.holding

    def apply(self, blob):
        """Put a received image or file on this computer's clipboard."""
        if not self.b:
            return False
        ok = False
        with self.lock:
            try:
                if blob["kind"] == "image":
                    self.b.write_image(blob["data"])
                else:
                    self._tidy(3)
                    folder = os.path.join(self.dir, secrets.token_hex(4))   # a fresh path every time:
                    os.makedirs(folder)                   # nothing can hold it open or have it cached
                    path = os.path.join(folder, safe_name(blob["name"]))
                    with open(path, "wb") as f:
                        f.write(blob["data"])
                    png = None
                    if os.path.splitext(path)[1].lower() in IMAGE_EXT and hasattr(self.b, "as_png"):
                        try:
                            png = self.b.as_png(blob["data"])
                        except Exception:
                            png = None
                    if png:                               # a picture file: paste works in apps too
                        self.b.write_file(path, png)
                    else:
                        self.b.write_file(path)
                changed = self._seq() != self.last
                self.known, self.holding, ok = blob["sha"], True, True
                print("clipboard: received %s (%.1f MB) - %s"
                      % (blob_label(blob), len(blob["data"]) / 1e6,
                         "ready to paste" if changed else "but this computer's clipboard did not change"))
            except Exception as e:
                print("clipboard: could not place %s (%s)" % (blob_label(blob), e))
            finally:
                self.last = self._seq()
        if ok and self.clip is not None:
            self.clip.resync()
        return ok


class RichHost:
    """Host side. Keeps the newest image or file from any computer and hands it
    to whichever computer the mouse is on."""

    def __init__(self, rich, host_key, get_active):
        self.rich, self.hk, self.get_active = rich, host_key, get_active
        self.lock = threading.Lock()
        self.blob, self.have = None, set()
        self.xlinks = {}                                 # client key -> transfer link
        self.q = queue.Queue()
        rich.on_change = self.local_copy
        threading.Thread(target=self._worker, daemon=True).start()

    def local_copy(self, blob):
        """The host's own clipboard changed (blob is None when it is no longer an image or file)."""
        with self.lock:
            if blob is None and self.hk not in self.have:
                return                                   # an item from a client is still waiting
            self.blob, self.have = blob, {self.hk}
        if blob is not None:
            print("clipboard: copied %s here" % blob_label(blob))
            active = self.get_active()
            if active is not None:                       # copied, and the mouse is already elsewhere
                self.q.put(active)

    def forget(self):
        """Newer text was copied somewhere: the held image or file is out of date."""
        with self.lock:
            self.blob, self.have = None, set()

    def switched(self, target):
        """Called from the input hook: must not block."""
        self.q.put(target)

    def serve(self, key, name, link, msgs):
        """Runs for the life of one client's transfer connection."""
        self.xlinks[key] = link
        if self.get_active() == key:
            self.q.put(key)                              # the link is back: hand over anything waiting
        rx = BlobRx(self.rich.max)
        for m in msgs:
            try:
                blob = rx.feed(m)
            except (ValueError, TypeError) as e:
                print("clipboard: transfer from %s refused (%s)" % (name, e))
                continue
            if blob:
                with self.lock:
                    self.blob, self.have = blob, {key}
                print("clipboard: got %s from %s" % (blob_label(blob), name))
                active = self.get_active()
                if active != key:                        # the mouse already left that computer
                    self.q.put(active)
        if self.xlinks.get(key) is link:
            del self.xlinks[key]

    def _worker(self):
        while True:
            target = self.q.get()
            try:
                self._deliver(target)
            except Exception as e:
                print("clipboard: %s" % e)

    def _deliver(self, target):
        if target is not None:
            self.rich.scan()                             # catch a copy made a moment before crossing
        key = target or self.hk
        with self.lock:
            blob = self.blob
            if blob is None or key in self.have:
                return
            self.have.add(key)
        if target is None:
            if self.rich.newer_here(blob.get("t0")):
                with self.lock:
                    if self.blob is blob:
                        self.blob, self.have = None, set()
                print("clipboard: kept the newer copy made here")
                return
            self.rich.apply(blob)
            return
        xl = self.xlinks.get(target)
        if xl is None or not xl.alive:
            with self.lock:
                self.have.discard(key)
            return
        send_blob(xl, blob)
        print("clipboard: sent %s to %s" % (blob_label(blob), target))


class RichPeer:
    """Client side of the transfer connection. Keeps it up for as long as the
    main connection lives, and re-opens it if it drops."""

    def __init__(self, rich, connect):
        self.rich, self.connect = rich, connect
        self.link, self.closed, self.waiting = None, False, None
        rich.on_change = self.copied
        threading.Thread(target=self._run, daemon=True).start()

    def copied(self, blob):
        if blob is None:
            return
        link = self.link
        if link is not None and link.alive:
            print("clipboard: copied %s here - sending" % blob_label(blob))
            send_blob(link, blob)
        else:
            self.waiting = blob                          # goes out as soon as the link is back

    def _run(self):
        told = False
        while not self.closed:
            try:
                link = self.connect()
            except Exception as e:
                if not told:
                    told = True
                    print("image and file paste is off for now (%s)" % e)
                time.sleep(3)
                continue
            told, self.link = False, link
            if self.closed:
                break
            blob, self.waiting = self.waiting, None
            if blob is not None:
                self.copied(blob)
            rx = BlobRx(self.rich.max)
            for m in link.messages():
                try:
                    blob = rx.feed(m)
                except (ValueError, TypeError) as e:
                    print("clipboard: transfer refused (%s)" % e)
                    continue
                if blob:
                    try:
                        if self.rich.newer_here(blob["t0"]):
                            print("clipboard: kept the newer copy made here")
                        else:
                            self.rich.apply(blob)
                    except Exception as e:
                        print("clipboard: %s" % e)
            if not self.closed:
                time.sleep(2)
        if self.link is not None:
            self.link.close()

    def close(self):
        self.closed = True
        if self.rich.on_change == self.copied:
            self.rich.on_change = None
        if self.link is not None:
            self.link.close()


# ==========================================================================
# discovery, pairing check, single instance
# ==========================================================================
DISCOVER_MSG = b"N8MOUSE?"


def discovery_responder(name, port):
    """Host: answer LAN broadcasts so clients can find it without an IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        print("discovery off (%s)" % e)
        return
    reply = json.dumps({"t": "n8mouse", "name": name, "port": port, "version": VERSION}).encode()
    while True:
        try:
            data, addr = s.recvfrom(512)
            if data.strip() == DISCOVER_MSG:
                s.sendto(reply, addr)
        except OSError:
            time.sleep(0.2)


def discover(port, wait=1.5, target="255.255.255.255"):
    """Client: broadcast for hosts. Returns [(ip, name, port)]."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.3)
    found, sent, end = {}, 0, time.monotonic() + wait
    while time.monotonic() < end:
        if sent < 3:
            try:
                s.sendto(DISCOVER_MSG, (target, port))
            except OSError:
                pass
            sent += 1
        try:
            data, addr = s.recvfrom(512)
            info = json.loads(data)
            if info.get("t") == "n8mouse":
                found[addr[0]] = (addr[0], str(info.get("name", "?")), int(info.get("port", port)))
        except (OSError, ValueError):
            pass
    s.close()
    return list(found.values())


def connect_tls(ip, port, code, timeout=5):
    """Encrypted, code-authenticated connection to a host. Raises
    PermissionError if the host does not hold the same pairing code."""
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        raw.settimeout(timeout)
        return tls_context(False, code).wrap_socket(raw)
    except ssl.SSLError:
        raw.close()
        raise PermissionError("pairing code rejected")
    except OSError:
        raw.close()
        raise


def probe_host(ip, port, code, name):
    """Check a pairing code against a host. Returns the host's name,
    "" if the host refused the code, or None if it could not be reached."""
    try:
        sock = connect_tls(ip, port, code, timeout=4)
    except PermissionError:
        return ""
    except OSError:
        return None
    try:
        hello = {"t": "hello", "probe": True, "name": name, "os": sys.platform, "version": VERSION}
        sock.sendall((json.dumps(hello) + "\n").encode())
        buf = b""
        while b"\n" not in buf and len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                return ""
            buf += chunk
        msg = json.loads(buf.split(b"\n", 1)[0])
        return clean_name(msg.get("host") or "?") if msg.get("t") == "hello" else ""
    except (OSError, ValueError, AttributeError):
        return ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def control_server(port):
    """One copy per machine: holds localhost port+1. Sending 'quit' stops it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port + 1))
    except OSError:
        sys.exit("n8Mouse+ is already running on this machine (use: n8mouse stop)")
    s.listen(2)

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                continue
            try:
                c.settimeout(2)
                if c.recv(16).strip() == b"quit":
                    print("stopped")
                    os._exit(0)
            except OSError:
                pass
            finally:
                c.close()
    threading.Thread(target=loop, daemon=True).start()


def is_running(port):
    try:
        socket.create_connection(("127.0.0.1", port + 1), timeout=1).close()
        return True
    except OSError:
        return False


def stop_running(port):
    try:
        with socket.create_connection(("127.0.0.1", port + 1), timeout=2) as c:
            c.sendall(b"quit\n")
    except OSError:
        return False
    for _ in range(20):
        time.sleep(0.25)
        if not is_running(port):
            break
    return True


# ==========================================================================
# routing (OS independent)
# ==========================================================================
class Hub:
    """Connected clients, the screen layout, and which screen is active.
    Methods that move the host cursor return (x, y) for the caller to apply
    after the lock is released."""

    def __init__(self, host_name, layout, place_host, park_host):
        self.host = host_name
        self.hk = host_name.lower()
        self.lock = threading.RLock()
        self.clients = {}            # key -> {"name", "link", "os"}
        self.order = []              # connect order, for the auto layout
        self.active = None           # None = host, else client key
        self.place = place_host      # (edge, pos) -> (x, y) on the host screen
        self.park = park_host        # () -> (x, y) where the host cursor waits
        self.on_switch = None        # called with the new active key (None = host)
        self.static = {}
        for a, sides in (layout or {}).items():
            for edge, b in (sides or {}).items():
                if edge in OPP and b:
                    a_k, b_k = a.lower(), b.lower()
                    self.static.setdefault(a_k, {})[edge] = b_k
                    self.static.setdefault(b_k, {}).setdefault(OPP[edge], a_k)

    def _row(self):
        return [self.hk] + [k for k in self.order if k in self.clients]

    def screens(self):
        if self.static:
            return [self.hk] + [k for k in self.static if k != self.hk]
        return self._row()

    def neighbor(self, k, edge):
        if self.static:
            return self.static.get(k, {}).get(edge)
        row = self._row()
        if k not in row:
            return None
        i = row.index(k)
        if edge == "right" and i + 1 < len(row):
            return row[i + 1]
        if edge == "left" and i > 0:
            return row[i - 1]
        return None

    def available(self, k):
        return k == self.hk or k in self.clients

    def switch_to(self, target, edge, pos):
        with self.lock:
            prev = self.active
            tgt = None if target == self.hk else target
            if tgt == prev or (tgt is not None and tgt not in self.clients):
                return None
            if prev is not None and prev in self.clients:
                self.clients[prev]["link"].send(t="exit")
            self.active = tgt
            if self.on_switch:
                self.on_switch(tgt)
            if tgt is None:
                print("<- %s" % self.host)
                return self.place(edge, pos)
            self.clients[tgt]["link"].send(t="enter", edge=edge, pos=pos)
            print("-> %s" % self.clients[tgt]["name"])
            return self.park() if prev is None else None

    def host_edge(self, edge, pos):
        """Pointer hit a host screen edge. Returns (switched, cursor)."""
        with self.lock:
            nb = self.neighbor(self.hk, edge)
            if nb is None or nb == self.hk or not self.available(nb):
                return False, None
            return True, self.switch_to(nb, OPP[edge], pos)

    def client_left(self, k, edge, pos):
        with self.lock:
            if self.active != k or edge not in OPP:
                return None
            nb = self.neighbor(k, edge)
            if nb is None or not self.available(nb):
                return None
            return self.switch_to(nb, OPP[edge], pos)

    def jump(self, n):
        with self.lock:
            s = self.screens()
            if 0 <= n < len(s) and self.available(s[n]):
                return self.switch_to(s[n], None, 0.5)
            return None

    def add(self, name, link, os_name):
        k = name.lower()
        with self.lock:
            old = self.clients.get(k)
            if old:
                old["link"].close()
            self.clients[k] = {"name": name, "link": link, "os": os_name}
            if k not in self.order:
                self.order.append(k)
        if self.static and k not in self.static:
            print("note: '%s' is not in the layout in n8mouse.json" % name)
        return k

    def remove(self, k, link):
        with self.lock:
            c = self.clients.get(k)
            if not c or c["link"] is not link:
                return None
            del self.clients[k]
            if self.active == k:
                self.active = None
                if self.on_switch:
                    self.on_switch(None)
                print("<- %s (client dropped)" % self.host)
                return self.place(None, 0.5)
            return None

    def active_link(self):
        c = self.clients.get(self.active) if self.active else None
        return c["link"] if c else None

    def broadcast(self, exclude=None, **msg):
        with self.lock:
            links = [c["link"] for k, c in self.clients.items() if k != exclude]
        for link in links:
            link.send(**msg)


# ==========================================================================
# HOST (Windows)
# ==========================================================================
def vk_names():
    t = {}
    for c in range(0x41, 0x5B):
        t[c] = chr(c).lower()
    for c in range(0x30, 0x3A):
        t[c] = chr(c)
    for i in range(10):
        t[0x60 + i] = str(i)
    for i in range(12):
        t[0x70 + i] = "f%d" % (i + 1)
    t.update({
        0x6A: "*", 0x6B: "+", 0x6D: "-", 0x6E: ".", 0x6F: "/",
        0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
        0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
        0x08: "backspace", 0x09: "tab", 0x0D: "enter",
        0x10: "shift", 0xA0: "shift", 0xA1: "shift_r",
        0x11: "ctrl", 0xA2: "ctrl", 0xA3: "ctrl_r",
        0x12: "alt", 0xA4: "alt", 0xA5: "alt_r",
        0x5B: "super", 0x5C: "super_r",
        0x14: "caps_lock", 0x1B: "esc", 0x20: "space",
        0x21: "page_up", 0x22: "page_down", 0x23: "end", 0x24: "home",
        0x25: "left", 0x26: "up", 0x27: "right", 0x28: "down",
        0x2D: "insert", 0x2E: "delete", 0x5D: "menu",
        0x2C: "print_screen", 0x13: "pause", 0x90: "num_lock",
    })
    return t


def run_host(cfg):
    if sys.platform != "win32":
        sys.exit("the host must be Windows in this version (Mac host is planned)")
    require_tls()
    if not code_ok(cfg.get("secret")):
        sys.exit("no valid pairing code - run: n8mouse setup host")
    tls = tls_context(True, cfg["secret"])
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    from pynput import keyboard, mouse

    port = int(cfg["port"])
    control_server(port)
    user32 = ctypes.windll.user32
    gsm = user32.GetSystemMetrics
    vx, vy, vw, vh = gsm(76), gsm(77), gsm(78), gsm(79)      # whole desktop
    cx, cy = gsm(0) // 2, gsm(1) // 2                         # primary centre

    def place(edge, pos):
        pos = min(max(float(pos), 0.0), 1.0)
        if edge == "left":
            return vx + 3, int(vy + pos * vh)
        if edge == "right":
            return vx + vw - 4, int(vy + pos * vh)
        if edge == "top":
            return int(vx + pos * vw), vy + 3
        if edge == "bottom":
            return int(vx + pos * vw), vy + vh - 4
        return cx, cy

    def set_cursor(xy):
        if xy:
            user32.SetCursorPos(int(xy[0]), int(xy[1]))

    name = machine_name()
    hub = Hub(name, cfg.get("layout"), place, lambda: (cx, cy))
    clip = Clip()
    names = vk_names()
    st = {"buttons": 0, "local_keys": set(), "ctrl": set(), "alt": set()}

    BTN = {0x201: ("left", True), 0x202: ("left", False),
           0x204: ("right", True), 0x205: ("right", False),
           0x207: ("middle", True), 0x208: ("middle", False)}

    def hit_edge(x, y):
        if x <= vx:
            return "left", (y - vy) / max(vh, 1)
        if x >= vx + vw - 1:
            return "right", (y - vy) / max(vh, 1)
        if y <= vy:
            return "top", (x - vx) / max(vw, 1)
        if y >= vy + vh - 1:
            return "bottom", (x - vx) / max(vw, 1)
        return None, 0.0

    def mouse_filter(msg, data):
        if data.flags & 0x01:                          # injected
            return True
        if hub.active is None:
            if msg in BTN:
                st["buttons"] = max(st["buttons"] + (1 if BTN[msg][1] else -1), 0)
            elif msg == 0x200 and not st["buttons"] and hub.clients:
                edge, pos = hit_edge(data.pt.x, data.pt.y)
                if edge:
                    switched, cur = hub.host_edge(edge, pos)
                    if switched:
                        set_cursor(cur)
                        ml.suppress_event()
            return True
        link = hub.active_link()
        if link is None:
            return True
        if msg == 0x200:
            dx, dy = data.pt.x - cx, data.pt.y - cy
            if (dx or dy) and abs(dx) < vw // 2 and abs(dy) < vh // 2:
                link.send(t="m", dx=dx, dy=dy)
        elif msg in BTN:
            b, down = BTN[msg]
            link.send(t="b", b=b, down=down)
        elif msg in (0x20A, 0x20E):
            notches = ctypes.c_short((data.mouseData >> 16) & 0xFFFF).value / 120.0
            if msg == 0x20A:
                link.send(t="w", dx=0, dy=notches)
            else:
                link.send(t="w", dx=notches, dy=0)
        ml.suppress_event()

    def key_filter(msg, data):
        if data.flags & 0x10:                          # injected
            return True
        down = msg in (0x100, 0x104)
        vk = data.vkCode
        for group, vks in (("ctrl", (0x11, 0xA2, 0xA3)), ("alt", (0x12, 0xA4, 0xA5))):
            if vk in vks:
                (st[group].add if down else st[group].discard)(vk)
        if down and st["ctrl"] and st["alt"] and 0x31 <= vk <= 0x39:
            set_cursor(hub.jump(vk - 0x31))            # Ctrl+Alt+N: jump to screen N
            kb.suppress_event()
        if hub.active is None:
            if down:
                st["local_keys"].add(vk)
            else:
                st["local_keys"].discard(vk)
            return True
        if vk == 0x91:                                 # ScrollLock: back to host
            if down:
                set_cursor(hub.switch_to(hub.hk, None, 0.5))
            kb.suppress_event()
        if vk in st["local_keys"]:                     # held before leaving: finish locally
            if not down:
                st["local_keys"].discard(vk)
            return True
        link = hub.active_link()
        key = names.get(vk)
        if link and key:
            link.send(t="k", key=key, down=down)
        kb.suppress_event()

    ml = mouse.Listener(win32_event_filter=mouse_filter)
    kb = keyboard.Listener(win32_event_filter=key_filter)
    ml.start()
    kb.start()

    def on_host_clip(text):
        hub.broadcast(t="clip", text=text)

    # images and files: the host keeps the newest one and hands it to whichever
    # computer the mouse moves to next
    rich = RichClip(cfg, clip=clip)
    rhost = RichHost(rich, hub.hk, lambda: hub.active)
    hub.on_switch = rhost.switched
    threading.Thread(target=clip.watch, args=(lambda: True, on_host_clip, rich), daemon=True).start()

    gate = threading.BoundedSemaphore(MAX_HANDSHAKES)
    failures = {}                                    # ip -> [timestamps of bad attempts]
    fail_lock = threading.Lock()

    def blocked(ip):
        with fail_lock:
            recent = [t for t in failures.get(ip, []) if time.monotonic() - t < FAIL_WINDOW]
            failures[ip] = recent
            return len(recent) >= FAIL_LIMIT

    def failed(ip):
        with fail_lock:
            failures.setdefault(ip, []).append(time.monotonic())

    def handshake(raw, addr):
        """TLS handshake: proves the peer holds the pairing code. Nothing is
        read from a peer before this succeeds."""
        try:
            raw.settimeout(DEAD_AFTER)
            return tls.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            failed(addr[0])
            print("rejected %s (wrong pairing code or not n8Mouse+)" % addr[0])
            try:
                raw.close()
            except OSError:
                pass
            return None
        finally:
            gate.release()

    def serve(raw, addr):
        sock = handshake(raw, addr)
        if sock is None:
            return
        link = Link(sock)
        msgs = link.messages()
        hello = next(msgs, None)
        if not hello or hello.get("t") != "hello" or not hello.get("name"):
            link.close()
            return
        cname = clean_name(hello["name"])
        if hello.get("xfer"):                          # second connection: images and files only
            rhost.serve(cname.lower(), cname, link, msgs)
            return
        if hello.get("probe"):                         # pairing check from setup
            link.send(t="hello", host=name, os="win", version=VERSION)
            print("pairing check OK from %s (%s)" % (cname, addr[0]))
            time.sleep(0.5)
            link.close()
            return
        cos = clean_name(hello.get("os", "?"))
        k = hub.add(cname, link, cos)
        link.send(t="hello", host=name, os="win", version=VERSION)
        print("+ %s (%s) from %s   screens: %s" % (cname, cos, addr[0], " | ".join(hub.screens())))
        for m in msgs:
            try:
                t = m.get("t")
                if t == "leave":
                    set_cursor(hub.client_left(k, str(m.get("edge")), float(m.get("pos", 0.5))))
                elif t == "clip":
                    text = m.get("text", "")
                    if isinstance(text, str) and text and len(text) <= CLIP_MAX:
                        clip.set(text)
                        rhost.forget()
                        hub.broadcast(exclude=k, t="clip", text=text)
            except (TypeError, ValueError):
                continue                               # malformed message: ignore
        set_cursor(hub.remove(k, link))
        print("- %s" % cname)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):         # Windows: no port hijacking
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    srv.settimeout(1.0)
    threading.Thread(target=discovery_responder, args=(name, port), daemon=True).start()
    print("n8Mouse+ %s host '%s' on port %s (encrypted)" % (VERSION, name, port))
    print("layout: %s" % ("from n8mouse.json" if hub.static else "auto, clients to the right in connect order"))
    print("ScrollLock = back to host   Ctrl+Alt+1..9 = jump to screen N")
    while True:
        try:
            raw, addr = srv.accept()
        except socket.timeout:
            continue
        if blocked(addr[0]) or not gate.acquire(blocking=False):
            raw.close()                                # too many bad codes / connections
            continue
        threading.Thread(target=serve, args=(raw, addr), daemon=True).start()


# ==========================================================================
# CLIENT (macOS or Windows)
# ==========================================================================
def screen_bounds():
    if sys.platform == "darwin":
        import Quartz
        _, ids, n = Quartz.CGGetActiveDisplayList(16, None, None)
        rects = [Quartz.CGDisplayBounds(i) for i in ids[:n]]
        x0 = min(r.origin.x for r in rects)
        y0 = min(r.origin.y for r in rects)
        x1 = max(r.origin.x + r.size.width for r in rects)
        y1 = max(r.origin.y + r.size.height for r in rects)
        return x0, y0, x1 - x0, y1 - y0
    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass
        g = ctypes.windll.user32.GetSystemMetrics
        return g(76), g(77), g(78), g(79)
    return 0, 0, 1920, 1080


def key_resolver(Key, swap_ctrl_cmd):
    alias = {"super": "cmd", "super_r": "cmd_r"}
    if swap_ctrl_cmd:
        alias.update({"ctrl": "cmd", "ctrl_r": "cmd_r", "super": "ctrl", "super_r": "ctrl_r"})
    cache = {}

    def resolve(name):
        if name not in cache:
            if len(name) == 1:
                cache[name] = name
            else:
                cache[name] = getattr(Key, alias.get(name, name), None)   # missing keys skipped
        return cache[name]
    return resolve


def mac_app_name():
    """Name macOS shows for this program in its permission lists."""
    return "n8mouse" if getattr(sys, "frozen", False) else "Python"


def mac_accessibility_ok(prompt=False):
    try:
        import HIServices
        if prompt:
            opts = {HIServices.kAXTrustedCheckOptionPrompt: True}
            return bool(HIServices.AXIsProcessTrustedWithOptions(opts))
        return bool(HIServices.AXIsProcessTrusted())
    except Exception:
        return True                                   # cannot check: assume allowed


def run_client(host, cfg, name=None):
    from pynput.keyboard import Controller as KC, Key
    from pynput.mouse import Button, Controller as MC

    require_tls()
    if not code_ok(cfg.get("secret")):
        sys.exit("no valid pairing code - run: n8mouse setup client <CODE>")
    mac = sys.platform == "darwin"
    port = int(cfg["port"])
    control_server(port)
    if mac:
        import Quartz
        if not mac_accessibility_ok(prompt=True):
            print("waiting for permission: System Settings > Privacy & Security > Accessibility > %s" % mac_app_name())
            while not mac_accessibility_ok():
                time.sleep(2)
            print("Accessibility permission granted")
    name = name or machine_name()
    m, k = MC(), KC()
    left, top, width, height = screen_bounds()
    right, bottom = left + width - 1, top + height - 1
    buttons = {"left": Button.left, "right": Button.right, "middle": Button.middle}
    speed = float(cfg.get("speed", 1.0))
    spx = float(cfg.get("scroll_pixels", 40))
    clip = Clip()
    rich = RichClip(cfg, clip=clip)

    def scroll(dx, dy):
        if mac:
            ev = Quartz.CGEventCreateScrollWheelEvent(
                None, Quartz.kCGScrollEventUnitPixel, 2, int(round(dy * spx)), int(round(dx * spx)))
            Quartz.CGEventPost(Quartz.kCGHIDEventTap, ev)
        else:
            m.scroll(dx, dy)

    def place(edge, pos):
        pos = min(max(float(pos), 0.0), 1.0)
        if edge == "left":
            return left + 1, top + pos * height
        if edge == "right":
            return right - 1, top + pos * height
        if edge == "top":
            return left + pos * width, top + 1
        if edge == "bottom":
            return left + pos * width, bottom - 1
        return left + width / 2, top + height / 2

    def find_host():
        for ip, _, cport in discover(port):
            if probe_host(ip, cport, cfg["secret"], name):
                return ip
        return None

    if not host:
        host = find_host() or ""
    print("n8Mouse+ %s client '%s' -> %s:%s" % (VERSION, name, host or "(searching)", port))
    failures = 0
    while True:
        try:
            if not host:
                raise OSError("host not found yet")
            sock = connect_tls(host, port, cfg["secret"])
        except PermissionError:
            print("host %s refused the pairing code - run: n8mouse setup client <CODE>" % host)
            time.sleep(15)
            continue
        except OSError as e:
            failures += 1
            print("cannot reach %s:%s (%s), retrying..." % (host or "host", port, e))
            if mac and failures == 1 and getattr(e, "errno", None) == 65:
                print("if the host is running, macOS may be blocking this: System Settings > "
                      "Privacy & Security > Local Network > switch %s on" % mac_app_name())
            if failures % 5 == 0:                     # host moved? look for it again
                found = find_host()
                if found and found != host:
                    host = found
                    print("host found at %s" % host)
                    if cfg.get("role") == "client":
                        cfg["host_ip"] = host
                        save_config(cfg)
            time.sleep(3)
            continue
        failures = 0
        link = Link(sock)
        link.send(t="hello", name=name, os="mac" if mac else sys.platform, version=VERSION)
        st = {"active": False, "keys": set(), "btns": set(), "last_leave": 0.0, "peer": None}
        resolve = key_resolver(Key, False)

        def release_all():
            for key in list(st["keys"]):
                try:
                    k.release(key)
                except Exception:
                    pass
            for b in list(st["btns"]):
                try:
                    m.release(b)
                except Exception:
                    pass
            st["keys"].clear()
            st["btns"].clear()

        for msg in link.messages():
            try:
                t = msg.get("t")
                if t == "hello":
                    swap = mac and msg.get("os") == "win" and bool(cfg.get("mac_ctrl_is_cmd", True))
                    resolve = key_resolver(Key, swap)
                    print("connected to host '%s'%s" % (msg.get("host"), "  (Ctrl -> Cmd)" if swap else ""))
                    if ver_tuple(msg.get("version", "0")) >= (0, 5, 0):
                        def xfer_link(host=host):      # second connection for images and files
                            xl = Link(connect_tls(host, port, cfg["secret"]))
                            xl.send(t="hello", xfer=True, name=name, version=VERSION)
                            return xl
                        if st["peer"] is None:
                            st["peer"] = RichPeer(rich, xfer_link)
                    threading.Thread(target=clip.watch, daemon=True, args=(
                        lambda: link.alive, lambda text: link.send(t="clip", text=text), rich)).start()
                elif t == "enter":
                    st["active"] = True
                    m.position = place(msg.get("edge"), msg.get("pos", 0.5))
                elif t == "exit":
                    st["active"] = False
                    release_all()
                    try:
                        rich.scan()                    # a copy made a moment before the mouse left
                    except Exception as e:
                        print("clipboard: %s" % e)
                elif t == "m" and st["active"]:
                    px, py = m.position
                    tx, ty = px + msg["dx"] * speed, py + msg["dy"] * speed
                    edge = ("left" if tx < left else "right" if tx > right else
                            "top" if ty < top else "bottom" if ty > bottom else None)
                    if edge and time.monotonic() - st["last_leave"] > 0.25:
                        st["last_leave"] = time.monotonic()
                        pos = (py - top) / max(height, 1) if edge in ("left", "right") \
                            else (px - left) / max(width, 1)
                        link.send(t="leave", edge=edge, pos=pos)
                    m.position = (max(left, min(right, tx)), max(top, min(bottom, ty)))
                elif t == "b" and st["active"]:
                    b = buttons.get(msg.get("b"))
                    if b:
                        if msg.get("down"):
                            m.press(b)
                            st["btns"].add(b)
                        else:
                            m.release(b)
                            st["btns"].discard(b)
                elif t == "w" and st["active"]:
                    scroll(msg.get("dx", 0), msg.get("dy", 0))
                elif t == "k" and st["active"]:
                    key = resolve(str(msg.get("key", "")))
                    if key is None:
                        continue
                    try:
                        if msg.get("down"):
                            k.press(key)
                            st["keys"].add(key)
                        else:
                            k.release(key)
                            st["keys"].discard(key)
                    except Exception:
                        pass
                elif t == "clip":
                    text = msg.get("text", "")
                    if isinstance(text, str) and text and len(text) <= CLIP_MAX:
                        clip.set(text)
            except (TypeError, ValueError, KeyError):
                continue                           # malformed message: ignore

        release_all()
        if st["peer"] is not None:
            st["peer"].close()
        print("disconnected, reconnecting...")
        time.sleep(2)


# ==========================================================================
# install: setup / stop / uninstall
# ==========================================================================
FW_NAME = "n8Mouse+"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def launch_command(background):
    """Command that starts this program: packaged app, or python + this file."""
    if getattr(sys, "frozen", False):
        exe = sys.executable
        if background and sys.platform == "win32":
            w = os.path.join(os.path.dirname(exe), "n8mousew.exe")
            exe = w if os.path.exists(w) else exe
        return [exe]
    py = sys.executable
    if background and sys.platform == "win32":
        w = os.path.join(os.path.dirname(py), "pythonw.exe")
        py = w if os.path.exists(w) else py
    return [py, os.path.abspath(__file__)]


def win_firewall(add, port):
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    netsh, cmd_exe = os.path.join(sysdir, "netsh.exe"), os.path.join(sysdir, "cmd.exe")
    if " " in netsh or not os.path.exists(netsh):     # unusual install: fall back to PATH
        netsh, cmd_exe = "netsh", "cmd.exe"

    def present():
        r = subprocess.run([netsh, "advfirewall", "firewall", "show", "rule", "name=" + FW_NAME],
                           capture_output=True)
        return r.returncode == 0
    if present() == add:
        return "already open" if add else "nothing to remove"
    if add:
        cmd = ('{x} advfirewall firewall add rule name="{n}" dir=in action=allow protocol=TCP '
               'localport={p} remoteip=localsubnet & {x} advfirewall firewall add rule name="{n}" '
               'dir=in action=allow protocol=UDP localport={p} remoteip=localsubnet').format(x=netsh, n=FW_NAME, p=port)
    else:
        cmd = '{x} advfirewall firewall delete rule name="{n}"'.format(x=netsh, n=FW_NAME)
    import ctypes
    if ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd_exe, "/c " + cmd, None, 0) <= 32:
        return "skipped (administrator approval declined)"
    for _ in range(30):
        time.sleep(0.5)
        if present() == add:
            return "opened for the local network" if add else "removed"
    return "not confirmed - check Windows Firewall"


def win_autostart(enable):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enable:
            winreg.SetValueEx(k, FW_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(launch_command(True)))
        else:
            try:
                winreg.DeleteValue(k, FW_NAME)
            except FileNotFoundError:
                pass


def win_start_now():
    subprocess.Popen(launch_command(True), creationflags=0x00000008 | 0x00000200,
                     close_fds=True, cwd=os.path.expanduser("~"))


def mac_agent_path():
    return os.path.expanduser("~/Library/LaunchAgents/%s.plist" % APP_ID)


def mac_autostart(enable):
    import plistlib
    path, dom = mac_agent_path(), "gui/%d" % os.getuid()
    subprocess.run(["launchctl", "bootout", dom, path], capture_output=True)
    if not enable:
        if os.path.exists(path):
            os.remove(path)
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(config_dir(), exist_ok=True)
    log = os.path.join(config_dir(), "n8mouse.log")
    with open(path, "wb") as f:
        plistlib.dump({"Label": APP_ID, "ProgramArguments": launch_command(True),
                       "RunAtLoad": True, "KeepAlive": True, "ProcessType": "Interactive",
                       "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
                       "StandardOutPath": log, "StandardErrorPath": log}, f)
    if subprocess.run(["launchctl", "bootstrap", dom, path], capture_output=True).returncode != 0:
        subprocess.run(["launchctl", "load", "-w", path], capture_output=True)


def start_background(port):
    """Install start-at-login and start now. Returns a status line."""
    if sys.platform == "win32":
        stop_running(port)
        win_autostart(True)
        win_start_now()
    elif sys.platform == "darwin":
        stop_running(port)
        mac_autostart(True)
    else:
        return "not automated on this OS - run 'n8mouse' at login"
    for _ in range(40):
        time.sleep(0.25)
        if is_running(port):
            return "on, running now"
    return "on (did not confirm it started - see %s)" % os.path.join(config_dir(), "n8mouse.log")


def setup_host(cfg):
    if sys.platform != "win32":
        sys.exit("the host must be Windows in this version (Mac host is planned)")
    port = int(cfg["port"])
    print("n8Mouse+ %s setup - host '%s'\n" % (VERSION, machine_name()))
    require_tls()
    if not code_ok(cfg.get("secret")):
        cfg["secret"] = new_code()
    cfg["role"] = "host"
    print("  [1/3] settings saved     %s" % save_config(cfg))
    print("  [2/3] firewall           approve the Windows admin prompt...")
    print("                           %s" % win_firewall(True, port))
    print("  [3/3] start at login     %s" % start_background(port))
    print("\n  Pairing code:  %s\n" % show_code(cfg["secret"]))
    print("  On each other computer run:")
    print("      n8mouse setup client %s\n" % show_code(cfg["secret"]))


def setup_client(cfg, code=None, ip=None):
    name, port = machine_name(), int(cfg["port"])
    print("n8Mouse+ %s setup - client '%s'\n" % (VERSION, name))
    require_tls()
    code = code or input("  Pairing code from the host: ").strip()
    if not code_ok(code):
        sys.exit("  that is not a pairing code - it looks like XXXX-XXXX-XXXX-XXXX")
    if ip:
        candidates = [(ip, "?", port)]
    else:
        print("  [1/3] looking for the host on the network...")
        candidates = discover(port)
        if not candidates:
            msg = ("        no host answered. Is the host running? You can also give its IP:\n"
                   "        n8mouse setup client %s <host-ip>" % show_code(code))
            if sys.platform == "darwin":
                msg += ("\n        If macOS just asked about your local network, "
                        "click Allow and run this again.")
            sys.exit(msg)
    host_ip = host_name = None
    refused = False
    for cip, _, cport in candidates:
        result = probe_host(cip, cport, code, name)
        if result:
            host_ip, host_name = cip, result
            break
        refused = refused or result == ""
    if not host_ip:
        sys.exit("  [1/3] the host refused pairing code %s - check the code shown on the host"
                 % show_code(code) if refused else
                 "  [1/3] could not reach the host at %s:%d - is it running, and is the firewall open?"
                 % (candidates[0][0], port))
    print("  [1/3] paired with host   %s (%s)" % (host_name, host_ip))
    cfg.update(role="client", host_ip=host_ip, secret=norm_code(code))
    print("  [2/3] settings saved     %s" % save_config(cfg))
    print("  [3/3] start at login     %s" % start_background(port))
    if sys.platform == "darwin":
        print("\n  macOS will ask for two permissions. Say yes to both:")
        print("  1. Accessibility: click 'Open System Settings' and switch %s on." % mac_app_name())
        print("  2. Local Network: click Allow.")
    print("\n  Done. Push the mouse off the host's screen edge to reach this computer.\n")


def stop(cfg):
    port = int(cfg["port"])
    if sys.platform == "darwin" and os.path.exists(mac_agent_path()):
        subprocess.run(["launchctl", "bootout", "gui/%d" % os.getuid(), mac_agent_path()],
                       capture_output=True)
    print("stopped" if stop_running(port) or not is_running(port) else "could not stop it")


def uninstall(cfg):
    port = int(cfg["port"])
    print("n8Mouse+ uninstall\n")
    if sys.platform == "win32":
        win_autostart(False)
        stop_running(port)
        print("  start at login           removed")
        print("  firewall                 %s" % win_firewall(False, port))
    elif sys.platform == "darwin":
        mac_autostart(False)
        stop_running(port)
        print("  start at login           removed")
    print("  settings kept            %s  (delete it to forget the pairing)\n" % config_path())


USAGE = """n8Mouse+ %s - one keyboard and mouse for all your computers

  n8mouse setup host                 run once on the PC with the keyboard and mouse
  n8mouse setup client <CODE> [ip]   run once on every other computer
  n8mouse stop                       stop until next login
  n8mouse uninstall                  remove start-at-login and firewall rules
  n8mouse                            run now in the role chosen at setup
""" % VERSION


def main():
    for stream in (sys.stdout, sys.stderr):           # packaged Mac app ignores PYTHONUNBUFFERED
        if stream is not None and hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(line_buffering=True)
    if sys.stdout is None:                           # background build: log to a file
        os.makedirs(config_dir(), exist_ok=True)
        log = os.path.join(config_dir(), "n8mouse.log")
        mode = "w" if os.path.exists(log) and os.path.getsize(log) > 1_000_000 else "a"
        sys.stdout = sys.stderr = open(log, mode, buffering=1, encoding="utf-8")
    args = sys.argv[1:]
    cmd = args[0] if args else ""
    cfg = load_config()
    if cmd == "setup" and args[1:2] == ["host"]:
        setup_host(cfg)
    elif cmd == "setup" and args[1:2] == ["client"]:
        setup_client(cfg, args[2] if len(args) > 2 else None, args[3] if len(args) > 3 else None)
    elif cmd == "stop":
        stop(cfg)
    elif cmd == "uninstall":
        uninstall(cfg)
    elif cmd == "host":
        run_host(cfg)
    elif cmd == "client" and len(args) >= 2:
        run_client(args[1], cfg, args[2] if len(args) > 2 else None)
    elif cmd in ("version", "--version"):
        print(VERSION)
    elif not cmd and cfg.get("role") == "host":
        run_host(cfg)
    elif not cmd and cfg.get("role") == "client":
        run_client(cfg.get("host_ip", ""), cfg)
    else:
        print(USAGE)
        sys.exit(1 if cmd else 0)


if __name__ == "__main__":
    main()
