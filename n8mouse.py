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
import hashlib
import json
import os
import queue
import secrets
import select
import socket
import ssl
import subprocess
import sys
import threading
import time

VERSION = "0.4.2"
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
            if time.monotonic() - self.last_rx > DEAD_AFTER:
                break                                  # heartbeat lost
            pending = self.sock.pending() if hasattr(self.sock, "pending") else 0
            if not pending:
                try:
                    ready, _, _ = select.select([self.sock], [], [], 0.5)
                except (OSError, ValueError):
                    break
                if not ready:
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

    def watch(self, alive, on_change):
        while alive():
            time.sleep(CLIP_POLL)
            with self.lock:
                cur = self._read()
                if not cur or cur == self.last or len(cur) > CLIP_MAX:
                    continue
                self.last = cur
            on_change(cur)


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

    threading.Thread(target=clip.watch, args=(lambda: True, on_host_clip), daemon=True).start()

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
        st = {"active": False, "keys": set(), "btns": set(), "last_leave": 0.0}
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
                    threading.Thread(target=clip.watch, daemon=True, args=(
                        lambda: link.alive, lambda text: link.send(t="clip", text=text))).start()
                elif t == "enter":
                    st["active"] = True
                    m.position = place(msg.get("edge"), msg.get("pos", 0.5))
                elif t == "exit":
                    st["active"] = False
                    release_all()
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
