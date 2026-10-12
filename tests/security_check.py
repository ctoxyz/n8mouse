"""Live security checks for n8mouse.py (transport layer). Run: python tests/security_check.py"""
import math, os, socket, ssl, sys, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import n8mouse as m

GOOD, BAD = m.new_code(), m.new_code()
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (("  - " + detail) if detail else ""))


def start_host(code, seen):
    """Minimal host using the same handshake and Link class as run_host."""
    ctx = m.tls_context(True, code)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def serve(raw):
        try:
            raw.settimeout(3)
            s = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        link = m.Link(s)
        for msg in link.messages():
            seen.append(("msg", msg))
            if msg.get("t") == "hello":
                link.send(t="hello", host="HOSTBOX", os="win", version=m.VERSION)
        seen.append(("closed", None))

    def loop():
        while True:
            try:
                raw, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(raw,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def count(seen, kind):
    return len([x for x in seen if x[0] == kind])


seen = []
port = start_host(GOOD, seen)

s = m.connect_tls("127.0.0.1", port, GOOD)
check("right code: handshake succeeds", True, "%s %s" % (s.version(), s.cipher()[0]))
check("protocol is TLS 1.3 only", s.version() == "TLSv1.3")
s.close()

try:
    m.connect_tls("127.0.0.1", port, BAD).close()
    check("wrong code refused", False)
except PermissionError:
    check("wrong code refused", True)

before = count(seen, "msg")
p = socket.create_connection(("127.0.0.1", port))
p.sendall(b'{"t":"hello","name":"evil","os":"x"}\n{"t":"clip","text":"pwned"}\n')
p.settimeout(3)
try:
    got = p.recv(4096)
except OSError:
    got = b""
p.close()
time.sleep(0.3)
check("plaintext client: host processes no messages", count(seen, "msg") == before)
check("plaintext client: host sends back no app data", b"hello" not in got and b"HOSTBOX" not in got)

for label, maxv in (("TLS client without the key refused", None), ("TLS 1.2 client refused", ssl.TLSVersion.TLSv1_2)):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if maxv:
        c.maximum_version = maxv
    try:
        c.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3)).close()
        check(label, False)
    except (ssl.SSLError, OSError):
        check(label, True)

port2 = start_host(BAD, [])
try:
    m.connect_tls("127.0.0.1", port2, GOOD).close()
    check("fake host without the code: client refuses", False)
except PermissionError:
    check("fake host without the code: client refuses", True)
check("probe_host returns '' for a host that refuses the code", m.probe_host("127.0.0.1", port2, GOOD, "me") == "")
check("probe_host returns the host name with the right code", m.probe_host("127.0.0.1", port, GOOD, "me") == "HOSTBOX")

captured = bytearray()
relay = socket.socket()
relay.bind(("127.0.0.1", 0))
relay.listen(1)


def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            captured.extend(d)
            b.sendall(d)
    except OSError:
        pass


def relay_loop():
    a, _ = relay.accept()
    b = socket.create_connection(("127.0.0.1", port))
    threading.Thread(target=pump, args=(a, b), daemon=True).start()
    pump(b, a)


threading.Thread(target=relay_loop, daemon=True).start()
MARK = "SECRET-CLIPBOARD-hunter2-MARKER"
s = m.connect_tls("127.0.0.1", relay.getsockname()[1], GOOD)
link = m.Link(s)
link.send(t="hello", name="laptop", os="mac", version=m.VERSION)
link.send(t="clip", text=MARK)
link.send(t="k", key="a", down=True)
time.sleep(1.0)
link.close()
time.sleep(0.3)
raw = bytes(captured)
check("wire capture: clipboard text not readable", MARK.encode() not in raw, "%d bytes captured" % len(raw))
check("wire capture: message names and host name not readable", b'"t"' not in raw and b"HOSTBOX" not in raw and b"laptop" not in raw)
check("wire capture: pairing code and key never on the wire",
      m.norm_code(GOOD).encode() not in raw and GOOD.encode() not in raw and m.psk_for(GOOD) not in raw)
check("host received the clipboard over the encrypted link", any(x[0] == "msg" and x[1].get("text") == MARK for x in seen))

s = m.connect_tls("127.0.0.1", port, GOOD)
s.sendall(b'not json at all\n[1,2,3]\n"str"\n{"t":"ok-after-garbage"}\n')
time.sleep(0.6)
check("garbage lines ignored, link survives", any(x[0] == "msg" and x[1].get("t") == "ok-after-garbage" for x in seen))
n = count(seen, "closed")
try:
    s.settimeout(5)
    sent = 0
    while sent <= m.MAX_LINE + 2 * 65536:
        s.sendall(b"A" * 65536)
        sent += 65536
except OSError:
    pass
time.sleep(1.0)
check("oversized message without newline: host drops the link", count(seen, "closed") > n)
try:
    s.close()
except OSError:
    pass

s = m.connect_tls("127.0.0.1", port, GOOD)
n, t0 = count(seen, "closed"), time.monotonic()
while time.monotonic() - t0 < 9 and count(seen, "closed") == n:
    time.sleep(0.2)
dt = time.monotonic() - t0
check("silent peer dropped by the heartbeat timeout", count(seen, "closed") > n and dt < 8, "%.1fs" % dt)
s.close()

codes = {m.new_code() for _ in range(20000)}
check("20,000 generated codes: all unique, all valid", len(codes) == 20000 and all(m.code_ok(c) for c in codes))
bits = m.CODE_LEN * math.log2(len(m.CODE_ALPHABET))
check("code strength above 79 bits", bits > 79, "%.1f bits" % bits)
weak = ["", None, "1234", "AAAA-AAAA-AAAA", "password", "K7QM-4XZP-9WRT-HC3", "0000-0000-0000-0000", "IIII-LLLL-OOOO-1111"]
check("empty, short and out-of-alphabet codes refused", not any(m.code_ok(w) for w in weak))
check("example code from the README is format-valid", m.code_ok("K7QM-4XZP-9WRT-HC3N"))
m._PSK_CACHE.clear()
t0 = time.perf_counter()
m.psk_for(GOOD)
kdf = time.perf_counter() - t0
check("key stretching makes each guess slow", kdf > 0.01, "%.0f ms per guess" % (kdf * 1000))
nasty = m.clean_name("../../etc/passwd; rm -rf / \n\x1b[31m")
check("hostile computer names cleaned", all(ch.isalnum() or ch in "-_." for ch in nasty), nasty)

# --- image and file transfer (v0.5) ------------------------------------------
import hashlib


got_blobs, refused = [], []
xsrv = socket.socket()
xsrv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
xsrv.bind(("127.0.0.1", 0))
xsrv.listen(4)
xctx = m.tls_context(True, GOOD)


def xserve():
    while True:
        try:
            raw, _ = xsrv.accept()
        except OSError:
            return
        def one(raw=raw):
            lk = m.Link(xctx.wrap_socket(raw, server_side=True))
            rx = m.BlobRx(3_000_000)
            for msg in lk.messages():
                try:
                    b = rx.feed(msg)
                except (ValueError, TypeError) as e:
                    refused.append(str(e))
                    continue
                if b:
                    got_blobs.append(b)
        threading.Thread(target=one, daemon=True).start()


threading.Thread(target=xserve, daemon=True).start()
xl = m.Link(m.connect_tls("127.0.0.1", xsrv.getsockname()[1], GOOD))
payload = os.urandom(1_200_000)
m.send_blob(xl, m.make_blob("file", "report.bin", payload))
t0 = time.monotonic()
while not got_blobs and time.monotonic() - t0 < 10:
    time.sleep(0.05)
check("file transfer: 1.2 MB arrives intact over the encrypted link",
      bool(got_blobs) and got_blobs[0]["data"] == payload and got_blobs[0]["name"] == "report.bin")

m.send_blob(xl, m.make_blob("file", "big.bin", b"x" * 3_000_001))
time.sleep(1.5)
check("file transfer: over the size limit is refused", len(got_blobs) == 1 and any("not allowed" in r for r in refused))

bad = m.make_blob("image", "image.png", os.urandom(5000))
bad["sha"] = hashlib.sha256(b"something else").hexdigest()
m.send_blob(xl, bad)
time.sleep(0.8)
check("file transfer: wrong checksum is refused", len(got_blobs) == 1 and any("checksum" in r for r in refused))

xl.send(t="bstart", id="z1", kind="file", name="grow.bin", size=10, sha="0" * 64)
xl.send(t="bdata", id="z1", d="QUFBQUFBQUFBQUFBQUFBQUFBQUE=")
time.sleep(0.6)
check("file transfer: more data than announced is refused", any("more data" in r for r in refused))

xl.send(t="bstart", id="z2", kind="program", name="x.exe", size=10, sha="0" * 64)
xl.send(t="bstart", id="z3", kind="file", name="x", size="10", sha="0" * 64)
time.sleep(0.6)
check("file transfer: unknown kind and non-numeric size are refused", sum("not allowed" in r for r in refused) >= 3)
xl.close()

names = {n: m.safe_name(n) for n in ("..\\..\\evil.txt", "../../etc/passwd", "C:\\Windows\\system32\\x.dll",
                                     "a\x00b\n.txt", "CON.txt", "", "...", "ok name (1).png")}
flat = all("/" not in v and "\\" not in v and v not in ("", ".", "..") and v.isprintable() for v in names.values())
check("received file names are flattened to a bare safe name", flat and names["..\\..\\evil.txt"] == "evil.txt"
      and names["CON.txt"] == "_CON.txt" and names["ok name (1).png"] == "ok name (1).png", str(sorted(names.values())))

import tempfile
tmpd = tempfile.mkdtemp()
m.config_dir = lambda: tmpd


class Board:
    """Stands in for one computer's clipboard (text, image or file) so the real
    watcher, transfer and delivery code runs anywhere."""

    def __init__(self):
        self.n, self.item, self.text, self.writes, self.busy, self.slow = 0, None, "", 0, 0, 0

    # what the person at that computer does
    def user_text(self, t):
        self.item, self.text, self.n = None, t, self.n + 1

    def user_image(self, png):
        self.item, self.text, self.n = ("image", png), "", self.n + 1

    def user_file(self, path):
        self.item, self.text, self.n = ("file", path), os.path.basename(path), self.n + 1

    def pastes(self):
        if self.item is None:
            return ("text", self.text)
        if self.item[0] == "file":
            return ("file", os.path.basename(self.item[1]), open(self.item[1], "rb").read())
        return self.item

    # what n8mouse.py calls
    def seq(self):
        return self.n

    def read(self, maxbytes):
        if self.busy:
            self.busy -= 1
            raise m.ClipboardBusy("busy")
        return self.item

    def write_image(self, png):
        time.sleep(self.slow)
        self.item, self.text, self.n, self.writes = ("image", png), "", self.n + 1, self.writes + 1

    def write_file(self, path, png=None):
        self.item, self.text, self.png = ("file", path), os.path.basename(path), png
        self.n, self.writes = self.n + 1, self.writes + 1

    def as_png(self, data):
        return data if data[:8] == m.PNG_MAGIC else None

    def paste(self):                                     # pyperclip stand-ins
        return self.text

    def copy(self, text):
        self.item, self.text, self.n = None, text, self.n + 1


def make_clip(board):
    sys.modules["pyperclip"] = board
    try:
        return m.Clip()
    finally:
        del sys.modules["pyperclip"]


board = Board()
rc = m.RichClip({"clip_max_mb": 1}, backend=board)
check("clipboard watcher: nothing new means nothing sent", rc.poll() == (False, None))
src = os.path.join(tmpd, "doc.txt")
open(src, "wb").write(b"hello file")
board.user_file(src)
ch, blob = rc.poll()
check("clipboard watcher: a copied file is picked up once", ch and blob["data"] == b"hello file" and rc.poll() == (False, None))
board.n += 1
check("clipboard watcher: the same item seen again is not a new copy", rc.poll() == (False, None) and rc.holding)
bigf = os.path.join(tmpd, "big.bin")
open(bigf, "wb").write(b"0" * 1_000_001)
board.user_file(bigf)
check("clipboard watcher: a file over clip_max_mb is not sent", rc.poll() == (True, None))
board.user_text("words")
check("clipboard watcher: text or anything else is left to the text path", rc.poll() == (True, None) and not rc.holding)
board.user_file(src)
board.busy = 1
first = rc.poll()
check("clipboard watcher: a busy clipboard is read again, not skipped",
      first == (False, None) and rc.poll()[1]["data"] == b"hello file")
ok = rc.apply(m.make_blob("file", "..\\..\\evil.txt", b"data"))
landed = board.item[1]
check("received file is saved inside the n8mouse clipboard folder only",
      ok and os.path.dirname(os.path.dirname(landed)) == os.path.join(tmpd, "clipboard")
      and os.path.basename(landed) == "evil.txt" and open(landed, "rb").read() == b"data")
check("a received item is not sent back as if it were a new copy", rc.poll() == (False, None))
board.n += 1
check("a received item read back later is still not a new copy", rc.poll() == (False, None))
rc.apply(m.make_blob("file", "evil.txt", b"data two"))
check("the same file name twice lands on a fresh path with the new contents",
      board.item[1] != landed and open(board.item[1], "rb").read() == b"data two")
for i in range(6):
    rc.apply(m.make_blob("file", "f%d.bin" % i, b"x"))
check("old received files are tidied away (newest few kept)", 1 <= len(os.listdir(os.path.join(tmpd, "clipboard"))) <= 4)
rc.apply(m.make_blob("image", "image.png", b"\x89PNG fake"))
check("received image is placed on the clipboard", board.item == ("image", b"\x89PNG fake"))
rc.apply(m.make_blob("file", "shot.png", m.PNG_MAGIC + b"rest"))
check("a received picture file is offered as a file and as an image", board.item[0] == "file" and board.png == m.PNG_MAGIC + b"rest")
rc.apply(m.make_blob("file", "notes.txt", b"plain"))
check("a received non-picture file is offered as a file only", board.item[0] == "file" and board.png is None)
check("no clipboard support (other systems): feature stays off quietly",
      m.RichClip({}, backend=None).poll() == (False, None) and m.RichClip({}, backend=None).apply(blob) is False)
check("drop-file payload has the Windows header and a wide, double-null path",
      m.pack_dropfiles("C:\\a.txt")[:20] == bytes([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0])
      and m.pack_dropfiles("C:\\a.txt")[20:] == "C:\\a.txt\0\0".encode("utf-16-le"))
check("version compare gates the transfer link", m.ver_tuple("0.5.0") >= (0, 5, 0) > m.ver_tuple("0.4.2")
      and m.ver_tuple("junk") == (0,))
check("a picture's web address beside it is not mistaken for copied text",
      m.just_a_link("https://example.com/a.png") and not m.just_a_link("see https://example.com")
      and not m.just_a_link("plain words") and not m.just_a_link(""))

nb = Board()
nclip = make_clip(nb)
nr = m.RichClip({}, backend=nb, clip=nclip)
t_old = time.monotonic()
time.sleep(0.05)
check("an arriving item is placed when nothing newer was copied here", nr.newer_here(t_old) is False)
nb.user_image(b"local picture")
check("an arriving item never replaces a picture copied here a moment ago", nr.newer_here(time.monotonic()) is True)
check("...nor one copied here after the transfer began", nr.newer_here(t_old) is True and nr.newer_here(time.monotonic()) is False)
nb.user_text("local words")
check("an arriving item never replaces text copied here a moment ago", nr.newer_here(time.monotonic()) is True)


# --- two whole computers: a host and a client, real code, real encrypted links ---
class Sim:
    """Host and client wired the way run_host and run_client wire them, minus
    the keyboard and mouse. Each has its own fake clipboard."""

    def __init__(self):
        self.hb, self.cb = Board(), Board()
        self.connects, self.xl = 0, None
        self.hd, self.cd = tempfile.mkdtemp(), tempfile.mkdtemp()
        # host
        self.hub = m.Hub("HOSTBOX", {}, lambda e, p: (0, 0), lambda: (0, 0))
        self.hclip = make_clip(self.hb)
        m.config_dir = lambda: self.hd
        self.hrich = m.RichClip({}, backend=self.hb, clip=self.hclip)
        self.rhost = m.RichHost(self.hrich, self.hub.hk, lambda: self.hub.active)
        self.hub.on_switch = self.rhost.switched
        threading.Thread(target=self.hclip.watch, daemon=True, args=(
            lambda: True, lambda text: self.hub.broadcast(t="clip", text=text), self.hrich)).start()
        ctx = m.tls_context(True, GOOD)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]

        def serve(raw):
            link = m.Link(ctx.wrap_socket(raw, server_side=True))
            msgs = link.messages()
            hello = next(msgs, None)
            if not hello:
                return
            cname = m.clean_name(hello["name"])
            if hello.get("xfer"):
                self.rhost.serve(cname.lower(), cname, link, msgs)
                return
            k = self.hub.add(cname, link, "mac")
            link.send(t="hello", host="HOSTBOX", os="win", version=m.VERSION)
            for msg in msgs:
                if msg.get("t") == "clip":
                    self.hclip.set(msg["text"])
                    self.rhost.forget()
                    self.hub.broadcast(exclude=k, t="clip", text=msg["text"])
            self.hub.remove(k, link)

        def accept():
            while True:
                try:
                    raw, _ = self.srv.accept()
                except OSError:
                    return
                threading.Thread(target=serve, args=(raw,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        # client
        self.cclip = make_clip(self.cb)
        m.config_dir = lambda: self.cd
        self.crich = m.RichClip({}, backend=self.cb, clip=self.cclip)
        m.config_dir = lambda: tmpd
        self.link = m.Link(m.connect_tls("127.0.0.1", self.port, GOOD))
        self.link.send(t="hello", name="macbook", os="mac", version=m.VERSION)

        def xfer_link():
            xl = m.Link(m.connect_tls("127.0.0.1", self.port, GOOD))
            xl.send(t="hello", xfer=True, name="macbook", version=m.VERSION)
            self.connects, self.xl = self.connects + 1, xl
            return xl

        def client():
            for msg in self.link.messages():
                t = msg.get("t")
                if t == "hello":
                    if m.ver_tuple(msg.get("version", "0")) >= (0, 5, 0):
                        self.peer = m.RichPeer(self.crich, xfer_link)
                    threading.Thread(target=self.cclip.watch, daemon=True, args=(
                        lambda: self.link.alive, lambda text: self.link.send(t="clip", text=text), self.crich)).start()
                elif t == "exit":
                    self.crich.scan()
                elif t == "clip":
                    self.cclip.set(msg["text"])
        threading.Thread(target=client, daemon=True).start()
        wait(lambda: "macbook" in self.hub.clients and "macbook" in self.rhost.xlinks)

    def to_client(self):
        self.hub.switch_to("macbook", "left", 0.5)

    def to_host(self):
        self.hub.switch_to(self.hub.hk, "right", 0.5)


def wait(cond, secs=6.0):
    t0 = time.monotonic()
    while time.monotonic() - t0 < secs:
        if cond():
            return True
        time.sleep(0.02)
    return False


def png(tag):
    return m.PNG_MAGIC + tag.encode() + os.urandom(20000)


def run_pair(label, poll, pause):
    """pause > 0: copy, wait a moment, then move the mouse. pause == 0: move at once."""
    m.CLIP_POLL = poll
    sim = Sim()
    hb, cb = sim.hb, sim.cb
    good = []
    for i in range(5):                                   # host -> client, five different pictures
        pic = png("h%d" % i)
        hb.user_image(pic)
        time.sleep(pause)
        sim.to_client()
        good.append(wait(lambda: cb.pastes() == ("image", pic)))
        sim.to_host()
    check("%s: host -> client, 5 pictures in a row, each paste is the new one" % label, all(good), str(good))
    good = []
    for i in range(5):                                   # client -> host
        pic = png("c%d" % i)
        sim.to_client()
        cb.user_image(pic)
        time.sleep(pause)
        sim.to_host()
        good.append(wait(lambda: hb.pastes() == ("image", pic)))
    check("%s: client -> host, 5 pictures in a row, each paste is the new one" % label, all(good), str(good))
    good = []
    for i in range(4):                                   # alternating directions
        a, b = png("ah%d" % i), png("ac%d" % i)
        hb.user_image(a)
        time.sleep(pause)
        sim.to_client()
        good.append(wait(lambda: cb.pastes() == ("image", a)))
        cb.user_image(b)
        time.sleep(pause)
        sim.to_host()
        good.append(wait(lambda: hb.pastes() == ("image", b)))
    check("%s: back and forth, 8 copies, each paste is the new one" % label, all(good), str(good))
    good = []
    for i in range(4):                                   # a file with the SAME name, new contents each time
        body = os.urandom(3000)
        f = os.path.join(tmpd, "Pasted Graphic.png")
        open(f, "wb").write(m.PNG_MAGIC + body)
        sim.to_client()
        cb.user_file(f)
        time.sleep(pause)
        sim.to_host()
        good.append(wait(lambda: hb.pastes() == ("file", "Pasted Graphic.png", m.PNG_MAGIC + body))
                    and hb.png == m.PNG_MAGIC + body)
        body2 = os.urandom(3000)
        f2 = os.path.join(tmpd, "report.bin")
        open(f2, "wb").write(body2)
        hb.user_file(f2)
        time.sleep(pause)
        sim.to_client()
        good.append(wait(lambda: cb.pastes() == ("file", "report.bin", body2)))
    check("%s: files both ways, same name with new contents, each paste is the new one" % label, all(good), str(good))
    return sim


sim = run_pair("copy, then move", 0.05, 0.25)
hb, cb = sim.hb, sim.cb
time.sleep(0.5)
w = (hb.writes, cb.writes)
for _ in range(6):                                       # wander about with nothing new copied
    sim.to_host()
    time.sleep(0.15)
    sim.to_client()
    time.sleep(0.15)
hb.n += 1                                                # the clipboard 'changes' but holds the same thing
cb.n += 1
time.sleep(0.6)
check("nothing is sent again or echoed back when no new copy was made", (hb.writes, cb.writes) == w,
      "%s -> %s" % (w, (hb.writes, cb.writes)))

sim.to_host()
pic = png("before-text")
hb.user_image(pic)
time.sleep(0.25)
sim.to_client()
wait(lambda: cb.pastes() == ("image", pic))
cb.user_text("typed on the client")
ok1 = wait(lambda: hb.pastes() == ("text", "typed on the client"))
sim.to_host()
time.sleep(0.5)
sim.to_client()
time.sleep(0.5)
check("text copied after a picture replaces it everywhere and the picture does not come back",
      ok1 and hb.pastes() == ("text", "typed on the client") and cb.pastes() == ("text", "typed on the client"))
sim.to_host()
hb.user_image(pic)
time.sleep(0.25)
sim.to_client()
check("the same picture copied again after that text is delivered again", wait(lambda: cb.pastes() == ("image", pic)))
sim.to_host()
hb.user_text("typed on the host")
ok1 = wait(lambda: cb.pastes() == ("text", "typed on the host"))
sim.to_client()
time.sleep(0.5)
check("host text after a picture: the client keeps the text", ok1 and cb.pastes() == ("text", "typed on the host"))
f = os.path.join(tmpd, "client-file.bin")
open(f, "wb").write(b"client file body")
cb.user_file(f)
time.sleep(0.4)
sim.to_host()
check("a copied file's name is never sent as text in its place",
      wait(lambda: hb.pastes() == ("file", "client-file.bin", b"client file body")) and not time.sleep(0.4)
      and hb.pastes()[0] == "file")

pic = png("busy")
hb.busy = 3
hb.user_image(pic)
time.sleep(0.25)
sim.to_client()
check("a clipboard that is busy at copy time still delivers the copy", wait(lambda: cb.pastes() == ("image", pic)))

n0 = sim.connects
sim.xl.close()                                           # the transfer connection drops
pic = png("after-drop")
cb.user_image(pic)
sim.to_host()
check("the transfer link re-opens by itself and the copy still arrives",
      wait(lambda: hb.pastes() == ("image", pic), 12) and sim.connects > n0)

old_dead, old_ping = m.DEAD_AFTER, m.PING_EVERY
n0 = sim.connects
cb.slow = m.DEAD_AFTER + 1.5                             # a clipboard write slower than the heartbeat limit
pic, pic2 = png("slow"), png("after-slow")
hb.user_image(pic)
time.sleep(0.25)
sim.to_client()
ok1 = wait(lambda: cb.pastes() == ("image", pic), m.DEAD_AFTER + 6)
cb.slow = 0
time.sleep(1.2)
sim.to_host()
hb.user_image(pic2)
time.sleep(0.25)
sim.to_client()
check("a slow clipboard write does not drop the link",
      ok1 and wait(lambda: cb.pastes() == ("image", pic2)) and sim.connects == n0)

run_pair("copy and move at once", 30, 0)                 # the poll never fires: only the crossing can catch it

big = os.urandom(12_000_000)
m.CLIP_POLL = 0.05
sim2 = Sim()
f = os.path.join(tmpd, "video.bin")
open(f, "wb").write(big)
sim2.hb.user_file(f)
time.sleep(0.3)
sim2.to_client()
ok1 = wait(lambda: sim2.cb.item is not None and sim2.cb.pastes() == ("file", "video.bin", big), 30)
big2 = os.urandom(12_000_000)
open(f, "wb").write(big2)
sim2.cb.user_file(f)
time.sleep(0.3)
sim2.to_host()
check("12 MB files cross both ways intact",
      ok1 and wait(lambda: sim2.hb.item is not None and sim2.hb.pastes() == ("file", "video.bin", big2), 30))

print("\n%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
