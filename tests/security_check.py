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

print("\n%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
