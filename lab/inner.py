#!/usr/bin/env python3
"""Runs INSIDE the tos-lab podman container: boots a throwaway TempleOS VM, loads the
HolyC sources over the serial port, runs one entry file and prints what it sent back."""
import argparse, json, os, socket, struct, subprocess, sys, time, zlib

ap = argparse.ArgumentParser()
ap.add_argument("entry", help="HolyC file relative to the source root, e.g. tests/Hello.HC")
ap.add_argument("--src", default="/src")
ap.add_argument("--app", default="", help="optional application source tree layered over the networking library")
ap.add_argument("--iso", default="/iso/TempleOS.ISO")
ap.add_argument("--out", default="/out")
ap.add_argument("--timeout", type=float, default=60)
ap.add_argument("--net", choices=["none", "apify", "mock", "mockplain", "open"], default="none")
ap.add_argument("--shot", default="")
a = ap.parse_args()

TMP = "/tmp/tos"
os.makedirs(TMP, exist_ok=True)
QMP, SER = TMP + "/qmp.sock", TMP + "/ser.sock"

netdev = "user,id=u1,restrict=on"
if a.net == "apify":
    for port in (80, 443):
        netdev += ",guestfwd=tcp:10.0.2.100:%d-cmd:socat - TCP:api.apify.com:%d" % (port, port)
elif a.net == "mock":
    netdev += ",guestfwd=tcp:10.0.2.100:443-cmd:socat - TCP:127.0.0.1:8443"
elif a.net == "mockplain":
    netdev += ",guestfwd=tcp:10.0.2.100:80-cmd:socat - TCP:127.0.0.1:8080"
elif a.net == "open":
    netdev = "user,id=u1"  # full user-mode NAT: real DNS + internet (explicit opt-in)
accel = "kvm" if os.access("/dev/kvm", os.W_OK) else "tcg"
cmd = ["qemu-system-x86_64", "-accel", accel, "-smp", "2", "-m", "1024", "-cdrom", a.iso, "-boot", "d",
       "-display", "none", "-vga", "std", "-qmp", "unix:%s,server,nowait" % QMP,
       "-serial", "unix:%s,server,nowait" % SER, "-netdev", netdev, "-device", "pcnet,netdev=u1",
       "-object", "filter-dump,id=f1,netdev=u1,file=%s/net.pcap" % a.out]
mock = None
if a.net in ("mock", "mockplain"):
    mock = subprocess.Popen(["python3", "/lab/mock_api.py"] + (["--plain"] if a.net == "mockplain" else []),
                            stdout=subprocess.DEVNULL, stderr=open(a.out + "/mock.log", "w"))
    time.sleep(1.5)
qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def wait_sock(p):
    for _ in range(100):
        if os.path.exists(p):
            return
        if qemu.poll() is not None:
            sys.exit("qemu died: " + qemu.stderr.read().decode())
        time.sleep(0.1)
    sys.exit("socket never appeared: " + p)

wait_sock(QMP); wait_sock(SER)
q = socket.socket(socket.AF_UNIX); q.connect(QMP); qf = q.makefile("rw"); qf.readline()
def qmp(c, **kw):
    qf.write(json.dumps({"execute": c, "arguments": kw}) + "\n"); qf.flush()
    while True:
        r = json.loads(qf.readline())
        if "return" in r or "error" in r:
            return r
qmp("qmp_capabilities")
ser = socket.socket(socket.AF_UNIX); ser.connect(SER); ser.settimeout(0.2)

SH = {'"': 'apostrophe', '(': '9', ')': '0', ':': 'semicolon', '{': 'bracket_left', '}': 'bracket_right',
      '<': 'comma', '>': 'dot', '+': 'equal', '*': '8', '&': '7', '|': 'backslash', '!': '1', '#': '3',
      '$': '4', '%': '5', '_': 'minus', '?': 'slash', '~': 'grave_accent', '^': '6', '@': '2'}
BASE = {' ': 'spc', '\n': 'ret', '.': 'dot', ',': 'comma', '/': 'slash', '-': 'minus', '=': 'equal',
        '[': 'bracket_left', ']': 'bracket_right', "'": 'apostrophe', '\\': 'backslash', ';': 'semicolon',
        '`': 'grave_accent'}
def key(keys):
    qmp("send-key", keys=[{"type": "qcode", "data": k} for k in keys], **{"hold-time": 8})
def typ(t, gap=0.012):
    for c in t:
        if c in SH: key(["shift", SH[c]])
        elif c.isupper(): key(["shift", c.lower()])
        elif c in BASE: key([BASE[c]])
        else: key([c])
        time.sleep(gap)

def shot(name):
    qmp("screendump", filename=TMP + "/s.ppm")
    d = open(TMP + "/s.ppm", "rb").read(); p = d.split(b"\n", 3); w, h = map(int, p[1].split()); px = p[3]
    raw = b"".join(b"\0" + px[y * w * 3:(y + 1) * w * 3] for y in range(h))
    ch = lambda t, b: struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b))
    open(os.path.join(a.out, name), "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))

buf = b""
def pump(t=0.2):
    global buf
    ser.settimeout(t)
    try:
        d = ser.recv(65536)
        buf += d; return d
    except (socket.timeout, BlockingIOError):
        return b""
def wait_for(tok, timeout):
    end = time.time() + timeout
    while time.time() < end:
        pump(0.2)
        i = buf.find(tok)
        if i >= 0 and (tok != b"TOS-DONE" or b"\n" in buf[i:]): return True
    return False

# ---- boot, decline the installer and the tour, type the tiny stage-1 receiver
time.sleep(7)
typ("n"); time.sleep(1); typ("n"); time.sleep(1.5)
STAGE1 = ("U8 *b=CAlloc(1<<20);I64 n=0,c;while(TRUE){while(!(InU8(0x3FD)&1))Sleep(1);c=InU8(0x3F8);"
          "if(c==4)break;b[n++]=c;}ExePutS(b);\n")
typ(STAGE1)
# ---- stage 2 (sent over serial): FIFO on, file receiver writing to the RAM drive B:, then run the entry
STAGE2 = r'''
OutU8(0x3FA,0xC7);
U0 SerPutS(U8 *s){while(*s){while(!(InU8(0x3FD)&0x20))Yield;OutU8(0x3F8,*s++);}}
U8 rb(){while(!(InU8(0x3FD)&1))Yield;return InU8(0x3F8);}
U0 rxline(U8 *o){I64 i=0;while((o[i]=rb())!=10)i++;o[i]=0;}
U0 rx(){U8 nm[160],en[160];I64 n,j;U8 *d;
while(TRUE){rxline(nm);if(!StrCmp(nm,"END"))break;n=0;for(j=0;j<4;j++)n+=rb()<<(8*j);
d=MAlloc(n+1);for(j=0;j<n;j++)d[j]=rb();d[n]=0;FileWrite(nm,d,n);Free(d);}
rxline(en);SerPutS("K\n");ExeFile(en);}
U0 SerDump(){I64 sz;U8 *s=DocSave(DocPut,&sz);SerPutS("\nDUMP-BEGIN\n");SerPutS(s);SerPutS("\nDUMP-END\n");Free(s);}
SerPutS("R\n");
rx;
'''
ser.sendall(STAGE2.encode() + b"\x04")
if not wait_for(b"R\n", 15):
    shot("boot-failed.png"); print("stage2 never started; screenshot in out/boot-failed.png"); qemu.kill(); sys.exit(3)

def files():
    staged = {}
    for source in filter(None, (a.src, a.app)):
        for root, dirs, names in os.walk(source):
            if root == source:
                dirs[:] = [d for d in dirs if d in ("src", "tests")]
            for f in sorted(names):
                if f.endswith((".HC", ".HH", ".DD")):
                    p = os.path.join(root, f)
                    name = "B:/" + os.path.relpath(p, source)
                    if name in staged:
                        raise ValueError("duplicate guest source path: " + name)
                    staged[name] = open(p, "rb").read()
    yield from sorted(staged.items())
payload = b""
gl = {k[len("TOS_SECRET_"):]: v for k, v in os.environ.items() if k.startswith("TOS_SECRET_")}
text = "\n".join('U8 *%s="%s";' % kv for kv in gl.items())
payload += b"B:/Env.HC\n" + struct.pack("<I", len(text)) + text.encode()
for name, data in files():
    payload += name.encode() + b"\n" + struct.pack("<I", len(data)) + data
payload += b"END\n" + ("B:/" + a.entry + "\n").encode()
t0 = time.time()
for i in range(0, len(payload), 256):
    ser.sendall(payload[i:i + 256])
sys.stderr.write("sent %d bytes in %.1fs\n" % (len(payload), time.time() - t0))

ok = wait_for(b"TOS-DONE", a.timeout)
pump(0.5)
if not ok:
    typ("SerDump;\n"); wait_for(b"DUMP-END", 8)
shot(a.shot or "last.png")
out = buf.decode("latin-1")
sys.stdout.write(out if out.endswith("\n") else out + "\n")
qemu.kill()
if mock: mock.kill()
if not ok:
    print("TIMEOUT after %.0fs (screenshot: out/%s)" % (a.timeout, a.shot or "last.png")); sys.exit(2)
sys.exit(0 if "TOS-DONE fail=0" in out else 1)
