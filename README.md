# ICMP C2

A minimal command-and-control framework that tunnels traffic over ICMP echo request/reply packets, bypassing firewalls that only filter TCP/UDP. Features cross-platform beacons for Windows and Linux, AES-256-CBC encrypted payloads, and randomised beacon intervals to reduce detection fingerprinting.

## Protocol

Each ICMP payload carries a custom header:

- **MAGIC** — `0xDEADBEEF`, identifies C2 packets
- **Session ID** — random value per implant, allows multiple sessions
- **Msg Type** — `BEACON / CMD / OUTPUT / ACK`
- **Data** — AES-256-CBC encrypted (IV prepended)

## Run Server

```bash
uv venv
source .venv/bin/activate
uv pip install pycryptodome
sudo .venv/bin/python3 server.py
```

### Server Commands

| Command | Description |
|---|---|
| `sessions` | List active sessions |
| `use <hex_id>` | Select active session |
| `history` | Show output history for active session |
| `<cmd>` | Queue a command for active session |

## Compile Linux Beacon

```bash
sudo apt install libssl-dev
g++ linuxbeacon.cpp -o beacon -lssl -lcrypto
sudo ./beacon
```

## Compile Windows Beacon (cross-compile from Linux)

```bash
sudo apt install mingw-w64
x86_64-w64-mingw32-g++ windowsbeacon.cpp -o beacon.exe -lws2_32 -lbcrypt -static-libgcc -static-libstdc++ -static
```

Run `beacon.exe` as **Administrator** on the target.

## Requirements

- Linux beacon requires `root` (raw ICMP socket)
- Windows beacon requires `Administrator` (raw socket + outbound ICMP only)
- C2 server requires `root` (disables kernel ICMP echo via `sysctl`)

## Credit

Architecture and protocol design based on [Building a Minimal ICMP C2](https://medium.com/@s12deff/building-a-minimal-icmp-c2-0a06f3c10ecc) by s12. Highly recommended read for understanding the methodology.

## Disclaimer

For CTF and lab use only.
