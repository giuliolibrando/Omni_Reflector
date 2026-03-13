# Omni Reflector
```
      ___  __  __ _  _ ___ 
     / _ \|  \/  |  \| |_ _|
    | (_) | |\/| | |\  || | 
     \___/|_|  |_|_| \_|___|
      REFLECTOR ENGINE vX.X
```

**Omni Reflector** is a high-performance network stress-testing engine written in C. It uses **DNS amplification** over raw sockets to simulate large traffic loads for infrastructure resilience testing and security research.

By sending spoofed UDP packets and using EDNS0-capable resolvers, the tool can achieve high amplification factors, turning a small uplink into a multi-gigabit flood toward the target.

---

## Features

- **EDNS0:** Requests DNS payloads up to 4096 bytes to maximize the amplification factor.
- **Live dashboard:** CLI with real-time PPS (Packets Per Second), outbound TX, and estimated impact on the target.
- **Leverage verification (`-v`):** Optional pre-scan that measures the real amplification factor of your resolvers before running the test.
- **Cross-platform:** Supports **macOS** (BSD sockets) and **Linux** (raw sockets).
- **Parallel execution:** Multi-process workers to saturate high-speed interfaces.

---

## Requirements

- C compiler (Clang on macOS, GCC on Linux)
- **pthread** support
- **No external dependencies**
- **Root** (e.g. `sudo`) to use raw sockets

---

## Build

### macOS (Clang)

```bash
clang -O3 omni_reflector.c -o omni_reflector -pthread
```

### Linux (GCC)

```bash
gcc -O3 omni_reflector.c -o omni_reflector -pthread
```

---

## Usage

```bash
sudo ./omni_reflector -s <target> -q <domain> -l <resolver_list> [options]
```

### Options

| Option | Long        | Description |
|--------|-------------|-------------|
| `-s`   | `--source`  | **Required.** Target (victim) IP — packets are spoofed from this address. |
| `-q`   | `--query`   | **Required.** Domain to query on the resolvers (e.g. `example.com`). |
| `-l`   | `--list`    | **Required.** Comma-separated list of DNS resolver IPs (e.g. `1.1.1.1,8.8.8.8`). |
| `-t`   | `--threads` | Number of worker processes (default: `2 × CPU count`). |
| `-d`   | `--delay`   | Delay in microseconds between packets (0 = maximum rate). |
| `-v`   | `--verify`  | Verify amplification factor against the first resolver before starting. |
| `-h`   | `--help`    | Show help and exit. |

### Examples

Verify leverage and run against `192.168.1.100` with domain `example.com` and two resolvers:

```bash
sudo ./omni_reflector -s 192.168.1.100 -q example.com -l 8.8.8.8,1.1.1.1 -v
```

Same with 8 workers and 100 µs delay between packets:

```bash
sudo ./omni_reflector -s 192.168.1.100 -q example.com -l 8.8.8.8,1.1.1.1 -t 8 -d 100
```

---

## How it works

1. **Raw sockets:** The program builds IP and UDP headers and sends EDNS0 DNS queries (OPT with UDP payload size 4096) to the resolvers given with `-l`.
2. **Spoofed source:** The source IP of each packet is set to the target (`-s`), so DNS responses go from the resolvers to the target, not to the machine running Omni Reflector.
3. **Workers:** Each worker is a child process with its own raw socket, sending packets in a loop to all resolvers and updating shared stats.
4. **Stats:** A dedicated thread reads shared counters every second and prints PPS, outbound bandwidth (TX), and estimated impact (TX × amplification factor when known via `-v`).

---

## Legal and ethical notice

DNS amplification and IP spoofing can be **illegal** when used without authorization. Use Omni Reflector **only** on networks and targets you own or have explicit permission to test (e.g. authorized penetration tests or bug bounty programs). The author is not responsible for misuse.

---

## License

[MIT License](LICENSE).
