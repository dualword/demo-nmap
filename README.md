**demo-nmap** - demo Network Port Scanner for Linux (c++20, gcc 14.2.0, CMake 3.16)   

Features:
 - multithreaded, low-level network port scanner
 - flag parsing using CLI11 lib (3-Clause BSD license)
 
## 🏛️ Project Directory:
```text
demo-nmap/
├── CMakeLists.txt         # CMake configuration using FetchContent
├── README.md
├── include/
│   ├── NetworkSocket.hpp  # Linux sockets wrapper
│   └── ScannerEngine.hpp  # Mutex-protected thread pool scheduler
└── src/
    └── main.cpp
```

## 🛠️ Compilation
```bash
# Clone the repository
git clone https://github.com/dualword/demo-nmap
cd demo-nmap
# Create and navigate to the compilation dir
mkdir build && cd build
# Configure and compile the application executable
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## 💻 Sample Command Usage & Flags
```bash
./demo-nmap --target <ip-or-domain> [options]
```

### Supported Flags:
* `-t, --target` (Required): Target IP address or domain hostname.
* `-p, --ports` (Default: `1-1024`): Supports ranges (e.g., `1-1000`) or single ports (e.g., `80`).
* `-j, --threads` (Default: `64`): Maximum number of concurrent worker threads (from `1` up to `512`).
* `--timeout` (Default: `750`): Connection timeout in milliseconds.

### Example Run:
```bash
./demo-nmap -t localhost -p 1-1000 -j 128 --timeout 500
```

### 📊 Example CLI Output
```text
[*] Target Host: localhost (127.0.0.1)
[*] Total Ports: 1000 | Concurrency: 128 Workers

Scanning Ports [========================================] 100%

[+] Scan Complete in 0.76 seconds.

PORT        STATE          SERVICE/BANNER
--------------------------------------------------
22/tcp      open           SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp      open           Apache/2.4.7 (Ubuntu)
631/tcp     open           CUPS/2.4 IPP/2.1
1717/tcp    open           Open (Silent)
```

## Disclaimer / Limitation of Liability
This scanner is provided **"as is"** for educational and research purposes only. It is intended to be used to audit your own networks or
systems you have authorization to test. The author assumes no liability for any misuse, damage, or illegal activity caused
by this program. Use at your own risk.

