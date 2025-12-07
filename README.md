# TP 3: Intrusion Detection System (NIDS)

This project implements a simple NIDS in C using the `libpcap` library to detect suspicious HTTP 404 error patterns.

---

## 🐧 Execution on Linux (Native - No Docker)

### Prerequisites
- **GCC Compiler**
- **Libpcap Development Headers**

### Installation

1. **Install dependencies**:
   ```bash
   sudo apt-get install build-essential libpcap-dev
   ```

2. **Compile the programs**:
   ```bash
   gcc -o analysis analysis.c
   gcc -o sniffer sniffer.c -lpcap
   ```

### Testing

#### Test 1: Analysis Logic (Standalone)
Run the analysis test program to verify the string parsing and alarm logic:
```bash
./analysis
```

**Expected Output**: You should see test cases demonstrating HTTP parsing and 404 detection logic.

#### Test 2: Network Sniffer (Requires root privileges)
Run the sniffer to capture real network traffic:
```bash
sudo ./sniffer
```

*Note: If no device is found automatically, specify your network interface:*
```bash
sudo ./sniffer eth0
```
(Replace `eth0` with your actual interface: `wlan0`, `enp0s3`, etc. Use `ip a` to list interfaces)

### Generating Test Traffic

Once the sniffer is running, **in another terminal**, generate HTTP traffic:

#### Option A: Using curl (Recommended)
```bash
# Normal request
curl http://example.com

# Trigger 404 errors (run twice to trigger alarm)
curl http://example.com/fakepage1
curl http://example.com/fakepage2
```

#### Option B: Using a Web Browser
**Important**: Modern browsers use HTTPS by default, which is encrypted and cannot be analyzed by the sniffer.

**You MUST use HTTP-only URLs**:
- `http://example.com` ✅
- `http://neverssl.com` ✅
- ~~`https://google.com`~~ ❌ (encrypted, won't work)

To trigger the alarm:
1. Visit `http://example.com/nonexistent1` (you'll see `[!] 404 Error Detected`)
2. Visit `http://example.com/nonexistent2` (you'll see `ALARM: Suspicious behavior detected`)

**Expected Output**: The sniffer will display captured packets and trigger an alarm after detecting two 404 errors.

---

## 🪟 Execution on Windows (Using Docker)

### Prerequisites
- **Docker Desktop**: Ensure Docker is installed and running

### Setup and Execution

1. **Build the Docker Image**:
   Open a terminal (PowerShell or CMD) in the project folder and run:
   ```bash
   docker build -t nids-project .
   ```

2. **Run the Container**:
   ```bash
   docker run -it --name nids nids-project
   ```
   
   *Note: You'll be inside the container as `root`, so `sudo` is not needed.*

3. **Inside the Container**:
   
   The executables `analysis` and `sniffer` are already compiled in `/app`.

   **Test Analysis**:
   ```bash
   ./analysis
   ```

   **Test Sniffer**:
   
   Start the sniffer in the background:
   ```bash
   ./sniffer &
   ```
   
   *(Alternative: Open a second terminal with `docker exec -it nids /bin/bash` and run `./sniffer`)*

4. **Generate Test Traffic** (inside the container):
   ```bash
   # Normal traffic
   curl http://example.com
   
   # Trigger 404 errors (alarm)
   curl http://example.com/fakepage1
   curl http://example.com/fakepage2
   ```

**Expected Output**: You should see packet captures and the alarm message after two 404 errors.

---

## 📝 Notes for Professors

- **Linux users**: The native approach is faster and more straightforward
- **Windows users**: Docker provides a consistent Linux environment without WSL complications
- **HTTPS Limitation**: The sniffer only works with unencrypted HTTP traffic (port 80). Modern HTTPS traffic cannot be analyzed without SSL/TLS decryption
- **Network Interface**: On Linux, the program auto-detects the interface, but you can specify it manually if needed
