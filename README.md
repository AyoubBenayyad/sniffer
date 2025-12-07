# TP 3: Intrusion Detection System (NIDS)

This project implements a simple NIDS in C using the `libpcap` library to detect suspicious HTTP 404 error patterns.

## Prerequisites

### Option 1: Linux Native
- **GCC Compiler**
- **Libpcap Development Headers**
    - `sudo apt-get install build-essential libpcap-dev`

### Option 2: Docker (Recommended for Windows/Mac)
- **Docker Desktop**: Ensure Docker is installed and running.

---

## Compilation & Execution

### Option 1: Native (Linux)

See previous instructions (below).

### Option 2: Using Docker

This is the easiest way to run the project on Windows.

1.  **Build the Docker Image**:
    Open a terminal in the project folder and run:
    ```bash
    docker build -t nids-project .
    ```

2.  **Run the Container**:
    We need to run it in interactive mode. 
    *Note: To capture traffic properly, we often use `--net=host`, but on Windows/Mac this has limitations. For this TP, we will generate traffic INSIDE the container to test.*
    ```bash
    docker run -it --name nids nids-project
    ```

3.  **Inside the Container**:
    You serve as `root`, so `sudo` is not needed. The executables `analysis` and `sniffer` are already compiled in `/app`.

    - **Test Analysis**:
      ```bash
      ./analysis
      ```

    - **Test Sniffer**:
      1.  Start the sniffer in the background or in a separate terminal exec:
          ```bash
          ./sniffer &
          ```
          *(Or open a new terminal on host: `docker exec -it nids /bin/bash` then run `./sniffer`)*
      
      2.  Generate Traffic:
          ```bash
          curl http://www.google.com
          ```
          You should see the sniffer output.
      
      3.  Trigger Alarm (404s):
          ```bash
          curl http://www.google.com/nothinghere
          curl http://www.google.com/nothinghereagain
          ```
          You should see "ALARM" in the output.

---

## Native Execution (Legacy Instructions)

Open a terminal in the project directory and run the following commands:

### Part 1: Analysis Logic (No pcap required)
```bash
gcc -o analysis analysis.c
```

### Part 2 & 3: Sniffer (Requires pcap)
```bash
gcc -o sniffer sniffer.c -lpcap
```

## Execution

### 1. Testing Analysis Logic
Run the analysis test program to verify the string parsing and alarm logic:
```bash
./analysis
```

### 2. Running the Sniffer
To capture packets, you typically need **root/administrator privileges**.
```bash
sudo ./sniffer
```
*Note: If no device is found automatically, you can specify it as an argument:*
```bash
sudo ./sniffer eth0
```
(Replace `eth0` with your actual network interface, e.g., `wlan0`, `en0`, etc.)

## Usage Scenarios for Testing

Once the sniffer is running:

1.  **Normal Traffic**: Open a browser and visit a valid website (http://start.ubuntu.com or similar HTTP site).
    - *Expected*: You should see packets being captured with destination IPs.
2.  **Generate 404 Errors**: Visit a non-existent page on an HTTP site (e.g., `http://example.com/nonexistent_page`).
    - *Do this twice* to trigger the NIDS alarm.
    - *Expected*: "ALARM: Suspicious behavior detected" should appear in the terminal.
