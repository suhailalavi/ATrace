# Nmap Reconnaissance & XML Parsing Guide

## Overview

**Nmap (Network Mapper)** is an industry-standard open-source tool used for network discovery and vulnerability auditing. In **AlaviTrace v0.1**, Nmap serves as the primary network reconnaissance engine.

AlaviTrace does not recreate Nmap's raw network scanning capabilities in Python. Instead, it acts as an **orchestration and intelligence layer**: it invokes Nmap safely, parses machine-readable XML results into structured data models, and prepares the data for downstream vulnerability intelligence and AI-assisted analysis.

---

## Key Concepts & Nmap Flags

### 1. Service & Version Detection (`-sV`)
- **What it does**: Interrogates open TCP ports by sending probe payloads and analyzing response banners to determine the specific software product and version number running on that port.
- **Example**: Instead of assuming port 21 is generic FTP, `-sV` identifies `pyftpdlib 1.5.5`.

### 2. XML Output (`-oX`)
- **Why XML over Terminal Scraping**: Terminal output formatting changes across Nmap versions, contains ANSI color codes, and varies based on terminal width. XML provides a stable, structured schema suitable for robust automated parsing.

---

## Security Lifecycle Hierarchy

Understanding the difference between each stage of network discovery is critical for offensive security and technical interviews:

```
[ Host Discovery ] ──► [ Port Discovery ] ──► [ Service Identification ] ──► [ Version Detection ] ──► [ Vulnerability Intelligence ]
(Host is UP?)          (Is port OPEN?)        (Is it FTP/SSH/HTTP?)           (pyftpdlib 1.5.5?)               (Is 1.5.5 in CVE database?)
```

1. **Host Discovery**: Determining if a target IP address is online.
2. **Port Discovery**: Identifying open TCP/UDP ports accepting network connections.
3. **Service Identification**: Classifying the protocol standard running on a port.
4. **Version Detection**: Identifying exact software names and version release numbers.
5. **Vulnerability Identification**: Correlating software version numbers with documented vulnerability intelligence (e.g., NIST NVD / CVE records).

> [!IMPORTANT]
> **Open Port $\neq$ Vulnerability**: An open port simply means a service is accessible over the network.
> **Software Version $\neq$ Guaranteed Exploit**: A detected version matching an old release means the service *may* be vulnerable, but actual exploitability depends on OS patches, backported fixes, system architecture, and configuration settings.

---

## Safe Subprocess Execution in Python

AlaviTrace executes Nmap using Python's `subprocess.run(shell=False)`:

```python
cmd = ["nmap", "-sV", "-oX", temp_xml_path, target.normalized]
subprocess.run(cmd, shell=False)
```

### Why `shell=False` Matters
Using `shell=True` passes input strings directly to the operating system's shell interpreter (e.g., `cmd.exe` or `/bin/sh`), exposing the system to **Command Injection** if user inputs contain characters like `;`, `|`, or `&`. Setting `shell=False` forces Python to pass arguments directly to the OS kernel process launcher as a discrete array of strings, preventing arbitrary shell command execution.

---

## Technical Limitations & Future Scope

- **Current Scope**: Focuses strictly on TCP service discovery and version identification.
- **Excluded in Phase 2**: No intrusive NSE vulnerability scripts, brute-force attacks, or automated exploitation.
