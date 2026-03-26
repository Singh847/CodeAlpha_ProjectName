# 🚀 Network Packet Analyzer

A real-time network traffic analyzer built with Python for packet inspection and basic threat detection.

---

## ✨ Features

* 📡 Real-time packet capture
* 🔍 Deep packet inspection (HTTP, DNS, TLS)
* 📊 Live traffic statistics
* 🚨 SYN scan / suspicious activity detection
* 🖥️ CLI + Interactive Dashboard (v2)
* 🌐 Supports TCP, UDP, ICMP, ARP, IPv4/IPv6

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[Network Interface] --> B[Packet Capture (Scapy)]
    B --> C[Packet Processing]
    C --> D[Protocol Parsing]
    C --> E[Deep Packet Inspection]
    D --> F[Detection Engine]
    E --> F
    F --> G[Alerts & Monitoring]
    G --> H[CLI Output]
    G --> I[Interactive Dashboard v2]
```

This architecture ensures modular packet processing, real-time monitoring, and scalable analysis.

---

## 📁 Project Structure

```
packet_analyzer.py
packet_analyzer_v2.py
```

---

## ⚙️ Installation

```bash
git clone https://github.com/Singh847/CodeAlpha_Network_Packet_Analyzer.git
cd CodeAlpha_Network_Packet_Analyzer
pip install scapy
```

---

## ▶️ Usage

### Run Basic Analyzer

```bash
sudo python3 packet_analyzer.py
```

### Run Advanced Dashboard

```bash
sudo python3 packet_analyzer_v2.py
```

---

## 🧪 Example

```bash
sudo python3 packet_analyzer.py -i eth0 -c 100 -f "tcp port 80"
```

* `-i` → Interface
* `-c` → Packet count
* `-f` → Filter

---

## ⚠️ Requirements

* Python 3.8+
* Linux (recommended)
* Root/Admin privileges

---

## 🔐 Security Features

* Detects SYN flood / port scanning
* Highlights suspicious traffic patterns
* Real-time monitoring alerts

---

## 🚧 Limitations

* Requires root privileges
* Linux-focused (raw sockets)
* Not optimized for high-throughput traffic

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch
3. Commit changes
4. Open a Pull Request

---

## 📜 License

MIT License

---

## 📬 Contact

Sumeer Singh Rana
Feel free to connect for collaboration or feedback.
