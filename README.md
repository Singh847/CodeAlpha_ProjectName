# Network Packet Analyzer (CodeAlpha Internship - Task 1)

## 📌 Project Overview
This project is a high-performance **Network Packet Analyzer** developed as part of my Cybersecurity Internship at **CodeAlpha**. The tool is designed to provide real-time visibility into network traffic, allowing for the inspection of protocols, payloads, and potential security anomalies.

The project includes two versions:
1.  **`packet_analyzer.py`**: A lightweight, CLI-based sniffer with protocol color-coding and session summaries.
2.  **`packet_analyzer_v2.py`**: An advanced, terminal-based dashboard (using `curses`) featuring live traffic graphs, protocol deep-dives (HTTP, DNS, TLS, SMTP), and basic port-scan detection.

## 🚀 Features
- **Multi-Protocol Support**: Detailed dissection of TCP, UDP, ICMP, ARP, DNS, and IPv6.
- **Live Dashboard**: Real-time sparkline graphs showing packets-per-second and distribution charts.
- **Deep-Dive Inspection**: Extracts and displays HTTP headers, DNS queries, and TLS SNI hostnames.
- **Security Alerts**: Built-in detection for suspicious activities like SYN port scanning.
- **Dual Backend**: Utilizes `Scapy` for deep packet inspection with a raw-socket fallback for Linux environments.

## 🛠️ Technical Stack
- **Language**: Python 3.x
- **Core Library**: [Scapy](https://scapy.net/) (Packet manipulation and sniffing)
- **UI Framework**: Curses (for the v2 Dashboard)
- **Platform**: Optimized for Kali Linux / Debian-based systems.

## 📋 Prerequisites & Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/CodeAlpha_Network_Packet_Analyzer.git](https://github.com/YOUR_USERNAME/CodeAlpha_Network_Packet_Analyzer.git)
cd CodeAlpha_Network_Packet_Analyzer
