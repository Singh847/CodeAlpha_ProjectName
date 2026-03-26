# CodeAlpha Network Packet Analyzer

## 🛡️ Project Overview
Developed during my **Cybersecurity Internship at CodeAlpha**, this project consists of two Python-based network analysis tools designed to capture, decode, and analyze live network traffic. It provides insights into protocol distribution, IP communication, and potential security threats.

## 🚀 Key Features
- **Protocol Support**: Deep inspection of TCP, UDP, ICMP, DNS, ARP, and IPv6.
- **Dual Versions**:
  - `packet_analyzer.py`: A clean, color-coded CLI tool for quick traffic monitoring.
  - `packet_analyzer_v2.py`: An advanced interactive dashboard with live throughput graphs and protocol "deep-dive" views.
- **Security Logic**: Detects common anomalies like SYN scans and displays HTTP/DNS metadata.
- **Hardware Fallback**: Automatically switches to raw sockets if Scapy is not present.

## 🛠️ Requirements
- **OS**: Kali Linux (or any Debian-based Linux)
- **Language**: Python 3.x
- **Libraries**: Scapy

## 🚦 Installation & Usage
1. **Clone the repository**:
   ```bash
   git clone [https://github.com/Singh847/CodeAlpha_Network_Packet_Analyzer.git](https://github.com/Singh847/CodeAlpha_Network_Packet_Analyzer.git)
   cd CodeAlpha_Network_Packet_Analyzer
