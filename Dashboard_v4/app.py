#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   CodeAlpha Dashboard v4.0                                   ║
║   Web GUI + VirusTotal API + AI Anomaly Detection            ║
╚══════════════════════════════════════════════════════════════╝
"""

import os, sys, json, time, threading
import collections, requests, hashlib
import numpy as np
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
    SCAPY = True
except ImportError:
    SCAPY = False

# ════════════════════════════════════════════════════════════
#  Configuration
# ════════════════════════════════════════════════════════════
VIRUSTOTAL_API_KEY = "21253c0f3d6fd12474a9dc5a511c481155d83e74b263edab5e1ada103451e42d"  # ← Paste your key

IDS_LOG = "/root/CodeAlpha_ProjectName/Task4_IDS/eve.json"

# ════════════════════════════════════════════════════════════
#  Flask App
# ════════════════════════════════════════════════════════════
app     = Flask(__name__)
app.config['SECRET_KEY'] = 'codealpha_v4_secret'
socketio = SocketIO(app, cors_allowed_origins="*",
                    async_mode='threading')

# ════════════════════════════════════════════════════════════
#  Shared State
# ════════════════════════════════════════════════════════════
lock = threading.Lock()

packets      = collections.deque(maxlen=500)
alerts       = collections.deque(maxlen=200)
ids_alerts   = collections.deque(maxlen=200)
vt_cache     = {}    # IP → VT result cache
anomalies    = collections.deque(maxlen=100)

proto_counts = collections.defaultdict(int)
src_counts   = collections.defaultdict(int)
port_counts  = collections.defaultdict(int)
total_pkts   = [0]
total_bytes  = [0]
ids_total    = [0]
start_time   = datetime.now()

# Rate tracking for AI
rate_history  = collections.deque(maxlen=100)
rate_window   = collections.deque(maxlen=10)
_rate_tmp     = [0]

# AI Model state
ai_baseline   = {
    "mean_rate"   : 0,
    "std_rate"    : 1,
    "mean_size"   : 0,
    "std_size"    : 1,
    "trained"     : False,
    "pkt_sizes"   : collections.deque(maxlen=200),
    "anomaly_count": 0
}

# ════════════════════════════════════════════════════════════
#  AI Anomaly Detection
# ════════════════════════════════════════════════════════════
def train_baseline():
    """Train AI model on collected traffic."""
    with lock:
        sizes = list(ai_baseline["pkt_sizes"])
        rates = list(rate_history)

    if len(sizes) < 30 or len(rates) < 10:
        return False

    sizes_arr = np.array(sizes)
    rates_arr = np.array(rates)

    with lock:
        ai_baseline["mean_size"]  = float(np.mean(sizes_arr))
        ai_baseline["std_size"]   = float(np.std(sizes_arr)) or 1
        ai_baseline["mean_rate"]  = float(np.mean(rates_arr))
        ai_baseline["std_rate"]   = float(np.std(rates_arr)) or 1
        ai_baseline["trained"]    = True

    return True

def detect_anomaly(pkt_size, current_rate, src_ip):
    """Z-score based anomaly detection."""
    with lock:
        if not ai_baseline["trained"]:
            return False

        mean_s = ai_baseline["mean_size"]
        std_s  = ai_baseline["std_size"]
        mean_r = ai_baseline["mean_rate"]
        std_r  = ai_baseline["std_rate"]

    # Z-score calculation
    z_size = abs(pkt_size - mean_s) / std_s
    z_rate = abs(current_rate - mean_r) / std_r

    # Anomaly if z-score > 3 (3 standard deviations)
    if z_size > 3 or z_rate > 3:
        reason = []
        if z_size > 3:
            reason.append(
                f"Abnormal packet size: {pkt_size}B "
                f"(z={z_size:.1f})"
            )
        if z_rate > 3:
            reason.append(
                f"Abnormal traffic rate: {current_rate}/s "
                f"(z={z_rate:.1f})"
            )

        ts = datetime.now().strftime("%H:%M:%S")
        anomaly = {
            "time"    : ts,
            "src"     : src_ip,
            "reason"  : " | ".join(reason),
            "z_size"  : round(z_size, 2),
            "z_rate"  : round(z_rate, 2),
            "severity": "HIGH" if (z_size>5 or z_rate>5)
                        else "MEDIUM"
        }

        with lock:
            anomalies.appendleft(anomaly)
            ai_baseline["anomaly_count"] += 1

        socketio.emit('anomaly', anomaly)
        return True
    return False

def ai_trainer_thread():
    """Periodically retrain AI model."""
    while True:
        time.sleep(30)
        if train_baseline():
            with lock:
                trained = ai_baseline["trained"]
            if trained:
                socketio.emit('ai_status', {
                    "trained"    : True,
                    "mean_rate"  : round(ai_baseline["mean_rate"],2),
                    "mean_size"  : round(ai_baseline["mean_size"],2),
                    "anomalies"  : ai_baseline["anomaly_count"]
                })

# ════════════════════════════════════════════════════════════
#  VirusTotal API Integration
# ════════════════════════════════════════════════════════════
def check_virustotal_ip(ip):
    """Check IP reputation on VirusTotal."""
    if ip in vt_cache:
        return vt_cache[ip]

    # Skip private/local IPs
    private = (
        ip.startswith("127.") or
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.") or
        ip == "0.0.0.0"
    )
    if private:
        return None

    if VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        return None

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(url, headers=headers, timeout=5)

        if resp.status_code == 200:
            data = resp.json()
            stats = data['data']['attributes'].get(
                'last_analysis_stats', {}
            )
            result = {
                "ip"         : ip,
                "malicious"  : stats.get('malicious', 0),
                "suspicious" : stats.get('suspicious', 0),
                "harmless"   : stats.get('harmless', 0),
                "reputation" : data['data']['attributes'].get(
                    'reputation', 0
                ),
                "country"    : data['data']['attributes'].get(
                    'country', 'Unknown'
                ),
                "checked_at" : datetime.now().strftime(
                    "%H:%M:%S"
                )
            }

            vt_cache[ip] = result

            if result["malicious"] > 0:
                ts = datetime.now().strftime("%H:%M:%S")
                alert = {
                    "time"    : ts,
                    "type"    : "VIRUSTOTAL",
                    "src"     : ip,
                    "msg"     : (
                        f"MALICIOUS IP: {ip} | "
                        f"{result['malicious']} engines flagged | "
                        f"Country: {result['country']}"
                    ),
                    "severity": "CRITICAL"
                }
                with lock:
                    alerts.appendleft(alert)
                socketio.emit('alert', alert)

            socketio.emit('vt_result', result)
            return result

    except Exception as e:
        pass
    return None

def vt_checker_thread():
    """Check suspicious IPs with VirusTotal."""
    checked = set()
    while True:
        time.sleep(15)
        with lock:
            top_srcs = list(src_counts.items())

        top_srcs.sort(key=lambda x: -x[1])
        for ip, count in top_srcs[:5]:
            if ip not in checked and count > 5:
                checked.add(ip)
                threading.Thread(
                    target=check_virustotal_ip,
                    args=(ip,),
                    daemon=True
                ).start()

# ════════════════════════════════════════════════════════════
#  Packet Sniffer
# ════════════════════════════════════════════════════════════
WELL_KNOWN = {
    21:"FTP", 22:"SSH", 23:"Telnet",
    25:"SMTP", 53:"DNS", 80:"HTTP",
    443:"HTTPS", 445:"SMB", 3306:"MySQL",
    3389:"RDP", 8080:"HTTP-alt",
    4444:"Metasploit"
}

def on_packet(pkt):
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size = len(pkt)
    proto = "OTHER"
    src = dst = "?"
    info = ""
    src_ip = ""

    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip   = ip_layer.src
        dst_ip   = ip_layer.dst

        if TCP in pkt:
            tcp   = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            svc   = WELL_KNOWN.get(dport) or \
                    WELL_KNOWN.get(sport, "")
            proto = (svc if svc in
                     ("HTTP","HTTPS","FTP","SSH","SMTP")
                     else "TCP")
            src   = f"{src_ip}:{sport}"
            dst   = f"{dst_ip}:{dport}"
            info  = f"Flags={tcp.flags}"

        elif UDP in pkt:
            udp   = pkt[UDP]
            proto = "DNS" if (
                udp.dport==53 or udp.sport==53
            ) else "UDP"
            src   = f"{src_ip}:{udp.sport}"
            dst   = f"{dst_ip}:{udp.dport}"

        elif ICMP in pkt:
            proto   = "ICMP"
            src,dst = src_ip, dst_ip
            t_map   = {0:"Reply", 8:"Request"}
            info    = f"Type={t_map.get(pkt[ICMP].type,'?')}"

        else:
            src,dst = src_ip, dst_ip

    elif ARP in pkt:
        a     = pkt[ARP]
        proto = "ARP"
        src   = a.psrc
        dst   = a.pdst
        src_ip= a.psrc

    else:
        return

    entry = {
        "time"  : ts,
        "proto" : proto,
        "src"   : src,
        "dst"   : dst,
        "size"  : size,
        "info"  : info
    }

    with lock:
        packets.appendleft(entry)
        proto_counts[proto] += 1
        if src_ip:
            src_counts[src_ip] += 1
        total_pkts[0]  += 1
        total_bytes[0] += size
        _rate_tmp[0]   += 1
        ai_baseline["pkt_sizes"].append(size)

    # AI anomaly check
    with lock:
        current_rate = rate_window[-1] if rate_window else 0
    if ai_baseline["trained"] and src_ip:
        detect_anomaly(size, current_rate, src_ip)

    # Emit to browser
    socketio.emit('packet', entry)

def sniffer_thread(iface):
    kwargs = {"prn": on_packet, "store": False}
    if iface:
        kwargs["iface"] = iface
    try:
        sniff(**kwargs)
    except Exception as e:
        print(f"Sniffer error: {e}")

def rate_ticker():
    while True:
        time.sleep(1)
        with lock:
            rate = _rate_tmp[0]
            _rate_tmp[0] = 0
            rate_window.append(rate)
            rate_history.append(rate)

# ════════════════════════════════════════════════════════════
#  Suricata Log Reader
# ════════════════════════════════════════════════════════════
def suricata_thread():
    if not os.path.exists(IDS_LOG):
        return
    seen = 0
    while True:
        try:
            with open(IDS_LOG, 'r') as f:
                lines = f.readlines()
            for line in lines[seen:]:
                try:
                    ev = json.loads(line.strip())
                    if ev.get('event_type') == 'alert':
                        sev   = ev['alert'].get('severity',3)
                        sev_l = {
                            1:"CRITICAL",2:"HIGH",3:"MEDIUM"
                        }.get(sev,"LOW")
                        alert = {
                            "time"    : ev.get('timestamp',
                                        '')[:19].replace('T',' '),
                            "type"    : "SURICATA",
                            "src"     : ev.get('src_ip','?'),
                            "dst"     : ev.get('dest_ip','?'),
                            "msg"     : ev['alert']['signature'],
                            "severity": sev_l
                        }
                        with lock:
                            ids_alerts.appendleft(alert)
                            ids_total[0] += 1
                        socketio.emit('ids_alert', alert)
                except Exception:
                    pass
            seen = len(lines)
        except Exception:
            pass
        time.sleep(2)

# ════════════════════════════════════════════════════════════
#  Flask Routes
# ════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    uptime = str(datetime.now() - start_time).split('.')[0]
    with lock:
        return jsonify({
            "total_packets" : total_pkts[0],
            "total_bytes"   : total_bytes[0],
            "total_alerts"  : len(alerts)+len(ids_alerts),
            "ids_total"     : ids_total[0],
            "uptime"        : uptime,
            "proto_counts"  : dict(proto_counts),
            "top_sources"   : sorted(
                src_counts.items(),
                key=lambda x: -x[1]
            )[:10],
            "ai_trained"    : ai_baseline["trained"],
            "anomaly_count" : ai_baseline["anomaly_count"],
            "rate"          : list(rate_window)[-1]
                              if rate_window else 0,
        })

@app.route('/api/packets')
def api_packets():
    with lock:
        return jsonify(list(packets)[:50])

@app.route('/api/alerts')
def api_alerts():
    with lock:
        all_alerts = (
            list(alerts) + list(ids_alerts)
        )
        all_alerts.sort(
            key=lambda x: x.get('time',''),
            reverse=True
        )
        return jsonify(all_alerts[:50])

@app.route('/api/anomalies')
def api_anomalies():
    with lock:
        return jsonify(list(anomalies)[:30])

@app.route('/api/vt_check/<ip>')
def api_vt_check(ip):
    result = check_virustotal_ip(ip)
    return jsonify(result or {"error": "Not checked yet"})

@app.route('/api/ai_status')
def api_ai_status():
    with lock:
        return jsonify({
            "trained"      : ai_baseline["trained"],
            "mean_rate"    : round(ai_baseline["mean_rate"],2),
            "std_rate"     : round(ai_baseline["std_rate"],2),
            "mean_size"    : round(ai_baseline["mean_size"],2),
            "std_size"     : round(ai_baseline["std_size"],2),
            "anomaly_count": ai_baseline["anomaly_count"],
            "samples"      : len(ai_baseline["pkt_sizes"]),
        })

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'CodeAlpha v4.0 Connected!'})

# ════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════
def main():
    iface = None
    if len(sys.argv) > 1:
        iface = sys.argv[1]

    print("""
╔══════════════════════════════════════════════╗
║   CodeAlpha Dashboard v4.0                   ║
║   Web GUI + VirusTotal + AI Detection        ║
╚══════════════════════════════════════════════╝
""")

    if SCAPY:
        print("✅ Scapy available")
    else:
        print("❌ Scapy missing — pip3 install scapy")

    if VIRUSTOTAL_API_KEY != "YOUR_API_KEY_HERE":
        print("✅ VirusTotal API configured")
    else:
        print("⚠️  VirusTotal API key not set")

    if os.path.exists(IDS_LOG):
        print("✅ Suricata log found")
    else:
        print("⚠️  Suricata log not found")

    print(f"\n[*] Starting threads...")

    threads = [
        threading.Thread(target=rate_ticker,     daemon=True),
        threading.Thread(target=ai_trainer_thread, daemon=True),
        threading.Thread(target=suricata_thread, daemon=True),
        threading.Thread(target=vt_checker_thread, daemon=True),
    ]

    if SCAPY:
        threads.append(
            threading.Thread(
                target=sniffer_thread,
                args=(iface,),
                daemon=True
            )
        )

    for t in threads:
        t.start()

    print("\n✅ Dashboard running!")
    print("🌐 Open browser at: http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Run as root: sudo python3 app.py")
        sys.exit(1)
    main()
