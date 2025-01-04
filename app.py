from flask import Flask, Response, render_template, jsonify, request
from scapy.all import sniff
from scapy.config import conf
from queue import Queue
import threading
import json
from packet_analyzer import PacketAnalyzer
from alert_system import AlertSystem
from config import *
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)

packet_queue = Queue()

class NetworkStats:
    def __init__(self):
        self.ip_activity = defaultdict(int)
        self.threat_types = defaultdict(int)
        self.threat_timeline = []
        self.lock = threading.Lock()

    def update_ip_activity(self, ip):
        with self.lock:
            self.ip_activity[ip] += 1

    def update_threat_stats(self, threat):
        with self.lock:
            self.threat_types[threat['type']] += 1
            current_time = datetime.now().strftime('%H:%M:%S')
            self.threat_timeline.append({
                'time': current_time,
                'type': threat['type'],
                'severity': threat['severity']
            })
            if len(self.threat_timeline) > 100:
                self.threat_timeline.pop(0)

    def get_stats(self):
        with self.lock:
            return {
                'ip_activity': dict(self.ip_activity),
                'threat_types': dict(self.threat_types),
                'threat_timeline': self.threat_timeline
            }

network_stats = NetworkStats()

analyzer = PacketAnalyzer()

smtp_config = {
    'host': SMTP_HOST,
    'port': SMTP_PORT,
    'username': SMTP_USERNAME,
    'password': SMTP_PASSWORD,
    'from_email': SMTP_FROM_EMAIL,
    'to_email': SMTP_TO_EMAIL
}
alert_system = AlertSystem(smtp_config)

def sniff_packets():
    def process_packet(packet):
        analysis_result = analyzer.analyze_packet(packet)
        if analysis_result:
            network_stats.update_ip_activity(analysis_result["packet_info"]["src_ip"])

            if analysis_result["threats"]:
                for threat in analysis_result["threats"]:
                    network_stats.update_threat_stats(threat)
                    if threat["severity"] in ["Critical", "High"]:
                        alert_system.send_alert(threat, analysis_result["packet_info"])

            if "packet_info" in analysis_result:
                if "flags" in analysis_result["packet_info"] and analysis_result["packet_info"]["flags"] is not None:
                    analysis_result["packet_info"]["flags"] = str(analysis_result["packet_info"]["flags"])
                if "timestamp" in analysis_result["packet_info"]:
                    analysis_result["packet_info"]["timestamp"] = \
                        analysis_result["packet_info"]["timestamp"].strftime('%Y-%m-%d %H:%M:%S')

            packet_queue.put({
                "summary": packet.sprintf("%IP.src% → %IP.dst% %IP.proto%"),
                "analysis": analysis_result
            })

    sniff(iface=NETWORK_INTERFACE, prn=process_packet, store=False, L2socket=conf.L3socket)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return jsonify({
        'status': 'error',
        'message': 'Invalid login attempt'
    }), 401

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream')
def stream():
    def generate():
        while True:
            packet_data = packet_queue.get()
            if 'analysis' in packet_data and 'packet_info' in packet_data['analysis']:
                if 'timestamp' in packet_data['analysis']['packet_info']:
                    timestamp = packet_data['analysis']['packet_info']['timestamp']
                    if hasattr(timestamp, 'strftime'):  # Provjera je li datetime objekt
                        packet_data['analysis']['packet_info']['timestamp'] = \
                            timestamp.strftime('%Y-%m-%d %H:%M:%S')
            yield f"data: {json.dumps(packet_data)}\n\n"

    return Response(generate(), content_type='text/event-stream')

@app.route('/stats')
def get_stats():
    return jsonify(network_stats.get_stats())

threading.Thread(target=sniff_packets, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)