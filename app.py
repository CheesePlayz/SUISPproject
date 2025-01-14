import time
from flask import Flask, Response, render_template, jsonify, request
from scapy.all import sniff, ifaces
from scapy.config import conf
from queue import Queue, Empty
import threading
import json

from scapy.arch.windows import get_windows_if_list
from scapy.all import get_if_list
from scapy.interfaces import get_if_list

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

    def reset(self):
        with self.lock:
            self.ip_activity.clear()
            self.threat_types.clear()
            self.threat_timeline.clear()


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

# ---------------------------
#  Globalne varijable za sniff
# ---------------------------
selected_interface = None
sniff_thread = None
stop_sniffing_event = threading.Event()


def sniff_packets(iface_to_sniff):
    """
    Sniffer funkcija koja se pokreće u posebnoj niti.
    Kad je stop_sniffing_event postavljen, prekida se sniff (stop_filter).
    """

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
                if ("flags" in analysis_result["packet_info"]
                        and analysis_result["packet_info"]["flags"] is not None):
                    analysis_result["packet_info"]["flags"] = str(
                        analysis_result["packet_info"]["flags"]
                    )
                if "timestamp" in analysis_result["packet_info"]:
                    analysis_result["packet_info"]["timestamp"] = (
                        analysis_result["packet_info"]["timestamp"]
                        .strftime('%Y-%m-%d %H:%M:%S')
                    )

            packet_queue.put({
                "summary": packet.sprintf("%IP.src% → %IP.dst% %IP.proto%"),
                "analysis": analysis_result
            })

    print(f"[INFO] Starting sniff on {iface_to_sniff}")
    sniff(
        iface=iface_to_sniff,
        prn=process_packet,
        store=False,
        stop_filter=lambda x: stop_sniffing_event.is_set(),
        L2socket=conf.L3socket
    )
    print(f"[INFO] Sniff stopped on {iface_to_sniff}")


# ---------------------------
#        FLASK ROUTES
# ---------------------------
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
                    if hasattr(timestamp, 'strftime'):
                        packet_data['analysis']['packet_info']['timestamp'] = \
                            timestamp.strftime('%Y-%m-%d %H:%M:%S')
            yield f"data: {json.dumps(packet_data)}\n\n"

            time.sleep(0.01)

    return Response(generate(), content_type='text/event-stream')


@app.route('/stats')
def get_stats():
    return jsonify(network_stats.get_stats())


@app.route('/interfaces', methods=['GET'])
def list_interfaces():
    """
    Dohvati interfejse s Windows friendly_name + pcap_name.
    """
    interfaces = []
    windows_interfaces = get_windows_if_list()
    for w_iface in windows_interfaces:
        guid = w_iface['guid']
        name = w_iface['name']  # "Ethernet", "Wi-Fi", ...
        desc = w_iface['description']
        pcap_name = f"\\Device\\NPF_{guid}"

        interfaces.append({
            "pcap_name": pcap_name,
            "friendly_name": name,
            "description": desc
        })
    return jsonify(interfaces)


@app.route('/select_interface', methods=['POST'])
def select_interface():
    """
    Kad dođe POST sa JSON {"friendly_name": "..."},
    nađemo odgovarajući pcap_name i pokrenemo sniff.
    Ako je stari sniff aktivan, zaustavimo ga (stop_sniffing_event).
    """
    global selected_interface, sniff_thread, stop_sniffing_event

    # DEBUG: provjera da li dolazi POST i koji su podaci
    print("DEBUG: '/select_interface' route called!")  # <-- debug
    data = request.get_json()
    print("DEBUG: data from request:", data)  # <-- debug

    if not data or 'friendly_name' not in data:
        print("DEBUG: missing 'friendly_name' in data!")  # <-- debug
        return jsonify({'status': 'error', 'message': 'No friendly_name provided'}), 400

    user_friendly_name = data['friendly_name']

    # Pronađi device_name (pcap_name) prema friendly_name
    device_name = None
    for iface_obj in ifaces.values():
        if iface_obj.name == user_friendly_name:
            device_name = getattr(iface_obj, 'pcap_name', None) or getattr(iface_obj, 'dev', None)
            break

    print(f"DEBUG: Looking for '{user_friendly_name}' => device_name = {device_name}")  # <-- debug

    # if not device_name:
    #    print("DEBUG: Interface NOT FOUND!")  # <-- debug
    #    return jsonify({'status': 'error', 'message': f'Interface {user_friendly_name} not found.'}), 404

    # Zaustavimo stari sniff, ako radi
    if sniff_thread and sniff_thread.is_alive():
        print("DEBUG: stopping old sniff...")  # <-- debug
        stop_sniffing_event.set()  # signal da se sniff prekine
        sniff_thread.join(timeout=1.0)  # pričekamo malo

    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except Empty:
            break

    network_stats.reset();
    # Reset eventa za idući sniff
    stop_sniffing_event = threading.Event()

    # Postavi novi interface
    selected_interface = user_friendly_name
    print(f"[INFO] Selected interface set to: {selected_interface}")

    # Pokreni novu sniff nit
    print("DEBUG: starting new sniff thread...")  # <-- debug
    sniff_thread = threading.Thread(target=sniff_packets, args=[selected_interface])
    sniff_thread.daemon = True
    sniff_thread.start()

    return jsonify({'status': 'ok', 'message': f'Sniffing started on {user_friendly_name}'})


# (Ne treba /login/ route ovdje ako se ne koristi, ali neka ostane primjer)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return jsonify({
        'status': 'error',
        'message': 'Invalid login attempt'
    }), 401


@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global sniff_thread, stop_sniffing_event

    print("[DEBUG] '/stop_sniffing' called!")

    if sniff_thread and sniff_thread.is_alive():
        stop_sniffing_event.set()
        sniff_thread.join(timeout=2.0)
        sniff_thread = None
        print("[INFO] Sniffing thread stopped.")
    else:
        print("[INFO] No active sniff thread to stop.");

    return jsonify({'status': 'ok', 'message': 'Sniffing stopped'}), 200

# ---------------------------
#   NE POKREĆEMO sniff ODMAH
# ---------------------------
# Možete isprobati s fiksnim interfaceom, ali u
# "Pristup #2" želimo pokrenuti kad klijent izabere interface.
# threading.Thread(target=sniff_packets, args=["Ethernet"], daemon=True).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
