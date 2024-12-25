from flask import Flask, Response, render_template
from scapy.all import sniff
from scapy.config import conf
from queue import Queue
import threading
import json
from packet_analyzer import PacketAnalyzer
from alert_system import AlertSystem
from config import *  # importamo sve konstante

app = Flask(__name__)

# Thread-safe queue to store packets
packet_queue = Queue()

# Initialize the packet analyzer
analyzer = PacketAnalyzer()

# Configure the alert system using konstante iz config.py
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
        # Analyze packet
        analysis_result = analyzer.analyze_packet(packet)
        if analysis_result:
            # Send alerts for any threats
            if analysis_result["threats"]:
                for threat in analysis_result["threats"]:
                    # Send alert for high severity threats
                    if threat["severity"] in ["Critical", "High"]:
                        alert_system.send_alert(threat, analysis_result["packet_info"])

            # Convert to JSON-friendly format and add to queue
            packet_queue.put({
                "summary": packet.sprintf("%IP.src% → %IP.dst% %IP.proto%"),
                "analysis": analysis_result
            })

    # Sniff packets on interface
    sniff(iface="Wi-Fi", prn=process_packet, store=False, L2socket=conf.L3socket)

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

# Route to stream packet data
@app.route('/stream')
def stream():
    def generate():
        while True:
            # Wait for a packet in the queue
            packet_data = packet_queue.get()
            yield f"data: {json.dumps(packet_data)}\n\n"

    return Response(generate(), content_type='text/event-stream')

# Start the packet sniffer in a separate thread
threading.Thread(target=sniff_packets, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)