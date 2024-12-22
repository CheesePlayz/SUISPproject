from flask import Flask, Response, render_template
from scapy.all import sniff
from queue import Queue
import threading

app = Flask(__name__)

# Thread-safe queue to store packets
packet_queue = Queue()


# Function to sniff packets
def sniff_packets():
    def process_packet(packet):
        # Add packet summary to the queue
        packet_queue.put(packet.summary())

    # Sniff packets on interface (replace "eth0" with your interface)
    sniff(iface="Ethernet", prn=process_packet, store=False)


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
            packet_summary = packet_queue.get()
            yield f"data: {packet_summary}\n\n"

    return Response(generate(), content_type='text/event-stream')


# Start the packet sniffer in a separate thread
threading.Thread(target=sniff_packets, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

