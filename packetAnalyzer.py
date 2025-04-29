# Import necessary libraries
from flask import Flask, render_template, jsonify, request  # Flask web framework and helper functions
from scapy.all import sniff  # Scapy for packet sniffing
import threading  # For running sniffing in background without freezing the web app
import time  # To pause between background sniffing sessions

# Initialize the Flask app
app = Flask(__name__)

# Global state variables
capturing = False  # Tracks whether packet capturing is active
captured_packets = []  # Stores captured packet data (up to 100 packets)
packet_stats = {  # Stores count of packets by protocol type
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'Other': 0
}

# Function to handle each sniffed packet
def packet_handler(pkt):
    global packet_stats

    # Get the protocol name of the packet (e.g., TCP, UDP, etc.)
    proto = pkt.payload.name

    # Update statistics based on protocol
    if proto in packet_stats:
        packet_stats[proto] += 1
    else:
        packet_stats['Other'] += 1

    # Extract packet source, destination, protocol, and summary
    captured_packets.append({
        'src': pkt[0][1].src if hasattr(pkt[0][1], 'src') else 'N/A',
        'dst': pkt[0][1].dst if hasattr(pkt[0][1], 'dst') else 'N/A',
        'proto': proto,
        'summary': pkt.summary()
    })

    # Keep only the 100 most recent packets to avoid memory overflow
    if len(captured_packets) > 100:
        captured_packets.pop(0)

# Sniff packets continuously (not used directly, reserved for future use)
def start_sniff():
    sniff(prn=packet_handler, store=False)

# Function to sniff packets in the background thread
def background_sniff():
    while capturing:
        sniff(prn=packet_handler, store=False, timeout=5)  # Sniff for 5 seconds
        time.sleep(1)  # Pause to reduce CPU load

# Route: Home page
@app.route('/')
def index():
    return render_template('index.html')  # Loads the frontend page

# Route: Start capturing packets
@app.route('/start')
def start():
    global capturing
    capturing = True
    thread = threading.Thread(target=background_sniff)  # Run sniffing in a separate thread
    thread.start()
    return jsonify({'status': 'started'})  # Return JSON response to frontend

# Route: Stop capturing packets
@app.route('/stop')
def stop():
    global capturing
    capturing = False
    return jsonify({'status': 'stopped'})

# Route: Return captured packet data to frontend
@app.route('/packets')
def packets():
    return jsonify(captured_packets)

# Route: Return packet statistics to frontend
@app.route('/stats')
def stats():
    return jsonify(packet_stats)

# Run the app in debug mode (useful during development)
if __name__ == '__main__':
    app.run(debug=True)
