from flask import Flask, render_template, jsonify, request
from scapy.all import sniff
import threading
import time

app = Flask(__name__)

capturing = False
captured_packets = []
packet_stats = {
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'Other': 0
}

def packet_handler(pkt):
    global packet_stats
    proto = pkt.payload.name
    if proto in packet_stats:
        packet_stats[proto] += 1
    else:
        packet_stats['Other'] += 1

    captured_packets.append({
        'src': pkt[0][1].src if hasattr(pkt[0][1], 'src') else 'N/A',
        'dst': pkt[0][1].dst if hasattr(pkt[0][1], 'dst') else 'N/A',
        'proto': proto,
        'summary': pkt.summary()
    })

    # Limit to latest 100 packets
    if len(captured_packets) > 100:
        captured_packets.pop(0)

def start_sniff():
    sniff(prn=packet_handler, store=False)

def background_sniff():
    while capturing:
        sniff(prn=packet_handler, store=False, timeout=5)
        time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start')
def start():
    global capturing
    capturing = True
    thread = threading.Thread(target=background_sniff)
    thread.start()
    return jsonify({'status': 'started'})

@app.route('/stop')
def stop():
    global capturing
    capturing = False
    return jsonify({'status': 'stopped'})

@app.route('/packets')
def packets():
    return jsonify(captured_packets)

@app.route('/stats')
def stats():
    return jsonify(packet_stats)

if __name__ == '__main__':
    app.run(debug=True)
