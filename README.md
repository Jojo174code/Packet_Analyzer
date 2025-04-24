# 🕵️ Packet Analyzer – Real-Time Web-Based Network Sniffer

A real-time packet analyzer built with **Python**, **Flask**, and **Scapy** that captures network traffic and displays it live in your browser.

---

## 🚀 Features

- ✅ Start/Stop packet capture from the browser
- 📡 Live-updating table of captured packets (source, destination, protocol)
- 🔍 Built-in search/filter for packets
- 📊 (Optional) Real-time traffic chart using Chart.js
- 🌑 Clean, dark-themed user interface

---

## 🧰 Technologies Used

- **Python 3**
- **Flask** (web server)
- **Flask-SocketIO** (real-time communication)
- **Scapy** (network packet sniffing)
- **HTML/CSS/JS** (frontend)
- **Chart.js** (for optional visualizations)

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

git clone https://github.com/YOUR_USERNAME/Packet_Analyzer.git
cd Packet_Analyzer

2. Create and Activate Virtual Environment (Recommended)

-python3 -m venv venv

-source venv/bin/activate

3. Install Dependencies

-pip install flask flask-socketio eventlet scapy


🖥️ Running the App
Start the Flask application:

-python packetAnalyzer.py

Then open your browser and go to:

-http://localhost:5000

🕹️ How to Use
-Click Start to begin capturing packets.

-Watch the packet table populate in real-time.

-Use the search bar to filter packets by IP or protocol.

-Click Stop to end the capture session.

📝 Notes
-Packet capturing may require administrative privileges on some systems.

-This app is meant for educational and ethical use only.

-Real-time features rely on WebSockets via Socket.IO.

📁 Folder Structure

packet_analyzer/
├── packetAnalyzer.py        # Flask app with Scapy integration
├── static/
│   ├── style.css            # UI styling
│   └── chart.js             # Optional traffic visualizations
├── templates/
│   └── index.html           # Main web interface
└── README.md                # You are here!
