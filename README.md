# Scantrap IDS ⬡

Scantrap is a lightweight, real-time Network Intrusion Detection System (IDS) written in Python. It sniffs network traffic and uses a stateful detection engine to identify common network anomalies and attacks as they happen. 

The project features a sleek, professional dark-mode web dashboard built with Flask and Socket.IO for live, real-time threat monitoring.

![Scantrap IDS Dashboard Preview](https://via.placeholder.com/800x450.png?text=Scantrap+IDS+Dashboard+Preview)

## ✨ Features

- **Live Packet Sniffing**: Uses Scapy to capture and analyze network packets asynchronously.
- **Port Scan Detection**: Detects half-open TCP port scans (e.g., Nmap) using dynamic IP-to-port thresholding.
- **ARP Spoofing Detection**: Maintains an algorithmic IP-MAC mapping table and alerts on sudden MAC address changes from gateways.
- **Traffic Spike Detection**: Monitors Packets Per Second (PPS) and triggers alerts on abnormal surges in traffic volume.
- **SQLite Logging**: Asynchronously persists all alerts safely into an SQLite database (`data/ids_alerts.db`) without blocking the packet capture thread.
- **Live Web Dashboard**: A professional, real-time web UI powered by Flask and WebSockets that updates statistics and displays security events instantly.
- **Demo Mode**: Includes a simulated traffic generator `demo.py` so you can preview the dashboard without requiring root permissions or actual network attacks.

## 🛠 Tech Stack

- **Backend**: Python 3.10+, Scapy
- **Web Server**: Flask, Flask-SocketIO, Eventlet
- **Database**: SQLite3
- **Frontend**: HTML5, Vanilla CSS3, Vanilla JS (Canvas API for charting)

## 📦 Installation

**1. Clone the repository**
```bash
git clone https://github.com/bhoomikaxoxo/scantrap.git
cd scantrap
```

**2. Install dependencies**
Make sure you have Python installed. You can install the required Python packages using pip:
```bash
pip3 install -r requirements.txt
```

*(Note: If you run into issues installing Scapy on macOS/Linux, ensure you have the necessary libpcap dependencies installed via Homebrew or apt-get).*

## 🚀 How to Run

### 1. Developer / Demo Mode (No Root Required)
If you just want to see the dashboard without capturing real network traffic, use the demo simulator. This is great for showcasing the UI.

```bash
python3 demo.py
```
Then open your browser to **http://127.0.0.1:5002**

### 2. Live IDS Mode (Requires Root)
Raw packet sniffing requires elevated system privileges. To run the real Intrusion Detection System on your live network interface:

```bash
sudo python3 main.py
```
Then open your browser to **http://127.0.0.1:5002**

### 3. Specify a Network Interface (Optional)
If Scapy does not automatically select the correct network interface (e.g., Wi-Fi vs Ethernet), you can specify it using an environment variable (`SCANTRAP_IFACE`):

```bash
# Example for macOS Wi-Fi (en0)
sudo SCANTRAP_IFACE=en0 python3 main.py

# Example for Linux Ethernet (eth0)
sudo SCANTRAP_IFACE=eth0 python3 main.py
```
*(You can use `ifconfig` or `ip a` to find your network interface names).*

## ⚠️ Disclaimer

**Educational Lab Use Only!**  
This tool is built for educational and portfolio purposes. Do not deploy this on production environments. Ensure you only test ARP spoofing and port scanning tools (like Nmap) on hardware and virtual machines that you own within a controlled lab environment.

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

[MIT](https://choosealicense.com/licenses/mit/)
