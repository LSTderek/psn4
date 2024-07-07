# Import necessary modules
import pypsn
from flask import Flask, request, render_template_string
from threading import Thread, Lock
import time
import socket

# Initialize Flask app
app = Flask(__name__)

# Dictionary to store system information keyed by source IP
systems_info = {}
trackers_list = []
lock = Lock()

# User-definable duration for stale entry removal (in seconds)
stale_duration = 10

# Define a function to convert bytes to string
def bytes_to_str(b):
    return b.decode('utf-8') if isinstance(b, bytes) else b

# Define a callback function to handle the received PSN data
def callback_function(data):
    global systems_info, trackers_list
    print("Callback function called")  # Debug print
    if isinstance(data, pypsn.psn_info_packet):
        info = data.info
        ip_address = data.ip_address if hasattr(data, 'ip_address') else 'N/A'
        print(f"Received data from {ip_address}")  # Debug print
        system_info = {
            'server_name': bytes_to_str(data.name),
            'packet_timestamp': info.timestamp,
            'version_high': info.version_high,
            'version_low': info.version_low,
            'frame_id': info.frame_id,
            'frame_packet_count': info.packet_count,
            'src_ip': ip_address,
            'last_update': time.time()
        }
        with lock:
            systems_info[ip_address] = system_info
            print(f"Updated systems_info: {systems_info}")  # Debug print

        trackers_list = [
            {
                'tracker_id': tracker.tracker_id,
                'tracker_name': bytes_to_str(tracker.tracker_name),
                'server_name': bytes_to_str(data.name),
                'src_ip': ip_address
            }
            for tracker in data.trackers
        ]
        print(f"Updated trackers_list: {trackers_list}")  # Debug print

# Custom psn_receiver class to capture IP address of incoming packets
class psn_receiver(Thread):
    def __init__(self, callback):
        Thread.__init__(self)
        self.callback = callback
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 56565))

    def run(self):
        print("Receiver started")  # Debug print
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                ip_address = addr[0]
                print(f"Data received from {ip_address}: {data}")  # Debug print
                psn_data = self.parse_data(data)
                if psn_data:
                    psn_data.ip_address = ip_address  # Add the IP address to the data object
                    print("Callback with parsed data")  # Debug print
                    self.callback(psn_data)
                else:
                    print("Failed to parse data")  # Debug print
            except Exception as e:
                print(f"Error receiving data: {e}")  # Debug print

    def parse_data(self, data):
        print("Parsing data")  # Debug print
        try:
            # Assuming parse_data correctly parses data into psn_info_packet
            psn_packet = pypsn.psn_info_packet(data)
            print("Parsed data successfully")  # Debug print
            return psn_packet
        except Exception as e:
            print(f"Error parsing data: {e}")  # Debug print
            return None

    def stop(self):
        self.running = False
        self.sock.close()
        print("Receiver stopped")  # Debug print

# Function to clean up stale sources
def clean_stale_sources():
    global systems_info
    while True:
        time.sleep(stale_duration)
        current_time = time.time()
        with lock:
            systems_info = {ip: info for ip, info in systems_info.items() if current_time - info['last_update'] <= stale_duration}
            print(f"Cleaned systems_info: {systems_info}")  # Debug print

# Define route to display system info and available trackers in tables
@app.route('/', methods=['GET', 'POST'])
def display_info():
    global stale_duration
    if request.method == 'POST':
        try:
            stale_duration = int(request.form.get('stale_duration', 10))
        except ValueError:
            stale_duration = 10
    print(f"Displaying info with stale_duration: {stale_duration}")  # Debug print

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PSN System Info and Trackers</title>
    </head>
    <body>
        <h1>System Information</h1>
        <form method="post">
            <label for="stale_duration">Stale Entry Duration (seconds):</label>
            <input type="number" id="stale_duration" name="stale_duration" value="{{ stale_duration }}">
            <button type="submit">Update</button>
        </form>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Server Name</th>
                <th>Packet Timestamp</th>
                <th>Version High</th>
                <th>Version Low</th>
                <th>Frame ID</th>
                <th>Frame Packet Count</th>
            </tr>
            {% for system in systems_info.values()|sort(attribute='src_ip') %}
            <tr>
                <td>{{ system.src_ip }}</td>
                <td>{{ system.server_name }}</td>
                <td>{{ system.packet_timestamp }}</td>
                <td>{{ system.version_high }}</td>
                <td>{{ system.version_low }}</td>
                <td>{{ system.frame_id }}</td>
                <td>{{ system.frame_packet_count }}</td>
            </tr>
            {% endfor %}
        </table>
        <h1>Available Trackers</h1>
        <table border="1">
            <tr>
                <th>Tracker ID</th>
                <th>Tracker Name</th>
                <th>Server Name</th>
                <th>IP Address</th>
            </tr>
            {% for tracker in trackers_list %}
            <tr>
                <td>{{ tracker.tracker_id }}</td>
                <td>{{ tracker.tracker_name }}</td>
                <td>{{ tracker.server_name }}</td>
                <td>{{ tracker.src_ip }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    with lock:
        return render_template_string(html_template, systems_info=systems_info, trackers_list=trackers_list, stale_duration=stale_duration)

# Function to run Flask app
def run_flask():
    print("Starting Flask server...")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

# Start the receiver and Flask server in separate threads
if __name__ == '__main__':
    try:
        # Initialize the receiver
        receiver = psn_receiver(callback_function)

        # Start the receiver
        print("Starting PSN receiver...")
        receiver_thread = Thread(target=receiver.start)
        receiver_thread.start()

        # Start the stale source cleaner
        cleaner_thread = Thread(target=clean_stale_sources)
        cleaner_thread.start()

        # Start Flask server
        flask_thread = Thread(target=run_flask)
        flask_thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping receiver, cleaner, and Flask server...")

        # Stop the receiver
        receiver.stop()

        # Wait for threads to finish
        receiver_thread.join()
        cleaner_thread.join()
        flask_thread.join()

        print("Stopped.")
