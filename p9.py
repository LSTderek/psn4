# Import necessary modules
import pypsn
from flask import Flask, render_template_string, request
from threading import Thread
import time
import socket
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Dictionary to store system information keyed by source IP
systems_info = {}
trackers_list = {}

# Logging levels
log_info = True
log_debug = False

# Define a function to convert bytes to string
def bytes_to_str(b):
    return b.decode('utf-8') if isinstance(b, bytes) else b

# Define a callback function to handle the received PSN data
def callback_function(data):
    global systems_info, trackers_list
    if isinstance(data, pypsn.psn_info_packet):
        info = data.info
        ip_address = info.src_ip if hasattr(info, 'src_ip') else 'N/A'
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        system_info = {
            'server_name': bytes_to_str(data.name),
            'packet_timestamp': info.timestamp,
            'version_high': info.version_high,
            'version_low': info.version_low,
            'frame_id': info.frame_id,
            'frame_packet_count': info.packet_count,
            'src_ip': ip_address,
            'timestamp': timestamp
        }
        systems_info[ip_address] = system_info

        if ip_address not in trackers_list:
            trackers_list[ip_address] = {}

        for tracker in data.trackers:
            tracker_info = {
                'tracker_id': tracker.tracker_id,
                'tracker_name': bytes_to_str(tracker.tracker_name),
                'server_name': bytes_to_str(data.name),
                'src_ip': ip_address,
                'timestamp': timestamp
            }
            trackers_list[ip_address][tracker.tracker_id] = tracker_info

        if log_info:
            print(f"Received data from {ip_address} at {timestamp}")

# Create a receiver object with the callback function
receiver = pypsn.receiver(callback_function)

# Function to clean up stale entries
def clean_stale_entries():
    global systems_info, trackers_list
    while True:
        current_time = datetime.now()
        systems_to_delete = []
        trackers_to_delete = {}

        # Clean up systems_info
        for ip, system in systems_info.items():
            system_timestamp = datetime.strptime(system['timestamp'], '%Y-%m-%d %H:%M:%S')
            if (current_time - system_timestamp).total_seconds() > 10:
                systems_to_delete.append(ip)

        for ip in systems_to_delete:
            del systems_info[ip]

        # Clean up trackers_list
        for ip, trackers in trackers_list.items():
            for tracker_id, tracker in trackers.items():
                tracker_timestamp = datetime.strptime(tracker['timestamp'], '%Y-%m-%d %H:%M:%S')
                if (current_time - tracker_timestamp).total_seconds() > 5:
                    if ip not in trackers_to_delete:
                        trackers_to_delete[ip] = []
                    trackers_to_delete[ip].append(tracker_id)

        for ip, tracker_ids in trackers_to_delete.items():
            for tracker_id in tracker_ids:
                del trackers_list[ip][tracker_id]
            if not trackers_list[ip]:  # If no trackers left for this IP, remove the key
                del trackers_list[ip]

        if log_debug:
            print(f"Cleaned systems_info: {systems_info}")  # Debug print
            print(f"Cleaned trackers_list: {trackers_list}")  # Debug print

        time.sleep(1)  # Run cleanup every second

# Define route to display system info
@app.route('/system_info', methods=['GET'])
def system_info():
    sorted_systems_info = dict(sorted(systems_info.items()))

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>System Information</title>
    </head>
    <body>
        <h1>System Information</h1>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Server Name</th>
                <th>Packet Timestamp</th>
                <th>Version High</th>
                <th>Version Low</th>
                <th>Frame ID</th>
                <th>Frame Packet Count</th>
                <th>Timestamp</th>
            </tr>
            {% for ip, system in sorted_systems_info.items() %}
            <tr>
                <td>{{ system.src_ip }}</td>
                <td>{{ system.server_name }}</td>
                <td>{{ system.packet_timestamp }}</td>
                <td>{{ system.version_high }}</td>
                <td>{{ system.version_low }}</td>
                <td>{{ system.frame_id }}</td>
                <td>{{ system.frame_packet_count }}</td>
                <td>{{ system.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    return render_template_string(html_template, sorted_systems_info=sorted_systems_info)

# Define route to display available trackers
@app.route('/trackers', methods=['GET'])
def trackers():
    sorted_trackers_list = []
    for ip in sorted(trackers_list.keys()):
        for tracker_id in sorted(trackers_list[ip].keys()):
            sorted_trackers_list.append(trackers_list[ip][tracker_id])

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Available Trackers</title>
    </head>
    <body>
        <h1>Available Trackers</h1>
        <table border="1">
            <tr>
                <th>Tracker ID</th>
                <th>Tracker Name</th>
                <th>Server Name</th>
                <th>IP Address</th>
                <th>Timestamp</th>
            </tr>
            {% for tracker in sorted_trackers_list %}
            <tr>
                <td>{{ tracker.tracker_id }}</td>
                <td>{{ tracker.tracker_name }}</td>
                <td>{{ tracker.server_name }}</td>
                <td>{{ tracker.src_ip }}</td>
                <td>{{ tracker.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    return render_template_string(html_template, sorted_trackers_list=sorted_trackers_list)

# Define route to display the main page with logging controls and frames
@app.route('/', methods=['GET', 'POST'])
def display_info():
    global log_info, log_debug

    if request.method == 'POST':
        log_info = 'log_info' in request.form
        log_debug = 'log_debug' in request.form

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PSN System Info and Trackers</title>
        <script>
            function refreshIframes() {
                document.getElementById('systemInfoFrame').src = document.getElementById('systemInfoFrame').src;
                document.getElementById('trackersFrame').src = document.getElementById('trackersFrame').src;
            }
            setInterval(refreshIframes, 5000);  // Refresh every 5 seconds
        </script>
    </head>
    <body>
        <h1>Logging Controls</h1>
        <form method="POST">
            <input type="checkbox" name="log_info" {% if log_info %}checked{% endif %}> Log Info<br>
            <input type="checkbox" name="log_debug" {% if log_debug %}checked{% endif %}> Log Debug<br>
            <input type="submit" value="Update Logging">
        </form>
        <h1>System Information</h1>
        <iframe id="systemInfoFrame" src="/system_info" width="100%" height="300px"></iframe>
        <h1>Available Trackers</h1>
        <iframe id="trackersFrame" src="/trackers" width="100%" height="300px"></iframe>
    </body>
    </html>
    """
    return render_template_string(html_template, log_info=log_info, log_debug=log_debug)

# Function to run Flask app
def run_flask():
    print("Starting Flask server...")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

# Start the receiver and Flask server in separate threads
if __name__ == '__main__':
    try:
        # Start the receiver
        print("Starting PSN receiver...")
        receiver_thread = Thread(target=receiver.start)
        receiver_thread.start()

        # Start the stale entry cleaner
        cleaner_thread = Thread(target=clean_stale_entries)
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
