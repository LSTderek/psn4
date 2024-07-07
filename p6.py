# Import necessary modules
import pypsn
from flask import Flask, render_template_string
from threading import Thread
import time
import socket

# Initialize Flask app
app = Flask(__name__)

# Dictionary to store system information keyed by source IP
systems_info = {}
trackers_list = {}

# Define a function to convert bytes to string
def bytes_to_str(b):
    return b.decode('utf-8') if isinstance(b, bytes) else b

# Define a callback function to handle the received PSN data
def callback_function(data):
    global systems_info, trackers_list
    if isinstance(data, pypsn.psn_info_packet):
        info = data.info
        ip_address = info.src_ip if hasattr(info, 'src_ip') else 'N/A'
        system_info = {
            'server_name': bytes_to_str(data.name),
            'packet_timestamp': info.timestamp,
            'version_high': info.version_high,
            'version_low': info.version_low,
            'frame_id': info.frame_id,
            'frame_packet_count': info.packet_count,
            'src_ip': ip_address
        }
        systems_info[ip_address] = system_info

        if ip_address not in trackers_list:
            trackers_list[ip_address] = {}

        for tracker in data.trackers:
            tracker_info = {
                'tracker_id': tracker.tracker_id,
                'tracker_name': bytes_to_str(tracker.tracker_name),
                'server_name': bytes_to_str(data.name),
                'src_ip': ip_address
            }
            trackers_list[ip_address][tracker.tracker_id] = tracker_info

# Create a receiver object with the callback function
receiver = pypsn.receiver(callback_function)

# Define route to display system info and available trackers in tables
@app.route('/', methods=['GET'])
def display_info():
    sorted_systems_info = dict(sorted(systems_info.items()))
    sorted_trackers_list = []
    for ip in sorted(trackers_list.keys()):
        for tracker_id in sorted(trackers_list[ip].keys()):
            sorted_trackers_list.append(trackers_list[ip][tracker_id])

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PSN System Info and Trackers</title>
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
            {% for tracker in sorted_trackers_list %}
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
    return render_template_string(html_template, sorted_systems_info=sorted_systems_info, sorted_trackers_list=sorted_trackers_list)

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

        # Start Flask server
        flask_thread = Thread(target=run_flask)
        flask_thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping receiver and Flask server...")

        # Stop the receiver
        receiver.stop()

        # Wait for threads to finish
        receiver_thread.join()
        flask_thread.join()

        print("Stopped.")
