# Import necessary modules
import pypsn
from flask import Flask, render_template_string
from threading import Thread
import time
import socket

# Initialize Flask app
app = Flask(__name__)

# Lists to store system information and tracker names
system_info = {}
trackers_list = []

# Define a function to convert bytes to string
def bytes_to_str(b):
    return b.decode('utf-8') if isinstance(b, bytes) else b

# Define a callback function to handle the received PSN data
def callback_function(data):
    global system_info, trackers_list
    if isinstance(data, pypsn.psn_info_packet):
        info = data.info
        system_info = {
            'server_name': bytes_to_str(data.name),
            'packet_timestamp': info.timestamp,
            'version_high': info.version_high,
            'version_low': info.version_low,
            'frame_id': info.frame_id,
            'frame_packet_count': info.packet_count,
            'src_ip': info.src_ip if hasattr(info, 'src_ip') else 'N/A'
        }
        trackers_list = [
            {
                'tracker_id': tracker.tracker_id,
                'tracker_name': bytes_to_str(tracker.tracker_name),
                'server_name': bytes_to_str(data.name),
                'src_ip': info.src_ip if hasattr(info, 'src_ip') else 'N/A'
            }
            for tracker in data.trackers
        ]

# Create a receiver object with the callback function
receiver = pypsn.receiver(callback_function)

# Define route to display system info and available trackers in tables
@app.route('/', methods=['GET'])
def display_info():
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
                <th>Server Name</th>
                <td>{{ system_info.server_name }}</td>
            </tr>
            <tr>
                <th>IP Address</th>
                <td>{{ system_info.src_ip }}</td>
            </tr>
            <tr>
                <th>Packet Timestamp</th>
                <td>{{ system_info.packet_timestamp }}</td>
            </tr>
            <tr>
                <th>Version High</th>
                <td>{{ system_info.version_high }}</td>
            </tr>
            <tr>
                <th>Version Low</th>
                <td>{{ system_info.version_low }}</td>
            </tr>
            <tr>
                <th>Frame ID</th>
                <td>{{ system_info.frame_id }}</td>
            </tr>
            <tr>
                <th>Frame Packet Count</th>
                <td>{{ system_info.frame_packet_count }}</td>
            </tr>
        </table>
        <h1>Available Trackers</h1>
        <table border="1">
            <tr>
                <th>Tracker ID</th>
                <th>Tracker Name</th>
                <th>Server Name</th>
                <th>IP Address</th>
            </tr>
            {% for tracker in trackers %}
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
    return render_template_string(html_template, system_info=system_info, trackers=trackers_list)

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
