# Import necessary modules
import pypsn
from flask import Flask, render_template, request
from threading import Thread, Event
import time
import socket
from datetime import datetime
import json
import os
from werkzeug.serving import make_server

# Initialize Flask app
app = Flask(__name__)

# Dictionary to store system information keyed by source IP
systems_info = {}
stale_systems = {}
trackers_list = {}
stale_trackers = {}

# Default settings
default_config = {
    'log_info': False,
    'log_debug': False,
    'page_auto_refresh_rate': 1,  # in seconds
    'system_info_cleanup_duration': 3,  # in seconds
    'trackers_cleanup_duration': 1  # in seconds
}

# Load or create config file
config_file = 'config.json'
if os.path.exists(config_file):
    with open(config_file, 'r') as file:
        config = json.load(file)
else:
    config = default_config
    with open(config_file, 'w') as file:
        json.dump(config, file)

# Apply settings from config file
log_info = config['log_info']
log_debug = config['log_debug']
page_auto_refresh_rate = config['page_auto_refresh_rate']
system_info_cleanup_duration = config['system_info_cleanup_duration']
trackers_cleanup_duration = config['trackers_cleanup_duration']

# Define a function to convert bytes to string
def bytes_to_str(b):
    return b.decode('utf-8') if isinstance(b, bytes) else b

# Define a callback function to handle the received PSN data
def callback_function(data):
    global systems_info, trackers_list, stale_trackers, stale_systems
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
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
            'src_ip': ip_address,
            'timestamp': timestamp,
            'tracker_count': len(data.trackers),
            'trackers': {
                tracker.tracker_id: bytes_to_str(tracker.tracker_name)
                for tracker in data.trackers
            }
        }
        systems_info[ip_address] = system_info

        if ip_address in stale_systems:
            del stale_systems[ip_address]
        
        if log_info:
            print(f"Received system info from {ip_address} at {timestamp}")
    
    elif isinstance(data, pypsn.psn_data_packet):
        ip_address = data.src_ip if hasattr(data, 'src_ip') else 'N/A'
        
        if ip_address in systems_info:
            system_trackers = systems_info[ip_address].get('trackers', {})
            system_name = systems_info[ip_address]['server_name']
        else:
            system_trackers = {}
            system_name = 'Unknown'

        for tracker in data.trackers:
            tracker_key = f"{tracker.src_ip}_{tracker.id}"  # Unique key combining IP and tracker ID
            tracker_info = {
                'tracker_id': tracker.id,
                'src_ip': tracker.src_ip,
                'timestamp': timestamp,
                'pos_x': round(tracker.pos.x, 3),
                'pos_y': round(tracker.pos.y, 3),
                'pos_z': round(tracker.pos.z, 3),
                'speed_x': round(tracker.speed.x, 3),
                'speed_y': round(tracker.speed.y, 3),
                'speed_z': round(tracker.speed.z, 3),
                'ori_x': round(tracker.ori.x, 3),
                'ori_y': round(tracker.ori.y, 3),
                'ori_z': round(tracker.ori.z, 3),
                'accel_x': round(tracker.accel.x, 3),
                'accel_y': round(tracker.accel.y, 3),
                'accel_z': round(tracker.accel.z, 3),
                'trgtpos_x': round(tracker.trgtpos.x, 3),
                'trgtpos_y': round(tracker.trgtpos.y, 3),
                'trgtpos_z': round(tracker.trgtpos.z, 3),
                'status': tracker.status,
                'tracker_name': system_trackers.get(tracker.id, 'Unknown'),
                'system_name': system_name
            }
            trackers_list[tracker_key] = tracker_info

            # Remove the tracker from stale_trackers if it is being updated
            if tracker_key in stale_trackers:
                del stale_trackers[tracker_key]

        if log_info:
            print(f"Received tracker data from {ip_address} at {timestamp}")

# Create a receiver object with the callback function
receiver = pypsn.receiver(callback_function)

# Function to clean up stale entries
def clean_stale_entries(stop_event):
    global systems_info, stale_systems, trackers_list, stale_trackers, system_info_cleanup_duration, trackers_cleanup_duration
    while not stop_event.is_set():
        current_time = datetime.now()
        systems_to_delete = []
        trackers_to_delete = []

        # Clean up systems_info
        for ip, system in systems_info.items():
            system_timestamp = datetime.strptime(system['timestamp'], '%Y-%m-%d %H:%M:%S')
            if (current_time - system_timestamp).total_seconds() > system_info_cleanup_duration:
                systems_to_delete.append(ip)

        for ip in systems_to_delete:
            stale_systems[ip] = systems_info[ip]
            del systems_info[ip]

        # Clean up trackers_list
        for tracker_key, tracker in trackers_list.items():
            tracker_timestamp = datetime.strptime(tracker['timestamp'], '%Y-%m-%d %H:%M:%S')
            if (current_time - tracker_timestamp).total_seconds() > trackers_cleanup_duration:
                trackers_to_delete.append(tracker_key)

        for tracker_key in trackers_to_delete:
            stale_trackers[tracker_key] = trackers_list[tracker_key]
            del trackers_list[tracker_key]

        if log_debug:
            print(f"Cleaned systems_info: {systems_info}")  # Debug print
            print(f"Cleaned trackers_list: {trackers_list}")  # Debug print
            print(f"Stale trackers: {stale_trackers}")  # Debug print
            print(f"Stale systems: {stale_systems}")  # Debug print

        stop_event.wait(1)  # Run cleanup every second

# Define route to display combined system info, active trackers, and stale trackers
@app.route('/combined_info', methods=['GET'])
def combined_info():
    sorted_systems_info = dict(sorted(systems_info.items()))
    sorted_stale_systems_info = dict(sorted(stale_systems.items()))
    sorted_trackers_list = list(trackers_list.values())
    sorted_stale_trackers_list = list(stale_trackers.values())

    return render_template(
        'trackers.html', 
        sorted_systems_info=sorted_systems_info, 
        sorted_stale_systems_info=sorted_stale_systems_info, 
        sorted_trackers_list=sorted_trackers_list, 
        sorted_stale_trackers_list=sorted_stale_trackers_list
    )

# Define route to display the main page with logging controls and frames
@app.route('/', methods=['GET', 'POST'])
def display_info():
    global log_info, log_debug, page_auto_refresh_rate, system_info_cleanup_duration, trackers_cleanup_duration

    if request.method == 'POST':
        log_info = 'log_info' in request.form
        log_debug = 'log_debug' in request.form
        page_auto_refresh_rate = int(request.form.get('page_auto_refresh_rate', 5))
        system_info_cleanup_duration = int(request.form.get('system_info_cleanup_duration', 10))
        trackers_cleanup_duration = int(request.form.get('trackers_cleanup_duration', 5))

        # Save the updated settings to config.json
        config.update({
            'log_info': log_info,
            'log_debug': log_debug,
            'page_auto_refresh_rate': page_auto_refresh_rate,
            'system_info_cleanup_duration': system_info_cleanup_duration,
            'trackers_cleanup_duration': trackers_cleanup_duration
        })
        with open(config_file, 'w') as file:
            json.dump(config, file)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PSN System Info and Trackers</title>
        <script>
            function refreshIframe() {
                document.getElementById('combinedInfoFrame').src = document.getElementById('combinedInfoFrame').src;
            }
            setInterval(refreshIframe, {{ page_auto_refresh_rate }} * 1000);  // Refresh combined info frame in seconds
        </script>
    </head>
    <body>
        <h1>Logging Controls</h1>
        <form method="POST">
            <input type="checkbox" name="log_info" {% if log_info %}checked{% endif %}> Log Info<br>
            <input type="checkbox" name="log_debug" {% if log_debug %}checked{% endif %}> Log Debug<br>
            Page Auto Refresh Rate (s): <input type="number" name="page_auto_refresh_rate" value="{{ page_auto_refresh_rate }}"><br>
            System Info Cleanup Duration (s): <input type="number" name="system_info_cleanup_duration" value="{{ system_info_cleanup_duration }}"><br>
            Trackers Cleanup Duration (s): <input type="number" name="trackers_cleanup_duration" value="{{ trackers_cleanup_duration }}"><br>
            <input type="submit" value="Update Settings">
        </form>
        <h1>Combined Information</h1>
        <iframe id="combinedInfoFrame" src="/combined_info" width="100%" height="1200px"></iframe>
    </body>
    </html>
    """
    return render_template_string(
        html_template, 
        log_info=log_info, 
        log_debug=log_debug, 
        page_auto_refresh_rate=page_auto_refresh_rate, 
        system_info_cleanup_duration=system_info_cleanup_duration, 
        trackers_cleanup_duration=trackers_cleanup_duration
    )

# Function to run Flask app
class ServerThread(Thread):
    def __init__(self, app):
        Thread.__init__(self)
        self.server = make_server('0.0.0.0', 5002, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        print("Starting Flask server...")
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

# Start the receiver and Flask server in separate threads
if __name__ == '__main__':
    try:
        stop_event = Event()

        # Start the receiver
        print("Starting PSN receiver...")
        receiver_thread = Thread(target=receiver.start)
        receiver_thread.start()

        # Start the stale entry cleaner
        cleaner_thread = Thread(target=clean_stale_entries, args=(stop_event,))
        cleaner_thread.start()

        # Start Flask server
        server_thread = ServerThread(app)
        server_thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping receiver, cleaner, and Flask server...")

        # Signal the cleaner thread to stop
        stop_event.set()

        # Stop the receiver
        receiver.stop()

        # Stop Flask server
        server_thread.shutdown()

        # Wait for threads to finish
        receiver_thread.join()
        cleaner_thread.join()
        server_thread.join()

        print("Stopped.")