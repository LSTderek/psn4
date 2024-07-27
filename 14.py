# Import necessary modules
import pypsn
from flask import Flask, render_template, render_template_string, request, jsonify
from threading import Thread, Event
import time
from datetime import datetime
import json
import os
from werkzeug.serving import make_server
import subprocess
import re

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

# Define a function to validate IP address
def validate_ip_address(ip_address):
    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if pattern.match(ip_address):
        return all(0 <= int(octet) <= 255 for octet in ip_address.split('.'))
    return False

# Define a function to validate netmask
def validate_netmask(netmask):
    if validate_ip_address(netmask):
        return True
    try:
        if 0 <= int(netmask) <= 32:
            return True
    except ValueError:
        pass
    return False

# Define a function to convert CIDR netmask to dotted decimal
def cidr_to_netmask(cidr):
    host_bits = 32 - int(cidr)
    return '.'.join([str((0xffffffff << host_bits >> i) & 0xff) for i in [24, 16, 8, 0]])

# Define a function to get IP settings
def get_ip_settings(interface):
    try:
        result = subprocess.run(['ip', 'addr', 'show', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet ' in line:
                    ip_address, cidr = line.strip().split(' ')[1].split('/')
                    netmask = cidr_to_netmask(cidr)
                    return ip_address, netmask
        return 'Not Configured', ''
    except Exception as e:
        return str(e), ''

# Define a function to set IP settings
def set_ip_settings(interface, ip_address, netmask, method):
    try:
        if method == 'static':
            if not validate_ip_address(ip_address):
                return 'Invalid IP address'
            if not validate_netmask(netmask):
                return 'Invalid netmask'

            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface], check=True)
            subprocess.run(['sudo', 'ip', 'addr', 'add', f'{ip_address}/{netmask}', 'dev', interface], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', interface, 'up'], check=True)
        elif method == 'dhcp':
            subprocess.run(['sudo', 'dhclient', '-r', interface], check=True)
            subprocess.run(['sudo', 'dhclient', interface], check=True)
        return 'Success'
    except subprocess.CalledProcessError as e:
        return f'Error: {e}'

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
            'trackers': {
                tracker.tracker_id: bytes_to_str(tracker.tracker_name)
                for tracker in data.trackers
            },
            'tracker_count': len(data.trackers)
        }
        systems_info[ip_address] = system_info

        if ip_address in stale_systems:
            del stale_systems[ip_address]
        
        if log_info:
            print(f"Received system info from {ip_address} at {timestamp}")
    
    elif isinstance(data, pypsn.psn_data_packet):
        if data.trackers:
            ip_address = data.trackers[0].src_ip
        else:
            ip_address = 'N/A'
       # print(systems_info)
        if ip_address in systems_info:
            system_trackers = systems_info[ip_address].get('trackers', {})
            system_name = systems_info[ip_address].get('server_name', 'Unknown')
        else:
            system_trackers = {}
            system_name = 'Unknown'

        for tracker in data.trackers:
            tracker_key = f"{tracker.src_ip}_{tracker.id}"  # Unique key combining IP and tracker ID
            tracker_name = system_trackers.get(tracker.id, 'Unknown')
            tracker_info = {
                'tracker_id': tracker.id,
                'src_ip': tracker.src_ip,
                'timestamp': timestamp,
                'pos_x': round(tracker.pos.x, 3),
                'pos_y': round(tracker.pos.y, 3),
                'pos_z': round(tracker.pos.z, 3),
                'tracker_name': tracker_name,
                'system_name': system_name,
                'speed_x': round(tracker.speed.x, 3) if hasattr(tracker.speed, 'x') else 'N/A',
                'speed_y': round(tracker.speed.y, 3) if hasattr(tracker.speed, 'y') else 'N/A',
                'speed_z': round(tracker.speed.z, 3) if hasattr(tracker.speed, 'z') else 'N/A',
                'ori_x': round(tracker.ori.x, 3) if hasattr(tracker.ori, 'x') else 'N/A',
                'ori_y': round(tracker.ori.y, 3) if hasattr(tracker.ori, 'y') else 'N/A',
                'ori_z': round(tracker.ori.z, 3) if hasattr(tracker.ori, 'z') else 'N/A',
                'accel_x': round(tracker.accel.x, 3) if hasattr(tracker.accel, 'x') else 'N/A',
                'accel_y': round(tracker.accel.y, 3) if hasattr(tracker.accel, 'y') else 'N/A',
                'accel_z': round(tracker.accel.z, 3) if hasattr(tracker.accel, 'z') else 'N/A',
                'trgtpos_x': round(tracker.trgtpos.x, 3) if hasattr(tracker.trgtpos, 'x') else 'N/A',
                'trgtpos_y': round(tracker.trgtpos.y, 3) if hasattr(tracker.trgtpos, 'y') else 'N/A',
                'trgtpos_z': round(tracker.trgtpos.z, 3) if hasattr(tracker.trgtpos, 'z') else 'N/A',
                'status': tracker.status if hasattr(tracker, 'status') else 'N/A'
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

@app.route('/trackers', methods=['GET'])
def combined_info():
    sorted_systems_info = dict(sorted(systems_info.items()))
    sorted_stale_systems_info = dict(sorted(stale_systems.items()))
    sorted_trackers_list = list(trackers_list.values())
    sorted_stale_trackers_list = list(stale_trackers.values())

    # Render the HTML template file with the sorted data
    return render_template('trackers.html', 
                           sorted_systems_info=sorted_systems_info, 
                           sorted_stale_systems_info=sorted_stale_systems_info, 
                           sorted_trackers_list=sorted_trackers_list, 
                           sorted_stale_trackers_list=sorted_stale_trackers_list)


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

    ip_eth0, netmask_eth0 = get_ip_settings('eth0')
    ip_eth1, netmask_eth1 = get_ip_settings('eth1')

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PSN System Info and Trackers</title>
        <script>
            function refreshIframe() {
                document.getElementById('trackerFrame').src = document.getElementById('trackerFrame').src;
            }
            setInterval(refreshIframe, {{ page_auto_refresh_rate }} * 1000);  // Refresh combined info frame in seconds

            function resizeIframe() {
                var iframe = document.getElementById('trackerFrame');
                iframe.style.height = iframe.contentWindow.document.body.scrollHeight + 'px';
            }
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
        <h1>Network Settings</h1>
        <form id="ipForm" method="POST" action="/update_ip">
            <fieldset>
                <legend>eth0</legend>
                <label for="eth0_method">Method:</label>
                <select name="eth0_method">
                    <option value="static">Static</option>
                    <option value="dhcp">DHCP</option>
                </select><br>
                <label for="eth0_ip_address">IP Address:</label>
                <input type="text" name="eth0_ip_address" value="{{ ip_eth0 }}" required><br>
                <label for="eth0_netmask">Netmask:</label>
                <input type="text" name="eth0_netmask" value="{{ netmask_eth0 }}" required><br>
            </fieldset>
            <fieldset>
                <legend>eth1</legend>
                <label for="eth1_method">Method:</label>
                <select name="eth1_method">
                    <option value="static">Static</option>
                    <option value="dhcp">DHCP</option>
                </select><br>
                <label for="eth1_ip_address">IP Address:</label>
                <input type="text" name="eth1_ip_address" value="{{ ip_eth1 }}" required><br>
                <label for="eth1_netmask">Netmask:</label>
                <input type="text" name="eth1_netmask" value="{{ netmask_eth1 }}" required><br>
            </fieldset>
            <input type="submit" value="Update IP">
        </form>
        <h1>Combined Information</h1>
        <iframe id="trackerFrame" src="/trackers" width="100%" onload="resizeIframe()"></iframe>
    </body>
    </html>
    """

    return render_template_string(
        html_template, 
        log_info=log_info, 
        log_debug=log_debug, 
        page_auto_refresh_rate=page_auto_refresh_rate, 
        system_info_cleanup_duration=system_info_cleanup_duration, 
        trackers_cleanup_duration=trackers_cleanup_duration,
        ip_eth0=ip_eth0,
        netmask_eth0=netmask_eth0,
        ip_eth1=ip_eth1,
        netmask_eth1=netmask_eth1
    )

@app.route('/update_ip', methods=['POST'])
def update_ip():
    eth0_method = request.form['eth0_method']
    eth0_ip_address = request.form['eth0_ip_address']
    eth0_netmask = request.form['eth0_netmask']
    eth1_method = request.form['eth1_method']
    eth1_ip_address = request.form['eth1_ip_address']
    eth1_netmask = request.form['eth1_netmask']

    result_eth0 = set_ip_settings('eth0', eth0_ip_address, eth0_netmask, eth0_method)
    result_eth1 = set_ip_settings('eth1', eth1_ip_address, eth1_netmask, eth1_method)
    
    return jsonify({'result_eth0': result_eth0, 'result_eth1': result_eth1})

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