import subprocess
import sys

def run_command(command):
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while executing {command}: {e.stderr}")
        sys.exit(1)

def configure_network(ip_address):
    print(f"Configuring the IP address to {ip_address} using nmcli...")
    
    # Bringing the interface down
    run_command(['nmcli', 'dev', 'disconnect', 'eth0'])
    
    # Configuring the IP address
    run_command(['nmcli', 'con', 'modify', 'eth0', 'ipv4.addresses', ip_address, 'ipv4.method', 'manual'])
    
    # Bringing the interface up
    run_command(['nmcli', 'con', 'up', 'eth0'])
    
    print(f"Network interface eth0 configured with IP {ip_address} and brought up successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python configure_network.py <IP_ADDRESS>")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    configure_network(ip_address)
