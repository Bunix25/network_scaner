from scapy.all import ARP, Ether, srp, conf
import csv
import subprocess

def scan_network(ip_range):
    # Create an ARP request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract MAC and IP addresses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_device_details(ip):
    try:
        # Run nmap to get more details about the IP address
        result = subprocess.run(["nmap", "-O", ip], capture_output=True, text=True, timeout=30)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out"
    except Exception as e:
        return str(e)

def save_to_csv(devices, filename):
    if not devices:
        print("No devices found on the network.")
        return

    # Define the CSV fieldnames including details
    fieldnames = ['ip', 'mac', 'details']
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        dict_writer.writeheader()
        for device in devices:
            dict_writer.writerow(device)

if __name__ == "__main__":
    # Setting scapy to ignore interfaces without an IPv4 address
    conf.ipv6_enabled = False

    ip_range = "10.0.0.1/24"  # Change this to your network range
    devices = scan_network(ip_range)

    if devices:
        print(f"Found {len(devices)} devices on the network.")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
            details = get_device_details(device['ip'])
            print(f"Details for IP {device['ip']}:\n{details}")
            device['details'] = details

        save_to_csv(devices, 'network_devices.csv')
    else:
        print("No devices found.")