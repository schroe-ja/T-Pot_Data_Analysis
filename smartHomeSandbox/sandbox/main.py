import argparse
from datetime import datetime

try:
    from network_capture import NetworkCapture
except ImportError:
    from classes.network_capture import NetworkCapture


def main():
    parser = argparse.ArgumentParser(
        description='Capture network flows from Raspberry Pi access point',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py -i wlan0 -o flows.csv
  sudo python3 main.py -i wlan0 -o flows.csv -c 10000 -t 300
  sudo python3 main.py -i wlan0 -o flows.csv -d 3600
        """,
    )
    parser.add_argument('-i', '--interface', default='wlan0', help='Network interface to capture on')
    parser.add_argument('-o', '--output', default=f'network_flows_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv', help='Output CSV file')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture; 0 = unlimited')
    parser.add_argument('-d', '--duration', type=int, default=0, help='Capture duration in seconds; 0 = unlimited')
    parser.add_argument('-t', '--timeout', type=int, default=120, help='Flow inactivity timeout in seconds')

    args = parser.parse_args()
    capture = NetworkCapture(interface=args.interface, output_file=args.output, flow_timeout=args.timeout)
    capture.start_capture(packet_count=args.count, duration=args.duration)


if __name__ == '__main__':
    main()
