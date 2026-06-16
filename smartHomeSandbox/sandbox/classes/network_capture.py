import csv
import os
import signal
import sys
import threading
import time
from datetime import datetime

try:
    from flow_tracker import FlowTracker
except ImportError:
    from classes.flow_tracker import FlowTracker

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: scapy not available. Install with: pip3 install scapy --break-system-packages")
    SCAPY_AVAILABLE = False

DUMP_INTERVAL_SECONDS = 86400


class NetworkCapture:
    """
    Live packet capture with flow tracking, login extraction and basic traffic logging.

    Periodic/final indicator CSVs:
      - login_attempts.csv
      - network_traffic.csv

    Final raw flow CSV:
      - <output_file>
    """

    def __init__(self, interface: str, output_file: str, flow_timeout: int = 120):
        self.interface = interface
        self.output_file = output_file
        self.flow_tracker = FlowTracker(flow_timeout)
        self.packet_count = 0
        self.running = True
        self._dump_lock = threading.Lock()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print('\n\nShutdown signal received — writing final outputs...')
        self.running = False

    def packet_handler(self, packet):
        self.packet_count += 1
        self.flow_tracker.update_flow(packet)

        if self.packet_count % 1000 == 0:
            store = self.flow_tracker.indicators
            print(
                f'[{datetime.now().strftime("%H:%M:%S")}] '
                f'{self.packet_count} packets | '
                f'flows={len(self.flow_tracker.flows)} | '
                f'logins={len(store.login_attempts)} | '
                f'traffic={len(store.network_traffic)}'
            )

    def _stem(self) -> str:
        base = self.output_file
        return base[:-4] if base.lower().endswith('.csv') else base

    @staticmethod
    def _ts() -> str:
        return datetime.utcnow().strftime('%Y%m%d_%H%M%S')

    def _indicator_path(self, suffix: str) -> str:
        return f'{self._stem()}_{suffix}.csv'

    @staticmethod
    def _write_csv(path: str, fieldnames: list, rows: list):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not rows:
            print(f'  (empty)  {path}')
            return
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
        print(f'  {len(rows):>5} rows  →  {path}')

    def _dump_indicators(self, timestamp: str):
        with self._dump_lock:
            store = self.flow_tracker.indicators
            print(f'\n[{datetime.utcnow().isoformat()}Z] Writing indicator CSVs (ts={timestamp})...')

            login_rows = list(dict(store.login_attempts).values())
            successful_count = sum(1 for row in login_rows if row.get('successful', False))
            print(f'  {len(login_rows)} unique login attempts recorded ({successful_count} successful)')
            self._write_csv(
                self._indicator_path('login_attempts'),
                ['username', 'password', 'src_ip', 'dst_ip', 'protocol', 'count', 'successful'],
                login_rows,
            )

            traffic_rows = store.get_traffic_rows()
            self._write_csv(
                self._indicator_path('network_traffic'),
                ['src_ip', 'count', 'url', 'threat', 'tags'],
                traffic_rows,
            )

    def _dump_flows(self):
        flows = self.flow_tracker.get_all_flows()
        flow_fields = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'protocol_name',
            'bytes_sent', 'bytes_received', 'total_bytes',
            'packets_sent', 'packets_received', 'total_packets',
            'duration_seconds', 'start_time', 'last_seen',
            'tcp_flags_forward', 'tcp_flags_reverse',
            'direction', 'bytes_per_second', 'packets_per_second',
        ]
        self._write_csv(self.output_file, flow_fields, flows)

    def _periodic_dump_thread(self):
        elapsed = 0
        sleep_step = 5
        while self.running:
            time.sleep(sleep_step)
            elapsed += sleep_step
            if elapsed >= DUMP_INTERVAL_SECONDS:
                elapsed = 0
                if self.running:
                    ts = self._ts()
                    print(f'\n[24h dump] Scheduled indicator export at {ts}Z')
                    try:
                        self._dump_indicators(ts)
                    except Exception as exc:
                        print(f'[24h dump] Error during scheduled export: {exc}')

    def start_capture(self, packet_count: int = 0, duration: int = 0):
        if not SCAPY_AVAILABLE:
            print('Error: scapy is required for packet capture.')
            sys.exit(1)

        print(f'Interface:    {self.interface}')
        print(f'Output stem:  {self._stem()}_*.csv')
        print(f'Flow timeout: {self.flow_tracker.flow_timeout}s')
        print(f'24h dump:     every {DUMP_INTERVAL_SECONDS // 3600}h')
        if packet_count > 0:
            print(f'Packet limit: {packet_count}')
        if duration > 0:
            print(f'Duration:     {duration}s')
        print('\nPress Ctrl+C to stop and save all outputs.\n')

        threading.Thread(target=self._periodic_dump_thread, daemon=True, name='periodic-dump').start()
        start_time = time.time()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: not self.running or (duration > 0 and time.time() - start_time >= duration),
            )
        except PermissionError:
            print(f'\nPermission denied. Run with sudo:\n    sudo python3 {sys.argv[0]} {" ".join(sys.argv[1:])}')
            sys.exit(1)
        except Exception as exc:
            print(f'\nCapture error: {exc}')
            import traceback
            traceback.print_exc()
        finally:
            self.running = False
            ts = self._ts()
            print(f'\nFinal export at {ts}Z')
            self._dump_flows()
            self._dump_indicators(ts)
            print(f'\nTotal packets processed: {self.packet_count}')
