import base64
import hashlib
import re
import time
from datetime import datetime
from urllib.parse import parse_qs

try:
    from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: scapy not available. Install with: pip3 install scapy --break-system-packages")
    SCAPY_AVAILABLE = False


PROTOCOL_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB',
}


class IndicatorStore:
    """Stores extracted indicators used by the CSV exports."""

    def __init__(self):
        self.login_attempts: dict[tuple, dict] = {}
        self.network_traffic: dict[tuple, dict] = {}
        self._pending_creds: dict[tuple, dict] = {}
        self._last_committed: dict[tuple, tuple] = {}

    # ── login_attempts ────────────────────────────────────────────────────────

    def set_login_username(self, *, src_ip, dst_ip, protocol, username):
        if not username:
            return

        value = username.strip()
        if '=' in value:
            key, val = value.split('=', 1)
            key = key.lower().strip()
            val = val.strip()
        else:
            key, val = 'username', value

        valid_keys = {'username', 'user', 'email', 'account', 'name', 'login'}
        if key not in valid_keys:
            return
        if key == 'email' and '@' not in val:
            return
        if key != 'email' and len(val) < 2:
            return

        pkey = (src_ip, dst_ip, protocol)
        self._pending_creds.setdefault(pkey, {'username': '', 'password': ''})
        self._pending_creds[pkey]['username'] = val

    def set_login_password(self, *, src_ip, dst_ip, protocol, password):
        pkey = (src_ip, dst_ip, protocol)
        self._pending_creds.setdefault(pkey, {'username': '', 'password': ''})
        self._pending_creds[pkey]['password'] = password

        pending = self._pending_creds[pkey]
        if pending['password']:
            self._commit_login(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                username=pending['username'],
                password=pending['password'],
                successful=False,
            )
            self._pending_creds[pkey] = {'username': '', 'password': ''}

    def add_login(self, *, username, password, src_ip, dst_ip, protocol, successful=False):
        self._commit_login(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            username=username,
            password=password,
            successful=successful,
        )

    def _commit_login(self, *, src_ip, dst_ip, protocol, username, password, successful):
        if password is None or password == '':
            password_hash = ''
        else:
            password_hash = hashlib.sha256(str(password).encode('utf-8')).hexdigest()
        
        key = (src_ip, dst_ip, protocol, username, password)
        ckey = (src_ip, dst_ip, protocol)

        if key in self.login_attempts:
            self.login_attempts[key]['count'] += 1
            if successful:
                self.login_attempts[key]['successful'] = True
        else:
            self.login_attempts[key] = {
                'username': username,
                'password': password_hash,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'count': 1,
                'successful': successful,
            }
        self._last_committed[ckey] = key

    def mark_login_successful(self, *, src_ip, dst_ip, protocol):
        ckey = (src_ip, dst_ip, protocol)
        pending = self._pending_creds.get(ckey)

        if pending and (pending['username'] or pending['password']):
            self._commit_login(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                username=pending['username'],
                password=pending['password'],
                successful=True,
            )
            self._pending_creds[ckey] = {'username': '', 'password': ''}
            return

        last_key = self._last_committed.get(ckey)
        if last_key and last_key in self.login_attempts:
            self.login_attempts[last_key]['successful'] = True

    def mark_login_failed(self, *, src_ip, dst_ip, protocol):
        ckey = (src_ip, dst_ip, protocol)
        pending = self._pending_creds.get(ckey)
        if pending and (pending['username'] or pending['password']):
            self._commit_login(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                username=pending['username'],
                password=pending['password'],
                successful=False,
            )
            self._pending_creds[ckey] = {'username': '', 'password': ''}

    # ── network_traffic ───────────────────────────────────────────────────────

    def add_traffic(self, *, src_ip, dst_ip, url=''):
        """Record one source-to-destination/url connection.

        Tags are intentionally not accepted here. The CSV export always uses
        only the fixed tag ``socket connect, benign`` plus an optional device
        tag based on the source IP. ``threat`` is always exported as ``none``.
        """
        destination = url if url else dst_ip
        key = (src_ip, destination)

        if key not in self.network_traffic:
            self.network_traffic[key] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'count': 0,
                'url': destination,
                'threat': 'none',
            }

        entry = self.network_traffic[key]
        entry['count'] += 1

        # Keep dst_ip/url populated if the first packet had less context.
        if dst_ip and not entry.get('dst_ip'):
            entry['dst_ip'] = dst_ip
        if url and not entry.get('url'):
            entry['url'] = url

        # Required fixed value. Do not overwrite this with protocol/threat data.
        entry['threat'] = 'none'

    def get_traffic_rows(self) -> list[dict]:
        device_map = {
            '10.42.0.170': 'homeassistant',
            '10.42.0.1': 'router',
            '10.42.0.39': 'smartphone',
            '10.42.0.141': 'camera',
            '10.42.0.228': 'panel',
            '10.42.0.24': 'socket',
            '10.42.0.169': 'laptop',
            '192.168.0.77': 'bridge',
        }

        rows = []
        for entry in self.network_traffic.values():
            tags = ['routine, benign']
            device_tag = device_map.get(entry['src_ip'])
            if device_tag:
                tags.append(device_tag)

            rows.append({
                'src_ip': entry['src_ip'],
                'count': entry['count'],
                'url': entry['url'],
                'threat': 'none',
                'tags': ', '.join(tags),
            })
        return rows


class FlowTracker:
    """Tracks network flows and extracts login attempts plus basic traffic data."""

    def __init__(self, flow_timeout=120):
        self.flows: dict[tuple, dict] = {}
        self.flow_timeout = flow_timeout
        self.last_cleanup = time.time()
        self.indicators = IndicatorStore()

    def get_flow_key(self, packet):
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        src_port = dst_port = 0

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol), 'forward'
        return (dst_ip, src_ip, dst_port, src_port, protocol), 'reverse'

    def update_flow(self, packet):
        result = self.get_flow_key(packet)
        if not result:
            return

        flow_key, direction = result
        current_time = time.time()

        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'src_ip': flow_key[0],
                'dst_ip': flow_key[1],
                'src_port': flow_key[2],
                'dst_port': flow_key[3],
                'protocol': flow_key[4],
                'protocol_name': self._get_protocol_name(flow_key[2], flow_key[3], flow_key[4]),
                'bytes_forward': 0,
                'bytes_reverse': 0,
                'packets_forward': 0,
                'packets_reverse': 0,
                'start_time': current_time,
                'last_seen': current_time,
                'tcp_flags_forward': set(),
                'tcp_flags_reverse': set(),
                'first_packet_direction': direction,
            }

        flow = self.flows[flow_key]
        packet_size = len(packet)

        if direction == 'forward':
            flow['bytes_forward'] += packet_size
            flow['packets_forward'] += 1
            if packet.haslayer(TCP):
                flow['tcp_flags_forward'].add(self._get_tcp_flags(packet[TCP]))
        else:
            flow['bytes_reverse'] += packet_size
            flow['packets_reverse'] += 1
            if packet.haslayer(TCP):
                flow['tcp_flags_reverse'].add(self._get_tcp_flags(packet[TCP]))

        flow['last_seen'] = current_time

        # Record basic IP-to-IP traffic even when no payload is available.
        self.indicators.add_traffic(src_ip=packet[IP].src, dst_ip=packet[IP].dst)

        if packet.haslayer(Raw):
            self._analyse_payload(packet, flow, bytes(packet[Raw]), direction)

        if packet.haslayer(DNS):
            self._analyse_dns(packet)

        if current_time - self.last_cleanup > 60:
            self.cleanup_inactive_flows()

    def _analyse_payload(self, packet, flow, payload: bytes, direction: str):
        if direction == 'forward':
            real_src = flow['src_ip']
            real_dst = flow['dst_ip']
            real_dport = flow['dst_port']
            real_sport = flow['src_port']
        else:
            real_src = flow['dst_ip']
            real_dst = flow['src_ip']
            real_dport = flow['src_port']
            real_sport = flow['dst_port']

        self._analyse_http_request(payload, real_src, real_dst)

        if real_sport in (80, 8080, 8123, 8888) or real_dport in (80, 8080, 8123, 8888):
            self._analyse_http_response(payload, real_src, real_dst)

        if real_dport == 21 or real_sport == 21:
            self._analyse_ftp(payload, real_src, real_dst, is_response=(real_sport == 21))

        if real_dport == 23 or real_sport == 23:
            self._analyse_telnet(payload, real_src, real_dst, is_response=(real_sport == 23))

        if real_dport in (25, 587) or real_sport in (25, 587):
            self._analyse_smtp(payload, real_src, real_dst, is_response=(real_sport in (25, 587)))

        if real_dport == 110 or real_sport == 110:
            self._analyse_pop3(payload, real_src, real_dst, is_response=(real_sport == 110))

        if real_dport == 143 or real_sport == 143:
            self._analyse_imap(payload, real_src, real_dst, is_response=(real_sport == 143))

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _analyse_http_request(self, payload: bytes, src_ip: str, dst_ip: str):
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            return

        for req_match in re.finditer(
            r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP',
            text,
            re.MULTILINE,
        ):
            method = req_match.group(1)
            path = req_match.group(2)
            block_start = req_match.start()
            block_end = text.find('\r\n\r\n', block_start)
            block = text[block_start:block_end] if block_end != -1 else text[block_start:]

            host_match = re.search(r'(?i)^Host:\s*([^\r\n]+)', block, re.MULTILINE)
            host = host_match.group(1).strip() if host_match else dst_ip
            url = f'http://{host}{path}'
            self.indicators.add_traffic(src_ip=src_ip, dst_ip=dst_ip, url=url)

            auth_match = re.search(r'(?i)^Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', block, re.MULTILINE)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode('utf-8', errors='replace')
                    if ':' in decoded:
                        user, pwd = decoded.split(':', 1)
                        self.indicators.add_login(
                            username=user,
                            password=pwd,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol='HTTP-Basic',
                            successful=False,
                        )
                except Exception:
                    pass

            if method == 'POST':
                body_start = text.find('\r\n\r\n', block_start)
                if body_start != -1:
                    body = text[body_start + 4:]
                    next_req = re.search(r'\r\n(GET|POST|PUT|DELETE)', body)
                    if next_req:
                        body = body[:next_req.start()]
                    self._parse_form_credentials(body, src_ip, dst_ip, 'HTTP-Form')

    def _analyse_http_response(self, payload: bytes, src_ip: str, dst_ip: str):
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            return

        status_match = re.match(r'HTTP/\d\.\d\s+(\d{3})', text)
        if not status_match:
            return

        status = int(status_match.group(1))
        header_text, _, _ = text.partition('\r\n\r\n')
        location_match = re.search(r'(?i)^Location:\s*([^\r\n]+)', header_text, re.MULTILINE)
        location = location_match.group(1).lower() if location_match else ''

        failure_patterns = [
            r'invalid password', r'incorrect password', r'login failed',
            r'authentication failed', r'access denied', r'bad credentials',
        ]
        has_failure_text = any(re.search(pattern, text, re.IGNORECASE) for pattern in failure_patterns)
        redirect_back_to_login = any(keyword in location for keyword in ['/login', '/signin', '/auth'])

        has_session_cookie = re.search(
            r'(?i)^Set-Cookie:\s*[^\r\n]*(session|sid|auth|token|jwt)',
            header_text,
            re.MULTILINE,
        )
        redirect_to_success_page = any(
            keyword in location
            for keyword in ['/dashboard', '/home', '/account', '/profile', '/admin']
        )

        if status in (401, 403) or has_failure_text or redirect_back_to_login:
            self.indicators.mark_login_failed(src_ip=dst_ip, dst_ip=src_ip, protocol='HTTP-Form')
            self.indicators.mark_login_failed(src_ip=dst_ip, dst_ip=src_ip, protocol='HTTP-Basic')
            return

        if has_session_cookie or redirect_to_success_page:
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='HTTP-Form')
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='HTTP-Basic')

    # ── FTP / Telnet / Mail protocols ─────────────────────────────────────────

    def _analyse_ftp(self, payload: bytes, src_ip: str, dst_ip: str, is_response: bool):
        try:
            text = payload.decode('utf-8', errors='replace').strip()
        except Exception:
            return

        if not is_response:
            user_match = re.match(r'(?i)USER\s+(\S+)', text)
            pass_match = re.match(r'(?i)PASS\s+(\S+)', text)
            if user_match:
                self.indicators.set_login_username(src_ip=src_ip, dst_ip=dst_ip, protocol='FTP', username=user_match.group(1))
            if pass_match:
                self.indicators.set_login_password(src_ip=src_ip, dst_ip=dst_ip, protocol='FTP', password=pass_match.group(1))
        elif re.match(r'^230[\s-]', text):
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='FTP')

    def _analyse_telnet(self, payload: bytes, src_ip: str, dst_ip: str, is_response: bool):
        clean = re.sub(b'\xff[\xfb-\xff].', b'', payload)
        try:
            text = clean.decode('utf-8', errors='replace').strip()
        except Exception:
            return

        if not is_response:
            user_match = re.search(r'(?i)(?:login|username):\s*(\S+)', text)
            pass_match = re.search(r'(?i)password:\s*(\S+)', text)
            if user_match:
                self.indicators.set_login_username(src_ip=src_ip, dst_ip=dst_ip, protocol='Telnet', username=user_match.group(1))
            if pass_match:
                self.indicators.set_login_password(src_ip=src_ip, dst_ip=dst_ip, protocol='Telnet', password=pass_match.group(1))
        else:
            shell_prompt = re.search(r'[\$#>]\s*$', text)
            login_fail = re.search(r'(?i)(login incorrect|authentication failed|invalid password|access denied)', text)
            if shell_prompt and not login_fail:
                self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='Telnet')

    def _analyse_smtp(self, payload: bytes, src_ip: str, dst_ip: str, is_response: bool):
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            return

        if not is_response:
            auth_login = re.search(r'(?i)AUTH\s+LOGIN\r?\n([A-Za-z0-9+/=]+)\r?\n([A-Za-z0-9+/=]+)', text)
            if auth_login:
                try:
                    user = base64.b64decode(auth_login.group(1)).decode('utf-8', errors='replace')
                    pwd = base64.b64decode(auth_login.group(2)).decode('utf-8', errors='replace')
                    self.indicators.add_login(username=user, password=pwd, src_ip=src_ip, dst_ip=dst_ip, protocol='SMTP')
                except Exception:
                    pass

            auth_plain = re.search(r'(?i)AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)', text)
            if auth_plain:
                try:
                    decoded = base64.b64decode(auth_plain.group(1)).decode('utf-8', errors='replace')
                    parts = decoded.split('\x00')
                    if len(parts) >= 3:
                        self.indicators.add_login(username=parts[1], password=parts[2], src_ip=src_ip, dst_ip=dst_ip, protocol='SMTP')
                except Exception:
                    pass

            oauth_match = re.search(r'(?i)AUTH\s+(?:XOAUTH2|OAUTHBEARER)\s+([A-Za-z0-9+/=]+)', text)
            if oauth_match:
                try:
                    blob = base64.b64decode(oauth_match.group(1)).decode('utf-8', errors='replace')
                    u_match = re.search(r'user=([^\x01]+)', blob)
                    if u_match:
                        self.indicators.add_login(username=u_match.group(1), password='(oauth)', src_ip=src_ip, dst_ip=dst_ip, protocol='SMTP-OAuth')
                except Exception:
                    pass
        elif re.match(r'^235[\s-]', text):
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='SMTP')
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='SMTP-OAuth')

    def _analyse_pop3(self, payload: bytes, src_ip: str, dst_ip: str, is_response: bool):
        try:
            text = payload.decode('utf-8', errors='replace').strip()
        except Exception:
            return

        if not is_response:
            user_match = re.match(r'(?i)USER\s+(\S+)', text)
            pass_match = re.match(r'(?i)PASS\s+(\S+)', text)
            if user_match:
                self.indicators.set_login_username(src_ip=src_ip, dst_ip=dst_ip, protocol='POP3', username=user_match.group(1))
            if pass_match:
                self.indicators.set_login_password(src_ip=src_ip, dst_ip=dst_ip, protocol='POP3', password=pass_match.group(1))
        elif re.match(r'^\+OK', text):
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='POP3')

    def _analyse_imap(self, payload: bytes, src_ip: str, dst_ip: str, is_response: bool):
        try:
            text = payload.decode('utf-8', errors='replace').strip()
        except Exception:
            return

        if not is_response:
            auth_plain = re.search(r'(?i)AUTHENTICATE\s+PLAIN\s+([A-Za-z0-9+/=]+)', text)
            if auth_plain:
                try:
                    decoded = base64.b64decode(auth_plain.group(1)).decode('utf-8', errors='replace')
                    parts = decoded.split('\x00')
                    if len(parts) >= 3:
                        self.indicators.add_login(username=parts[1], password=parts[2], src_ip=src_ip, dst_ip=dst_ip, protocol='IMAP')
                except Exception:
                    pass

            login_cmd = re.search(r'(?i)\w+\s+LOGIN\s+"?(\S+?)"?\s+"?(\S+?)"?\s*$', text)
            if login_cmd:
                self.indicators.add_login(username=login_cmd.group(1), password=login_cmd.group(2), src_ip=src_ip, dst_ip=dst_ip, protocol='IMAP')
        elif re.search(r'(?i)\bOK\b.*(LOGIN|AUTHENTICATE)', text):
            self.indicators.mark_login_successful(src_ip=dst_ip, dst_ip=src_ip, protocol='IMAP')

    # ── DNS / form parsing ────────────────────────────────────────────────────

    def _analyse_dns(self, packet):
        if not packet.haslayer(IP):
            return
        if packet[DNS].qr == 0 and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode('utf-8', errors='replace').rstrip('.')
            self.indicators.add_traffic(src_ip=packet[IP].src, dst_ip=packet[IP].dst, url=qname)

    def _parse_form_credentials(self, body: str, src_ip: str, dst_ip: str, protocol: str):
        user_fields = ['username', 'user', 'login', 'email', 'uname', 'uid', 'name', 'log', 'j_username', 'user_name']
        pass_fields = ['password', 'pass', 'passwd', 'pwd', 'secret', 'j_password', 'wppassword']
        params = parse_qs(body)

        user = ''
        pwd = ''
        for k, v in params.items():
            key = k.lower()
            if any(field in key for field in user_fields) and v:
                user = v[0]
            elif any(field in key for field in pass_fields) and v:
                pwd = v[0]

        if user and pwd:
            self.indicators.add_login(username=user, password=pwd, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)

    # ── utilities / cleanup / export ──────────────────────────────────────────

    def _get_protocol_name(self, src_port: int, dst_port: int, proto_num: int) -> str:
        for port in (dst_port, src_port):
            if port in PROTOCOL_PORTS:
                return PROTOCOL_PORTS[port]
        return {1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH'}.get(proto_num, f'PROTO_{proto_num}')

    @staticmethod
    def _get_tcp_flags(tcp_layer) -> str:
        flags = []
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.U:
            flags.append('URG')
        if tcp_layer.flags.E:
            flags.append('ECE')
        if tcp_layer.flags.C:
            flags.append('CWR')
        return '|'.join(flags) if flags else 'NONE'

    def cleanup_inactive_flows(self):
        current_time = time.time()
        inactive = [key for key, flow in self.flows.items() if current_time - flow['last_seen'] > self.flow_timeout]
        for key in inactive:
            del self.flows[key]
        self.last_cleanup = current_time
        if inactive:
            print(f'Cleaned up {len(inactive)} inactive flows')

    def get_all_flows(self) -> list[dict]:
        rows = []
        for flow in self.flows.values():
            duration = max(flow['last_seen'] - flow['start_time'], 0)
            total_bytes = flow['bytes_forward'] + flow['bytes_reverse']
            total_packets = flow['packets_forward'] + flow['packets_reverse']
            rows.append({
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'protocol_name': flow['protocol_name'],
                'bytes_sent': flow['bytes_forward'],
                'bytes_received': flow['bytes_reverse'],
                'total_bytes': total_bytes,
                'packets_sent': flow['packets_forward'],
                'packets_received': flow['packets_reverse'],
                'total_packets': total_packets,
                'duration_seconds': round(duration, 2),
                'start_time': datetime.fromtimestamp(flow['start_time']).isoformat(),
                'last_seen': datetime.fromtimestamp(flow['last_seen']).isoformat(),
                'tcp_flags_forward': '|'.join(flow['tcp_flags_forward']) if flow['tcp_flags_forward'] else 'N/A',
                'tcp_flags_reverse': '|'.join(flow['tcp_flags_reverse']) if flow['tcp_flags_reverse'] else 'N/A',
                'direction': flow['first_packet_direction'],
                'bytes_per_second': round(total_bytes / duration, 2) if duration > 0 else 0,
                'packets_per_second': round(total_packets / duration, 2) if duration > 0 else 0,
            })
        return rows
