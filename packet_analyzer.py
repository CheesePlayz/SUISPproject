from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import re
from config import *

class PacketAnalyzer:
    def __init__(self):
        self.ip_counts = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.sql_attempts = defaultdict(lambda: {'count': 0, 'last_seen': None})
        self.login_attempts = defaultdict(list)
        self.last_cleanup = datetime.now()
        self.cleanup_interval = timedelta(minutes=5)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='network_security.log'
        )
        self.logger = logging.getLogger(__name__)

        self.sql_patterns = [
            rb"SELECT.*FROM",
            rb"UNION.*SELECT",
            rb"DROP.*TABLE",
            rb"DELETE.*FROM",
            rb"INSERT.*INTO",
            rb"UPDATE.*SET",
            rb"EXEC.*sp_",
            rb"xp_cmdshell",
            rb"'.*OR.*'1'.*='1",
            rb"--.*",
            rb";.*",
            rb"/*.**/",
            rb"WAITFOR.*DELAY",
            rb"BENCHMARK\(",
            rb"SLEEP\("
        ]

    def analyze_packet(self, packet):
        """Analyze a single packet for potential security threats."""
        current_time = datetime.now()

        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_tracking_data()
            self.last_cleanup = current_time

        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return None

        threats = []

        if self._check_ddos(packet_info):
            threats.append({
                "type": "DDoS",
                "severity": "High",
                "details": f"High traffic from {packet_info['src_ip']}"
            })

        if self._check_port_scanning(packet_info):
            threats.append({
                "type": "Port Scan",
                "severity": "Medium",
                "details": f"Multiple ports accessed from {packet_info['src_ip']}"
            })

        sql_threat = self._check_sql_injection(packet)
        if sql_threat:
            threats.append(sql_threat)

        brute_force = self._check_brute_force(packet_info)
        if brute_force:
            threats.append(brute_force)

        if threats:
            self._log_threats(packet_info, threats)

        return {
            "packet_info": packet_info,
            "threats": threats
        }

    def _extract_packet_info(self, packet):
        """Extract relevant information from the packet."""
        if IP not in packet:
            return None

        packet_info = {
            "timestamp": datetime.now(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "flags": None,
            "payload": None
        }

        if TCP in packet:
            packet_info.update({
                "protocol": "TCP",
                "src_port": packet[TCP].sport,
                "dst_port": packet[TCP].dport,
                "flags": packet[TCP].flags,
                "payload": str(packet[TCP].payload) if packet[TCP].payload else None
            })
        elif UDP in packet:
            packet_info.update({
                "protocol": "UDP",
                "src_port": packet[UDP].sport,
                "dst_port": packet[UDP].dport,
                "payload": str(packet[UDP].payload) if packet[UDP].payload else None
            })
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"

        return packet_info

    def _check_sql_injection(self, packet):
        """Check for SQL injection patterns."""
        if TCP not in packet:
            return None

        try:
            raw_payload = bytes(packet[TCP].payload)

            for pattern in self.sql_patterns:
                if re.search(pattern, raw_payload, re.IGNORECASE):
                    src_ip = packet[IP].src
                    current_time = datetime.now()

                    if self.sql_attempts[src_ip]['last_seen']:
                        time_diff = current_time - self.sql_attempts[src_ip]['last_seen']
                        if time_diff.total_seconds() < 60:
                            self.sql_attempts[src_ip]['count'] += 1
                    else:
                        self.sql_attempts[src_ip]['count'] = 1

                    self.sql_attempts[src_ip]['last_seen'] = current_time

                    if self.sql_attempts[src_ip]['count'] >= 3:
                        return {
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "details": f"Multiple SQL patterns detected from {src_ip}",
                            "additional_info": {
                                "attempts_count": self.sql_attempts[src_ip]['count'],
                                "detected_pattern": pattern.decode('utf-8', errors='ignore'),
                                "time_window": "5 minutes",
                                "port": packet[TCP].dport
                            }
                        }

        except Exception as e:
            self.logger.error(f"Error in SQL injection check: {e}")

        return None

    def _check_brute_force(self, packet_info):
        """Check for potential brute force login attempts."""
        if packet_info["protocol"] != "TCP":
            return None

        auth_ports = [21, 22, 80, 443, 8080]

        if packet_info["dst_port"] not in auth_ports:
            return None

        src_ip = packet_info["src_ip"]
        current_time = packet_info["timestamp"]

        self.login_attempts[src_ip].append(current_time)

        recent_attempts = [
            attempt for attempt in self.login_attempts[src_ip]
            if current_time - attempt <= timedelta(minutes=5)
        ]
        self.login_attempts[src_ip] = recent_attempts

        if len(recent_attempts) > 10:
            return {
                "type": "Brute Force",
                "severity": "High",
                "details": f"Multiple login attempts from {src_ip} ({len(recent_attempts)} attempts in 5 minutes)"
            }

        return None

    def _check_ddos(self, packet_info):
        """Check for potential DDoS attacks."""
        src_ip = packet_info["src_ip"]
        self.ip_counts[src_ip] += 1
        return self.ip_counts[src_ip] > DDOS_THRESHOLD

    def _check_port_scanning(self, packet_info):
        """Check for potential port scanning activity."""
        if packet_info["protocol"] not in ("TCP", "UDP"):
            return False

        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]
        self.port_scans[src_ip].add(dst_port)
        return len(self.port_scans[src_ip]) > PORT_SCAN_THRESHOLD

    def _cleanup_tracking_data(self):
        """Clean up old tracking data."""
        self.ip_counts.clear()
        self.port_scans.clear()
        self.syn_floods.clear()
        self.sql_attempts.clear()

        current_time = datetime.now()
        for ip in list(self.login_attempts.keys()):
            recent_attempts = [
                attempt for attempt in self.login_attempts[ip]
                if current_time - attempt <= timedelta(minutes=5)
            ]
            if recent_attempts:
                self.login_attempts[ip] = recent_attempts
            else:
                del self.login_attempts[ip]

    def _log_threats(self, packet_info, threats):
        """Log detected security threats."""
        for threat in threats:
            self.logger.warning(
                f"Security threat detected - Type: {threat['type']}, "
                f"Severity: {threat['severity']}, "
                f"Source IP: {packet_info['src_ip']}, "
                f"Destination IP: {packet_info['dst_ip']}, "
                f"Details: {threat['details']}"
            )