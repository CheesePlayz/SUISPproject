from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import re
from config import *  # importamo konstante

class PacketAnalyzer:
    def __init__(self):
        # Initialize counters and tracking dictionaries
        self.ip_counts = defaultdict(int)  # Track IP addresses frequency
        self.port_scans = defaultdict(set)  # Track port scanning attempts
        self.syn_floods = defaultdict(int)  # Track SYN flood attempts
        self.login_attempts = defaultdict(list)  # Track login attempts for brute force detection
        self.sql_attempts = defaultdict(int)  # Track potential SQL injection attempts

        self.last_cleanup = datetime.now()
        self.cleanup_interval = timedelta(minutes=5)

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='network_security.log'
        )
        self.logger = logging.getLogger(__name__)

        # SQL injection patterns
        self.sql_patterns = [
            r"('\s*OR\s*'1'\s*=\s*'1)", # OR 1=1
            r"('\s*OR\s*'1'\s*=\s*'1\s*--)", # OR 1=1--
            r"(?i)(UNION\s+SELECT\s+)", # UNION SELECT
            r"(?i)(SELECT\s+.*\s+FROM\s+)", # Basic SELECT
            r"(?i)(DROP\s+TABLE)", # DROP TABLE
            r"(?i)(DELETE\s+FROM)", # DELETE FROM
            r"(?i)(/\*.*\*/)", # SQL comments
            r"(?i)(EXEC\s+xp_)", # SQL Server stored procedures
            r"(?i)(INTO\s+OUTFILE)", # MySQL file operations
            r"--;", # SQL comment
        ]

    def analyze_packet(self, packet):
        """Analyze a single packet for potential security threats."""
        current_time = datetime.now()

        # Periodic cleanup of tracking dictionaries
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_tracking_data()
            self.last_cleanup = current_time

        # Extract basic packet information
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return None

        # Run security checks
        threats = []

        # Check for potential DDoS
        if self._check_ddos(packet_info):
            threats.append({
                "type": "DDoS",
                "severity": "High",
                "details": f"High traffic from {packet_info['src_ip']}"
            })

        # Check for port scanning
        if self._check_port_scanning(packet_info):
            threats.append({
                "type": "Port Scan",
                "severity": "Medium",
                "details": f"Multiple ports accessed from {packet_info['src_ip']}"
            })

        # Check for SQL injection attempts
        sql_threat = self._check_sql_injection(packet)
        if sql_threat:
            threats.append(sql_threat)

        # Check for brute force attempts
        brute_force = self._check_brute_force(packet_info)
        if brute_force:
            threats.append(brute_force)

        # Log threats if found
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
        """Check for SQL injection patterns in HTTP traffic."""
        if TCP not in packet or not packet[TCP].payload:
            return None

        payload = str(packet[TCP].payload).lower()

        # Check for HTTP traffic (common ports 80, 443, 8080)
        if packet[TCP].dport not in [80, 443, 8080]:
            return None

        # Check for SQL injection patterns
        for pattern in self.sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                self.sql_attempts[packet[IP].src] += 1
                return {
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "details": f"Potential SQL injection attempt from {packet[IP].src}",
                    "pattern_matched": pattern
                }

        return None

    def _check_brute_force(self, packet_info):
        """Check for potential brute force login attempts."""
        if packet_info["protocol"] != "TCP":
            return None

        # Common authentication ports (SSH:22, FTP:21, HTTP:80, HTTPS:443)
        auth_ports = [21, 22, 80, 443, 8080]

        if packet_info["dst_port"] not in auth_ports:
            return None

        src_ip = packet_info["src_ip"]
        current_time = packet_info["timestamp"]

        # Track login attempts
        self.login_attempts[src_ip].append(current_time)

        # Remove attempts older than 5 minutes
        recent_attempts = [
            attempt for attempt in self.login_attempts[src_ip]
            if current_time - attempt <= timedelta(minutes=5)
        ]
        self.login_attempts[src_ip] = recent_attempts

        # Alert if more than 10 attempts in 5 minutes
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

        # Clean up old login attempts
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