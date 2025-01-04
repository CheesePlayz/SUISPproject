import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import logging
from threading import Lock
from config import ALERT_COOLDOWN

class AlertSystem:
    def __init__(self, smtp_config):
        """
        Initialize the alert system with SMTP configuration.

        smtp_config should be a dictionary containing:
        - host: SMTP server host
        - port: SMTP server port
        - username: Email username
        - password: Email password
        - from_email: Sender email
        - to_email: Recipient email
        """
        self.smtp_config = smtp_config
        self.alert_history = {}
        self.alert_threshold = timedelta(minutes=ALERT_COOLDOWN)
        self.lock = Lock()

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='alerts.log'
        )
        self.logger = logging.getLogger(__name__)

    def send_alert(self, threat_data, packet_info):
        """Send alert for detected security threat."""
        alert_key = f"{threat_data['type']}_{packet_info['src_ip']}"

        with self.lock:
            if self._should_send_alert(alert_key):
                try:
                    self._send_email_alert(threat_data, packet_info)
                    self.alert_history[alert_key] = datetime.now()
                    self.logger.info(f"Alert sent successfully for {alert_key}")
                except Exception as e:
                    self.logger.error(f"Failed to send alert: {str(e)}")

    def _should_send_alert(self, alert_key):
        """
        Determine if an alert should be sent based on history and threshold.
        Returns True if alert should be sent.
        """
        if alert_key not in self.alert_history:
            return True

        time_since_last = datetime.now() - self.alert_history[alert_key]
        return time_since_last > self.alert_threshold

    def _send_email_alert(self, threat_data, packet_info):
        """Send email alert about security threat."""
        msg = MIMEMultipart()
        msg['From'] = self.smtp_config['from_email']
        msg['To'] = self.smtp_config['to_email']
        msg['Subject'] = f"Security Alert: {threat_data['type']} Detected"

        body = self._create_alert_body(threat_data, packet_info)
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
            server.starttls()
            server.login(self.smtp_config['username'], self.smtp_config['password'])
            server.send_message(msg)

    def _create_alert_body(self, threat_data, packet_info):
        """Create formatted alert message body."""
        return f"""
Security Threat Detected!

Type: {threat_data['type']}
Severity: {threat_data['severity']}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Details: {threat_data['details']}

Network Information:
- Source IP: {packet_info['src_ip']}
- Destination IP: {packet_info['dst_ip']}
- Protocol: {packet_info['protocol']}
- Source Port: {packet_info['src_port']}
- Destination Port: {packet_info['dst_port']}

This is an automated security alert. Please investigate immediately if this activity is unauthorized.
        """

    def cleanup_old_alerts(self):
        """Clean up old alerts from history."""
        with self.lock:
            current_time = datetime.now()
            self.alert_history = {
                key: time for key, time in self.alert_history.items()
                if current_time - time <= self.alert_threshold
            }