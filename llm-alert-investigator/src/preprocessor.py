"""Alert preprocessor for normalizing and enriching SIEM alerts."""

import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


class AlertPreprocessor:
    """Normalizes and enriches security alerts from various SIEM formats."""

    SEVERITY_MAP = {
        "critical": "critical",
        "crit": "critical",
        "emergency": "critical",
        "high": "high",
        "major": "high",
        "error": "medium",
        "err": "medium",
        "warning": "medium",
        "warn": "medium",
        "low": "low",
        "minor": "low",
        "info": "low",
        "debug": "low",
    }

    COMMON_SUSPICIOUS_PATTERNS = [
        r"powershell.*-enc",
        r"powershell.*-encodedcommand",
        r"invoke-expression",
        r"iex\s",
        r"downloadstring",
        r"downloadfile",
        r"webclient",
        r" certutil.*-urlcache",
        r"bitsadmin",
        r"msiexec.*http",
        r"mshta.*http",
        r"wscript.*http",
        r"cscript.*http",
        r"rundll32.*http",
        r"regsvr32.*http",
        r"cmd.*\/c",
        r"\/bin\/bash",
        r"\/bin\/sh",
        r"nc\s+-e",
        r"ncat\s+-e",
        r"bash\s+-i",
        r"rm\s+-rf",
        r"chmod\s+777",
        r"wget\s+http",
        r"curl\s+http",
    ]

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.COMMON_SUSPICIOUS_PATTERNS
        ]

    def normalize(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Convert various SIEM alert formats to canonical format."""
        normalized = {
            "timestamp": self._extract_timestamp(alert),
            "src_ip": self._extract_ip(alert, ["src_ip", "source_ip", "srcip", "source_address", "ip_src"]),
            "dst_ip": self._extract_ip(alert, ["dst_ip", "dest_ip", "destination_ip", "destip", "ip_dst"]),
            "src_port": self._extract_port(alert, ["src_port", "source_port", "sport", "srcport"]),
            "dst_port": self._extract_port(alert, ["dst_port", "dest_port", "dport", "dstport"]),
            "event_type": self._extract_event_type(alert),
            "process": self._extract_process(alert),
            "command_line": self._extract_command_line(alert),
            "file_hash": self._extract_hash(alert),
            "severity": self._normalize_severity(alert),
            "raw_log": self._extract_raw_log(alert),
            "original_format": self._detect_format(alert),
        }
        return normalized

    def enrich(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Add derived fields and threat intelligence hints to normalized alert."""
        enriched = alert.copy()

        enriched["ioc_hints"] = self._extract_ioc_hints(alert)
        enriched["is_suspicious_command"] = self._check_suspicious_command(
            alert.get("command_line", "")
        )
        enriched["is_lateral_movement"] = self._check_lateral_movement(alert)
        enriched["is_data_exfiltration"] = self._check_data_exfiltration(alert)

        enriched["attack_indicators"] = {
            "has_powershell": bool(re.search(r"powershell", alert.get("command_line", "") or "", re.IGNORECASE)),
            "has_wmi": bool(re.search(r"wmic|winmgmts", alert.get("command_line", "") or "", re.IGNORECASE)),
            "has_scheduled_task": bool(re.search(r"schtasks|at\s|schedule", alert.get("command_line", "") or "", re.IGNORECASE)),
            "has_network_connection": alert.get("dst_ip") is not None and alert.get("dst_port") is not None,
            "has_file_write": bool(re.search(r"echo|copy|move|type|echo\s>", alert.get("command_line", "") or "", re.IGNORECASE)),
            "has_registry_mod": bool(re.search(r"reg\s|regedit", alert.get("command_line", "") or "", re.IGNORECASE)),
        }

        return enriched

    def to_text(self, alert: dict[str, Any]) -> str:
        """Convert normalized alert to text representation for embedding."""
        parts = []

        if alert.get("timestamp"):
            parts.append(f"Time: {alert['timestamp']}")

        if alert.get("event_type"):
            parts.append(f"Event Type: {alert['event_type']}")

        if alert.get("src_ip") and alert.get("dst_ip"):
            parts.append(
                f"Network: {alert['src_ip']}:{alert.get('src_port', 'N/A')} -> {alert['dst_ip']}:{alert.get('dst_port', 'N/A')}"
            )
        elif alert.get("src_ip"):
            parts.append(f"Source IP: {alert['src_ip']}")

        if alert.get("process"):
            parts.append(f"Process: {alert['process']}")

        if alert.get("command_line"):
            parts.append(f"Command: {alert['command_line']}")

        if alert.get("file_hash"):
            parts.append(f"File Hash: {alert['file_hash']}")

        if alert.get("severity"):
            parts.append(f"Severity: {alert['severity']}")

        if alert.get("raw_log"):
            parts.append(f"Raw Log: {alert['raw_log'][:500]}")

        return " | ".join(parts)

    def _extract_timestamp(self, alert: dict[str, Any]) -> str | None:
        """Extract timestamp from various possible fields."""
        timestamp_fields = [
            "timestamp", "time", "datetime", "date", "@timestamp",
            "event_time", "event_timestamp", "generated_time", "_time"
        ]
        for field in timestamp_fields:
            if field in alert:
                value = alert[field]
                if isinstance(value, str):
                    try:
                        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                        return dt.isoformat()
                    except (ValueError, AttributeError):
                        return value
                elif isinstance(value, (int, float)):
                    return datetime.fromtimestamp(value).isoformat()
        return None

    def _extract_ip(
        self, alert: dict[str, Any], fields: list[str]
    ) -> str | None:
        """Extract IP address from possible fields."""
        for field in fields:
            if field in alert and alert[field]:
                ip = str(alert[field]).strip()
                if self._is_valid_ip(ip):
                    return ip
        return None

    def _extract_port(self, alert: dict[str, Any], fields: list[str]) -> int | None:
        """Extract port number from possible fields."""
        for field in fields:
            if field in alert and alert[field]:
                try:
                    port = int(alert[field])
                    if 0 < port <= 65535:
                        return port
                except (ValueError, TypeError):
                    pass
        return None

    def _extract_event_type(self, alert: dict[str, Any]) -> str | None:
        """Extract event type from various possible fields."""
        event_fields = [
            "event_type", "event_type", "event_action", "action",
            "action_type", "operation", "action_name", "rule_name",
            "source_name", "provider"
        ]
        for field in event_fields:
            if field in alert and alert[field]:
                return str(alert[field]).strip()
        return None

    def _extract_process(self, alert: dict[str, Any]) -> str | None:
        """Extract process name from various possible fields."""
        process_fields = [
            "process", "process_name", "process_name_full", "image",
            "file_name", "filename", "executable", "program", "process_path"
        ]
        for field in process_fields:
            if field in alert and alert[field]:
                return str(alert[field]).strip()
        return None

    def _extract_command_line(self, alert: dict[str, Any]) -> str | None:
        """Extract command line from various possible fields."""
        cmd_fields = [
            "command_line", "cmd", "command", "command_line_args",
            "args", "arguments", "params", "parameters"
        ]
        for field in cmd_fields:
            if field in alert and alert[field]:
                return str(alert[field]).strip()
        return None

    def _extract_hash(self, alert: dict[str, Any]) -> str | None:
        """Extract file hash from various possible fields."""
        hash_fields = [
            "file_hash", "hash", "md5", "sha1", "sha256", "file_hash_md5",
            "file_hash_sha1", "file_hash_sha256", "hash_value"
        ]
        for field in hash_fields:
            if field in alert and alert[field]:
                return str(alert[field]).strip()
        return None

    def _normalize_severity(self, alert: dict[str, Any]) -> str:
        """Normalize severity to standard levels."""
        severity_fields = [
            "severity", "priority", "level", "risk", "risk_level", "criticality"
        ]
        for field in severity_fields:
            if field in alert and alert[field]:
                raw = str(alert[field]).lower().strip()
                return self.SEVERITY_MAP.get(raw, "medium")
        return "medium"

    def _extract_raw_log(self, alert: dict[str, Any]) -> str | None:
        """Extract raw log data from alert."""
        raw_fields = ["raw_log", "raw", "log", "message", "msg", "full_log", "_raw"]
        for field in raw_fields:
            if field in alert and alert[field]:
                return str(alert[field]).strip()
        return None

    def _detect_format(self, alert: dict[str, Any]) -> str:
        """Detect the original SIEM format of the alert."""
        if "@timestamp" in alert and "_index" in alert:
            return "elasticsearch"
        elif "_time" in alert and "host" in alert:
            return "splunk"
        elif "id" in alert and "json" in alert.get("version", ""):
            return "chronicle"
        elif "event" in alert and "v" in alert:
            return "azure_sentinel"
        return "unknown"

    def _extract_ioc_hints(self, alert: dict[str, Any]) -> dict[str, list[str]]:
        """Extract Indicators of Compromise from alert."""
        ioc_hints = {
            "urls": [],
            "domains": [],
            "ips": [],
            "file_hashes": [],
        }

        text_content = json.dumps(alert)

        url_pattern = r"https?://[^\s\"'<>]+"
        ioc_hints["urls"] = list(set(re.findall(url_pattern, text_content)))

        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        domains = re.findall(domain_pattern, text_content)
        ioc_hints["domains"] = [
            d for d in set(domains)
            if not d.endswith(".com") and not d.endswith(".org") and len(d) > 4
        ]

        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ips = re.findall(ip_pattern, text_content)
        ioc_hints["ips"] = [ip for ip in set(ips) if self._is_valid_ip(ip)]

        hash_pattern = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
        ioc_hints["file_hashes"] = list(set(re.findall(hash_pattern, text_content)))

        return ioc_hints

    def _check_suspicious_command(self, command_line: str) -> bool:
        """Check if command line contains suspicious patterns."""
        if not command_line:
            return False
        return any(pattern.search(command_line) for pattern in self._compiled_patterns)

    def _check_lateral_movement(self, alert: dict[str, Any]) -> bool:
        """Check if alert indicates lateral movement."""
        cmd = alert.get("command_line", "") or ""
        patterns = [
            r"psexec", r"wmiexec", r"dcomexec", r"smbexec", r"at\s",
            r"schtasks.*\/create", r"remote桌面", r"rdp", r"tscon",
            r"rdesktop", r"xfreerdp"
        ]
        return any(re.search(p, cmd, re.IGNORECASE) for p in patterns)

    def _check_data_exfiltration(self, alert: dict[str, Any]) -> bool:
        """Check if alert indicates potential data exfiltration."""
        cmd = alert.get("command_line", "") or ""
        patterns = [
            r"curl.*-T", r"scp.*:", r"rsync.*remote",
            r"ftp.*put", r"sftp", r"exfil", r"tar.*\.gz.*remote",
            r"dd.*of=/dev/", r"nc\s+.*l.*>", r"base64.*\|.*nc"
        ]
        return any(re.search(p, cmd, re.IGNORECASE) for p in patterns)

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


def load_alerts_from_file(filepath: str) -> list[dict[str, Any]]:
    """Load alerts from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            if "alerts" in data:
                return data["alerts"]
            return [data]
    return []


def batch_preprocess(alerts: list[dict[str, Any]], enrich: bool = True) -> list[dict[str, Any]]:
    """Preprocess a batch of alerts."""
    preprocessor = AlertPreprocessor()
    results = []
    for alert in alerts:
        normalized = preprocessor.normalize(alert)
        if enrich:
            normalized = preprocessor.enrich(normalized)
        results.append(normalized)
    return results