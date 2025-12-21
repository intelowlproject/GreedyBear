import re
from typing import Any
from urllib.parse import urlparse

from greedybear.regex import REGEX_URL_PROTOCOL


class CowrieSessionData:
    def __init__(self, session_id: str, source_ip: str):
        self.session_id = session_id
        self.source_ip = source_ip
        self.start_time: Any = None
        self.duration: float = 0.0
        self.credentials: list[str] = []
        self.commands: list[str] = []
        self.interaction_count: int = 0
        self.login_attempt: bool = False
        self.command_execution: bool = False
        self.commands_first_seen: Any = None
        self.commands_last_seen: Any = None


class CowrieLogParser:
    def __init__(self, log):
        self.log = log

    def extract_payloads(self, hits: list[dict]) -> list[dict]:
        """
        Extracts payloads from messages.
        Returns a list of dicts: {'source_ip': str, 'payload_url': str, 'payload_hostname': str}
        """
        results = []
        for hit in hits:
            if hit.get("eventid", "") not in ["cowrie.login.failed", "cowrie.session.file_upload"]:
                continue

            message = hit.get("message", "")
            match_url = re.search(REGEX_URL_PROTOCOL, message)
            if match_url:
                payload_url = match_url.group()
                src_ip = hit.get("src_ip")

                try:
                    parsed = urlparse(payload_url)
                    if parsed.hostname:
                        results.append(
                            {
                                "source_ip": src_ip,
                                "payload_url": payload_url,
                                "payload_hostname": parsed.hostname,
                            }
                        )
                except ValueError:
                    self.log.warning(f"Failed to parse URL {payload_url}")
                    continue
        return results

    def extract_downloads(self, hits: list[dict]) -> list[dict]:
        """
        Extracts download attempts.
        Returns list of dicts: {'source_ip': str, 'download_url': str, 'hostname': str}
        """
        results = []
        for hit in hits:
            if hit.get("eventid") != "cowrie.session.file_download":
                continue
            if "url" not in hit:
                continue

            url = str(hit["url"])
            if url:
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname:
                        results.append(
                            {
                                "source_ip": str(hit.get("src_ip")),
                                "download_url": url,
                                "hostname": hostname,
                            }
                        )
                except ValueError:
                    self.log.warning(f"Failed to parse URL {url}")
                    continue
        return results

    def extract_sessions(self, hits: list[dict]) -> dict[str, "CowrieSessionData"]:
        """
        Aggregates hits into sessions.
        Returns Dict[session_id, CowrieSessionData]
        """
        sessions: dict[str, CowrieSessionData] = {}

        # Group hits by session first
        hits_per_session = {}
        for hit in hits:
            sid = hit.get("session")
            if not sid:
                continue
            if sid not in hits_per_session:
                hits_per_session[sid] = []
            hits_per_session[sid].append(hit)

        for sid, session_hits in hits_per_session.items():
            sorted_hits = sorted(session_hits, key=lambda h: h.get("timestamp", ""))

            # Find source IP
            src_ip = None
            for h in sorted_hits:
                if "src_ip" in h:
                    src_ip = h["src_ip"]
                    break

            if not src_ip:
                continue

            session_data = CowrieSessionData(session_id=sid, source_ip=src_ip)

            for hit in sorted_hits:
                eventid = hit.get("eventid")
                timestamp = hit.get("timestamp")

                if eventid == "cowrie.session.connect":
                    session_data.start_time = timestamp

                elif eventid in ["cowrie.login.failed", "cowrie.login.success"]:
                    session_data.login_attempt = True
                    username = hit.get("username", "").replace("\x00", "[NUL]")
                    password = hit.get("password", "").replace("\x00", "[NUL]")
                    session_data.credentials.append(f"{username} | {password}")

                elif eventid == "cowrie.command.input":
                    session_data.command_execution = True
                    if session_data.commands_first_seen is None:
                        session_data.commands_first_seen = timestamp

                    message = hit.get("message", "")
                    if message.startswith("CMD: "):
                        command = message[5:].replace("\x00", "[NUL]")
                    else:
                        command = message.replace("\x00", "[NUL]")

                    session_data.commands.append(command[:1024])
                    session_data.commands_last_seen = timestamp

                elif eventid == "cowrie.session.closed":
                    session_data.duration = hit.get("duration")

                session_data.interaction_count += 1

            sessions[sid] = session_data

        return sessions
