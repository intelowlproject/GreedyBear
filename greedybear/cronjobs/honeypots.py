from dataclasses import dataclass


@dataclass
class Honeypot:
    name: str
    description: str = ""
