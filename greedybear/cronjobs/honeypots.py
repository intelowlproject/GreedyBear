# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from dataclasses import dataclass


@dataclass
class Honeypot:
    name: str
    description: str = ""
