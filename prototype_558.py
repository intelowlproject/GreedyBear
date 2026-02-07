#!/usr/bin/env python3
import os
import json
import hashlib
from datetime import datetime

class DionaeaPayloadScanner:
    def __init__(self, tpot_data_path="./mock_tpotce_data"):
        self.tpot_path = tpot_data_path
        self.payloads = []
    
    def create_mock_data(self):
        os.makedirs(self.tpot_path + "/dionaea/binaries", exist_ok=True)
        with open(self.tpot_path + "/dionaea/binaries/malware.bin", 'wb') as f:
            f.write(b'\xDE\xAD\xBE\xEF')
    
    def scan_payloads(self):
        self.create_mock_data()
        for root, _, files in os.walk(self.tpot_path):
            for file in files:
                if file.endswith('.bin'):
                    filepath = os.path.join(root, file)
                    stat = os.stat(filepath)
                    with open(filepath, 'rb') as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                    
                    self.payloads.append({
                        'path': filepath,
                        'sha256': sha256,
                        'size_bytes': stat.st_size,
                        'ioc_type': 'dionaea_payload'
                    })
        return self.payloads
    
    def print_feeds(self):
        print("=== GSoC #558: Dionaea Payload Feed ===")
        print(json.dumps(self.payloads, indent=2))
        print(f"\nProcessed {len(self.payloads)} payloads")

if __name__ == "__main__":
    scanner = DionaeaPayloadScanner()
    payloads = scanner.scan_payloads()
    scanner.print_feeds()

