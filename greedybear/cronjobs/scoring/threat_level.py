import json

import numpy as np
import pandas as pd
import requests
from greedybear.cronjobs.scoring.scorer import Scorer

URL = "https://www.spamhaus.org/drop/asndrop.json"
WEIGHTS = {
    "intensity": 0.25,
    "persistence": 0.25,
    "infrastructure": 0.25,
    "breadth": 0.25,
}

SIGMOID_CENTER = 3
LOGIN_NORM_FACTOR = 8

assert sum(WEIGHTS.values()) == 1


def sigmoid(x: float, center: float = 0) -> float:
    """
    Apply the logistic sigmoid function with optional centering to transform input into range (0,1).

    The sigmoid function creates an S-shaped curve that smoothly transitions between 0 and 1,
    with the steepest change around x=center.

    Args:
        x: Input value to be transformed
        center: Value at which the sigmoid function should be centered

    Returns:
        float: Transformed value in range (0,1)
    """
    return 1 / (1 + np.exp(-(x - center)))


class ThreatLevel(Scorer):
    """
    A model for calculating threat scores of IP addresses based on their observed behavior.

    Attributes:
        high_risk_asns (set): Set of ASNs identified as high-risk by Spamhaus
    """

    def __init__(self):
        super().__init__("Threat Level", "threat_level", False)
        self.high_risk_asns = set()

    def fetch_asn_list(self) -> None:
        """
        Fetch and update the set of high-risk ASNs from Spamhaus ASN-DROP list.

        Data source:
        The Spamhaus Project (https://www.spamhaus.org/blocklists/do-not-route-or-peer/)

        Makes an HTTP request to fetch the ASN-DROP list, parses the JSON response
        where each line contains an ASN entry, and updates the instance's high_risk_asns set.
        Failed requests are silently logged without raising exceptions.
        """
        try:
            response = requests.get(URL, timeout=10)
            asn_list = [json.loads(line) for line in response.text.splitlines()]
            self.high_risk_asns = {str(d["asn"]) for d in asn_list if "asn" in d}
        except Exception as e:
            self.log.error(f"failed to fetch ASN-DROP list: {str(e)}")

    def threat_level(self, ioc: pd.Series) -> float:
        """
        Calculate a threat score for an IP address based on its observed behavior.

        The score is calculated as a weighted sum of four components:
        - Intensity: Login attempts per day
        - Persistence: Combination of activity duration and density
        - Infrastructure: Binary score based on presence in Spamhaus ASN-DROP list
        - Breadth: Number of unique ports targeted

        The final score is adjusted by an aging factor that decreases as time since last activity increases.

        Args:
            ioc (pd.Series): Dictionary containing IoC data

        Returns:
            float: Threat score in range [0,1], where higher values indicate greater threat
        """
        scores = {}

        # 1. Intensity Score
        # based on login attempts per day
        # Normalize by log1p and divide by LOGIN_NORM_FACTOR (default: 8):
        # This means the score reaches 1.0 at ~2,980 attempts per day,
        # while 100 attempts/day scores ~0.58 and 10 attempts/day scores ~0.30
        attempts_per_day = ioc["login_attempts"] / ioc["days_seen_count"]
        scores["intensity"] = min(np.log1p(attempts_per_day) / LOGIN_NORM_FACTOR, 1)

        # 2. Persistence Score
        # considers both total days seen and the density of activity
        scores["persistence"] = 0.5 * ioc["active_days_ratio"] + 0.5 * min(ioc["days_seen_count"] / 30, 1)

        # 3. Infrastructure Score
        # ASN rating based on Spamhaus ASN-DROP list
        scores["infrastructure"] = 1 if ioc["asn"] in self.high_risk_asns else 0

        # 4. Breadth Score
        # based on number of destination ports targeted
        # Uses sigmoid centered at SIGMOID_CENTER ports (default: 3):
        # This means 1 port scores ~0.05, 3 ports score 0.5,
        # 5 ports score ~0.95, and the scores asymptotically approach 0 or 1.
        scores["breadth"] = sigmoid(ioc["destination_port_count"], center=SIGMOID_CENTER)

        total_score = sum(scores[s] * weight for s, weight in WEIGHTS.items())

        # Aging factor according to AIP Prioritize New
        aging_factor = 2 / (2 + ioc["days_since_last_seen"])
        return aging_factor * total_score

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        self.log.info(f"calculate {self.score_name} with {self.name}")

        self.fetch_asn_list()
        result_df = df.copy()
        result_df[self.score_name] = df.apply(self.threat_level, axis=1)
        return result_df
