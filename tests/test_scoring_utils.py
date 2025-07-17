from datetime import datetime

import pandas as pd
from greedybear.cronjobs.scoring.utils import correlated_features, date_delta, get_current_data, get_features, multi_label_encode

from . import CustomTestCase

SAMPLE_DATA = pd.DataFrame(
    {
        "interactions_on_eval_day": [0, 1, 2, 0, 3],
        "feature1": [1, 2, 3, 4, 5],
        "feature2": [0.1, 0.2, 0.3, 0.4, 0.5],
        "feature3": [122, 12, 0, 14, 87],
        "multi_val_feature": ["A,B", "B,C", "A", "C", "A,B,C"],
    }
)


class TestCorrelatedFeatures(CustomTestCase):
    def test_with_sample_data(self):
        """Test with sample data"""
        high_corr_pairs = correlated_features(SAMPLE_DATA.select_dtypes(include="number"))
        self.assertEqual(len(high_corr_pairs), 1)
        self.assertEqual(high_corr_pairs[0], ("feature1", "feature2", 1.0))


class TestDateDelta(CustomTestCase):
    def test_positive_delta(self):
        """Test dates with positive difference"""
        self.assertEqual(date_delta("2024-01-01", "2024-01-02"), 1)
        self.assertEqual(date_delta("2024-01-01", "2024-02-01"), 31)
        self.assertEqual(date_delta("2023-12-31", "2024-01-01"), 1)

    def test_zero_delta(self):
        """Test identical dates"""
        self.assertEqual(date_delta("2024-01-01", "2024-01-01"), 0)

    def test_negative_delta(self):
        """Test dates with negative difference"""
        self.assertEqual(date_delta("2024-01-02", "2024-01-01"), -1)
        self.assertEqual(date_delta("2024-02-01", "2024-01-01"), -31)

    def test_leap_year(self):
        """Test dates across leap year February"""
        self.assertEqual(date_delta("2024-02-28", "2024-02-29"), 1)  # 2024 is leap year
        self.assertEqual(date_delta("2024-02-01", "2024-03-01"), 29)  # February 2024 has 29 days
        self.assertEqual(date_delta("2023-02-01", "2023-03-01"), 28)  # February 2023 has 28 days

    def test_long_range(self):
        """Test dates with multi-year difference"""
        self.assertEqual(date_delta("2020-01-01", "2024-01-01"), 1461)  # Includes leap year 2020
        self.assertEqual(date_delta("1999-12-31", "2000-01-01"), 1)

    def test_invalid_format(self):
        """Test invalid date formats"""
        with self.assertRaises(ValueError):
            date_delta("2024/01/01", "2024-01-02")  # Wrong separator
        with self.assertRaises(ValueError):
            date_delta("2024-1-1", "2024-01-02")  # Missing leading zeros
        with self.assertRaises(ValueError):
            date_delta("24-01-01", "2024-01-02")  # Two-digit year
        with self.assertRaises(ValueError):
            date_delta("2024-13-01", "2024-01-02")  # Invalid month
        with self.assertRaises(ValueError):
            date_delta("2024-01-32", "2024-01-02")  # Invalid day
        with self.assertRaises(ValueError):
            date_delta("invalid", "2024-01-02")  # Not a date string

    def test_edge_dates(self):
        """Test edge cases for valid dates"""
        self.assertEqual(date_delta("0001-01-01", "0001-01-02"), 1)  # Minimum valid year
        self.assertEqual(date_delta("9999-12-30", "9999-12-31"), 1)  # Maximum valid year
        self.assertEqual(date_delta("2024-01-31", "2024-02-01"), 1)  # Month boundary
        self.assertEqual(date_delta("2024-12-31", "2025-01-01"), 1)  # Year boundary


class TestFeatExtraction(CustomTestCase):
    def test_data_retrieval(self):
        """Test with sample IoCs"""
        data = get_current_data()
        self.assertEqual(len(data), 2)

    def test_feature_extraction(self):
        """Test with sample IoCs"""
        today = datetime.now().strftime("%Y-%m-%d")
        data = get_current_data()
        features = get_features(data, today).to_dict("records")
        for feature in features:
            self.assertEqual(feature["attack_count"], 1)
            self.assertEqual(feature["last_seen"], today)
            self.assertEqual(feature["first_seen"], today)
            self.assertEqual(len(feature["days_seen"]), 1)
            self.assertEqual(str(feature["days_seen"][0]), today)
            self.assertEqual(feature["asn"], "12345")
            self.assertEqual(set(feature["honeypots"]), set(["heralding", "ciscoasa", "log4j", "cowrie"]))
            self.assertEqual(feature["honeypot_count"], 4)
            self.assertEqual(feature["destination_port_count"], 3)
            self.assertEqual(feature["days_seen_count"], 1)
            self.assertEqual(feature["active_timespan"], 1)
            self.assertEqual(feature["active_days_ratio"], 1)
            self.assertEqual(feature["login_attempts"], 1)
            self.assertEqual(feature["login_attempts_per_day"], 1)
            self.assertEqual(feature["interaction_count"], 1)
            self.assertEqual(feature["interactions_per_day"], 1)
            self.assertEqual(feature["avg_days_between"], 1)
            self.assertEqual(feature["std_days_between"], 0)
            self.assertEqual(feature["days_since_last_seen"], 0)
            self.assertEqual(feature["days_since_first_seen"], 0)


class TestMultiLabelEncode(CustomTestCase):
    def test_multi_label_encode_ioc(self):
        """Test with sample IoCs"""
        today = datetime.now().strftime("%Y-%m-%d")
        data = get_current_data()
        features = get_features(data, today)
        features = multi_label_encode(features, "honeypots").to_dict("records")
        for h in ["heralding", "ciscoasa", "log4j", "cowrie"]:
            self.assertEqual(features[0][f"has_{h}"], 1)

    def test_multi_label_encode_sample(self):
        """Test with sample data"""
        features = multi_label_encode(SAMPLE_DATA, "multi_val_feature").to_dict("records")
        for idx, feat in enumerate(SAMPLE_DATA["multi_val_feature"]):
            for f in ["A", "B", "C"]:
                self.assertEqual(features[idx][f"has_{f}"], f in feat)
