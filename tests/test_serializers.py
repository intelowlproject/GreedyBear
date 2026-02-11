import random
from itertools import product

from rest_framework.serializers import ValidationError

from api.serializers import FeedsRequestSerializer, FeedsResponseSerializer
from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.models import IOC, Honeypot
from tests import CustomTestCase


class FeedsRequestSerializersTestCase(CustomTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.adbhoney = Honeypot.objects.filter(name__iexact="adbhoney").first()
        if not cls.adbhoney:
            cls.adbhoney = Honeypot.objects.create(name="Adbhoney", active=True)

    def test_valid_fields(self):
        choices = {
            "feed_type": ["all", "log4pot", "cowrie", "adbhoney"],
            "attack_type": ["all", "scanner", "payload_request"],
            "ioc_type": ["ip", "domain", "all"],
            "max_age": [str(n) for n in [1, 2, 4, 8, 16]],
            "min_days_seen": [str(n) for n in [1, 2, 4, 8, 16]],
            "include_reputation": [
                [],
                ["known attacker"],
                ["known attacker", "mass scanner"],
            ],
            "exclude_reputation": [
                [],
                ["known attacker"],
                ["known attacker", "mass scanner"],
            ],
            "feed_size": [str(n) for n in [100, 200, 5000, 10_000_000]],
            "ordering": [field.name for field in IOC._meta.get_fields()],
            "verbose": ["true", "false"],
            "paginate": ["true", "false"],
            "format": ["txt", "json", "csv"],
        }

        # generate n random sets of valid input data
        n = 1_000
        for _ in range(n):
            data_ = {field: random.choice(values) for field, values in choices.items()}
            serializer = FeedsRequestSerializer(
                data=data_,
                context={"valid_feed_types": frozenset(choices["feed_type"])},
            )
            valid = serializer.is_valid(raise_exception=True)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4pot", "cowrie", "adbhoney"])
        data_ = {
            "feed_type": "invalid_feed_type",
            "attack_type": "invalid_attack_type",
            "max_age": "0",
            "min_days_seen": "0",
            "include_reputation": None,
            "exclude_reputation": None,
            "feed_size": "0",
            "ordering": "invalid_ordering",
            "verbose": "invalid_value",
            "paginate": "invalid_value",
            "format": "invalid_format",
        }
        serializer = FeedsRequestSerializer(
            data=data_,
            context={"valid_feed_types": valid_feed_types},
        )
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)
            self.assertIn("attack_type", serializer.errors)
            self.assertIn("max_age", serializer.errors)
            self.assertIn("min_days_seen", serializer.errors)
            self.assertIn("include_reputation", serializer.errors)
            self.assertIn("exclude_reputation", serializer.errors)
            self.assertIn("feed_size", serializer.errors)
            self.assertIn("ordering", serializer.errors)
            self.assertIn("verbose", serializer.errors)
            self.assertIn("paginate", serializer.errors)
            self.assertIn("format", serializer.errors)


class FeedsResponseSerializersTestCase(CustomTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.adbhoney = Honeypot.objects.filter(name__iexact="adbhoney").first()
        if not cls.adbhoney:
            cls.adbhoney = Honeypot.objects.create(name="Adbhoney", active=True)

    def test_valid_fields(self):
        scanner_choices = [True, False]
        payload_request_choices = [True, False]
        feed_type_choices = ["all", "log4pot", "cowrie", "adbhoney"]

        # generete all possible valid input data using cartesian product
        valid_data_choices = product(scanner_choices, payload_request_choices, feed_type_choices)

        for element in valid_data_choices:
            data_ = {
                "feed_type": [element[2]],
                "value": "140.246.171.141",
                SCANNER: element[0],
                PAYLOAD_REQUEST: element[1],
                "first_seen": "2023-03-20",
                "last_seen": "2023-03-21",
                "attack_count": "5",
                "interaction_count": "50",
                "ip_reputation": "known attacker",
                "firehol_categories": [],
                "asn": "8400",
                "destination_port_count": "14",
                "login_attempts": "0",
                "recurrence_probability": "0.1",
                "expected_interactions": "11.1",
            }
            serializer = FeedsResponseSerializer(
                data=data_,
                context={"valid_feed_types": frozenset(feed_type_choices)},
            )
            valid = serializer.is_valid(raise_exception=True)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4pot", "cowrie", "adbhoney"])
        data_ = {
            "feed_type": "invalid_feed_type",
            "value": True,
            SCANNER: "invalid_scanner",
            PAYLOAD_REQUEST: "invalid_payload_request",
            "first_seen": "31-2023-03",
            "last_seen": "31-2023-03",
            "attack_count": "0",
            "interaction_count": "0",
            "ip_reputation": "A" * 64,
            "asn": "8400ABC",
            "destination_port_count": "-1",
            "login_attempts": "-1",
            "recurrence_probability": "1.1",
            "expected_interactions": "-1",
        }
        serializer = FeedsResponseSerializer(
            data=data_,
            context={"valid_feed_types": valid_feed_types},
        )
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)
            self.assertIn("value", serializer.errors)
            self.assertIn(SCANNER, serializer.errors)
            self.assertIn(PAYLOAD_REQUEST, serializer.errors)
            self.assertIn("first_seen", serializer.errors)
            self.assertIn("last_seen", serializer.errors)
            self.assertIn("attack_count", serializer.errors)
            self.assertIn("interaction_count", serializer.errors)
            self.assertIn("ip_reputation", serializer.errors)
            self.assertIn("asn", serializer.errors)
            self.assertIn("login_attempts", serializer.errors)
            self.assertIn("recurrence_probability", serializer.errors)
            self.assertIn("expected_interactions", serializer.errors)
