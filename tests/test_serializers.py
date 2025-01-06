import random
from itertools import product

from api.serializers import FeedsRequestSerializer, FeedsResponseSerializer, FeedsSerializer
from django.test import TestCase
from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.models import IOC, GeneralHoneypot
from rest_framework.serializers import ValidationError


class FeedsSerializersTestCase(TestCase):
    @classmethod
    def setUpClass(self):
        GeneralHoneypot.objects.create(
            name="adbhoney",
            active=True,
        )

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()

    def test_valid_fields(self):
        feed_type_choices = ["all", "log4j", "cowrie", "adbhoney"]
        attack_type_choices = ["all", "scanner", "payload_request"]
        age_choices = ["recent", "persistent"]
        format_choices = ["txt", "json", "csv"]
        # genereted all the possible valid input data using cartesian product
        valid_data_choices = product(feed_type_choices, attack_type_choices, age_choices, format_choices)

        for element in valid_data_choices:
            data_ = {"feed_type": element[0], "attack_type": element[1], "age": element[2], "format": element[3]}
            serializer = FeedsSerializer(
                data=data_,
                context={"valid_feed_types": frozenset(feed_type_choices)},
            )
            valid = serializer.is_valid(raise_exception=True)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4j", "cowrie", "adbhoney"])
        data_ = {"feed_type": "invalid_feed_type", "attack_type": "invalid_attack_type", "age": "invalid_age", "format": "invalid_format"}
        serializer = FeedsSerializer(
            data=data_,
            context={"valid_feed_types": valid_feed_types},
        )
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)
            self.assertIn("attack_type", serializer.errors)
            self.assertIn("age", serializer.errors)
            self.assertIn("format", serializer.errors)


class FeedsRequestSerializersTestCase(TestCase):
    @classmethod
    def setUpClass(self):
        GeneralHoneypot.objects.create(
            name="adbhoney",
            active=True,
        )

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()

    def test_valid_fields(self):
        choices = {
            "feed_type": ["all", "log4j", "cowrie", "adbhoney"],
            "attack_type": ["all", "scanner", "payload_request"],
            "max_age": [1, 2, 4, 8, 16],
            "min_days_seen": [1, 2, 4, 8, 16],
            "include_reputation": [[], ["known attacker"], ["known attacker", "mass scanner"]],
            "exclude_reputation": [[], ["known attacker"], ["known attacker", "mass scanner"]],
            "feed_size": [100, 200, 5000, 10_000_000],
            "ordering": [field.name for field in IOC._meta.get_fields()],
            "verbose": [True, False],
            "paginate": [True, False],
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
        valid_feed_types = frozenset(["all", "log4j", "cowrie", "adbhoney"])
        data_ = {
            "feed_type": "invalid_feed_type",
            "attack_type": "invalid_attack_type",
            "max_age": 0,
            "min_days_seen": 0,
            "include_reputation": None,
            "exclude_reputation": None,
            "feed_size": 0,
            "ordering": "invalid_ordering",
            "verbose": None,
            "paginate": None,
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


class FeedsResponseSerializersTestCase(TestCase):
    @classmethod
    def setUpClass(self):
        GeneralHoneypot.objects.create(
            name="adbhoney",
            active=True,
        )

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()

    def test_valid_fields(self):
        scanner_choices = [True, False]
        payload_request_choices = [True, False]
        feed_type_choices = ["all", "log4j", "cowrie", "adbhoney"]

        # generete all possible valid input data using cartesian product
        valid_data_choices = product(scanner_choices, payload_request_choices, feed_type_choices)

        for element in valid_data_choices:
            data_ = {
                "feed_type": element[2],
                "value": "140.246.171.141",
                SCANNER: element[0],
                PAYLOAD_REQUEST: element[1],
                "first_seen": "2023-03-20",
                "last_seen": "2023-03-21",
                "attack_count": "5",
                "interaction_count": "50",
                "ip_reputation": "known attacker",
                "asn": "8400",
                "destination_port_count": "14",
                "login_attempts": "0",
            }
            serializer = FeedsResponseSerializer(
                data=data_,
                context={"valid_feed_types": frozenset(feed_type_choices)},
            )
            valid = serializer.is_valid(raise_exception=True)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4j", "cowrie", "adbhoney"])
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
