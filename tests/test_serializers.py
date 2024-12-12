from datetime import datetime
from itertools import product

from api.serializers import FeedsResponseSerializer, FeedsSerializer, feed_type_validation
from django.test import TestCase
from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.models import GeneralHoneypot
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
            serializer = FeedsSerializer(data=data_)
            valid = serializer.is_valid(raise_exception=True) and feed_type_validation(data_["feed_type"], frozenset(feed_type_choices))
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4j", "cowrie", "adbhoney"])
        data_ = {"feed_type": "invalid_feed_type", "attack_type": "invalid_attack_type", "age": "invalid_age", "format": "invalid_format"}
        serializer = FeedsSerializer(data=data_)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("attack_type", serializer.errors)
            self.assertIn("age", serializer.errors)
            self.assertIn("format", serializer.errors)
        try:
            feed_type_validation(data_["feed_type"], valid_feed_types)
        except ValidationError as e:
            self.assertIn("feed_type", str(e))


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
                "value": "140.246.171.141",
                SCANNER: element[0],
                PAYLOAD_REQUEST: element[1],
                "first_seen": "2023-03-20",
                "last_seen": "2023-03-21",
                "times_seen": "5",
                "feed_type": element[2],
            }
            serializer = FeedsResponseSerializer(data=data_)
            valid = serializer.is_valid(raise_exception=True) and feed_type_validation(data_["feed_type"], frozenset(feed_type_choices))
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4j", "cowrie", "adbhoney"])
        data_ = {
            "value": True,
            SCANNER: "invalid_scanner",
            PAYLOAD_REQUEST: "invalid_payload_request",
            "first_seen": "31-2023-03",
            "last_seen": "31-2023-03",
            "times_seen": "invalid_times_seen",
            "feed_type": "invalid_feed_type",
        }
        serializer = FeedsResponseSerializer(data=data_)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("value", serializer.errors)
            self.assertIn(SCANNER, serializer.errors)
            self.assertIn(PAYLOAD_REQUEST, serializer.errors)
            self.assertIn("first_seen", serializer.errors)
            self.assertIn("last_seen", serializer.errors)
            self.assertIn("times_seen", serializer.errors)
        try:
            feed_type_validation(data_["feed_type"], valid_feed_types)
        except ValidationError as e:
            self.assertIn("feed_type", str(e))
