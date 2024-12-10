import random
from datetime import datetime
from itertools import product

from api.serializers import feed_request_validation, ioc_validation, serialize_ioc
from django.test import TestCase
from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.models import GeneralHoneypot
from rest_framework.serializers import ValidationError


class FeedsSerializersTestCase(TestCase):
    @classmethod
    def setUpClass(self):
        feed_type_choices = ["all", "log4j", "cowrie", "adbhoney"]
        attack_type_choices = ["all", "scanner", "payload_request"]
        age_choices = ["recent", "persistent"]
        format_choices = ["txt", "json", "csv"]
        # genereted all the possible valid input data using cartesian product
        self.valid_data_choices = product(feed_type_choices, attack_type_choices, age_choices, format_choices)
        GeneralHoneypot.objects.create(
            name="adbhoney",
            active=True,
        )

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()

    def test_valid_fields(self):
        for element in self.valid_data_choices:
            data_ = {"feed_type": element[0], "attack_type": element[1], "age": element[2], "format": element[3]}
            valid = feed_request_validation(data_)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        invalid_data = {"feed_type": "invalid_feed_type", "attack_type": "invalid_attack_type", "age": "invalid_age", "format": "invalid_format"}
        for element in self.valid_data_choices:
            data_ = {"feed_type": element[0], "attack_type": element[1], "age": element[2], "format": element[3]}
            key, invalid_value = random.choice(list(invalid_data.items()))
            data_[key] = invalid_value
            try:
                feed_request_validation(data_)
            except ValidationError as e:
                self.assertIn(key, str(e))


class FeedsResponseSerializersTestCase(TestCase):
    @classmethod
    def setUpClass(self):
        scanner_choices = [True, False]
        payload_request_choices = [True, False]
        feed_type_choices = ["all", "log4j", "cowrie", "adbhoney"]
        # generete all possible valid input data using cartesian product
        self.valid_data_choices = product(scanner_choices, payload_request_choices, feed_type_choices)
        GeneralHoneypot.objects.create(
            name="adbhoney",
            active=True,
        )

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()

    def test_valid_fields(self):
        for element in self.valid_data_choices:
            if not element[0] and not element[1]:
                continue
            data_ = {
                "value": "140.246.171.141",
                SCANNER: element[0],
                PAYLOAD_REQUEST: element[1],
                "first_seen": "2023-03-20",
                "last_seen": "2023-03-21",
                "times_seen": 5,
                "feed_type": element[2],
            }
            valid = ioc_validation(data_)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        invalid_data = {
            "scanner nor payload": (False, False),
            "times_seen": 0,
            "feed_type": "invalid_feed_type",
        }
        for element in self.valid_data_choices:
            if not element[0] and not element[1]:
                continue
            data_ = {
                "value": "140.246.171.141",
                SCANNER: element[0],
                PAYLOAD_REQUEST: element[1],
                "first_seen": "2023-03-20",
                "last_seen": "2023-03-21",
                "times_seen": 5,
                "feed_type": element[2],
            }
            key, invalid_value = random.choice(list(invalid_data.items()))
            if key == "scanner nor payload":
                data_[SCANNER], data_[PAYLOAD_REQUEST] = invalid_value
            else:
                data_[key] = invalid_value
            try:
                ioc_validation(data_)
            except ValidationError as e:
                self.assertIn(key, str(e))
