from datetime import datetime

from api.serializers import FeedsResponseSerializer, FeedsSerializer
from django.test import TestCase
from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.models import IOC
from rest_framework.serializers import ValidationError


class FeedsSerializersTestCase(TestCase):
    def test_valid_fields(self):
        data_ = {"feed_type": "all", "attack_type": "all", "age": "recent", "format": "txt"}
        serializer = FeedsSerializer(data=data_)
        valid = serializer.is_valid(raise_exception=True)
        self.assertEqual(valid, True)

    def test_invalid_fields(self):
        data_ = {"feed_type": "feed_type", "attack_type": "attack", "age": "age", "format": "format"}
        serializer = FeedsSerializer(data=data_)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)
            self.assertIn("attack_type", serializer.errors)
            self.assertIn("age", serializer.errors)
            self.assertIn("format", serializer.errors)


class FeedsResponseSerializersTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super(FeedsResponseSerializersTestCase, cls).setUpClass()
        current_time = datetime.utcnow()
        cls.ioc = IOC.objects.create(
            name="140.246.171.141",
            type="testing_type",
            first_seen=current_time,
            last_seen=current_time,
            days_seen=[current_time],
            number_of_days_seen=1,
            times_seen=1,
            log4j=True,
            cowrie=False,
            general=[],
            scanner=True,
            payload_request=True,
            related_urls=[],
        )

    def test_valid_fields(self):
        data_ = {
            "value": self.ioc.name,
            SCANNER: self.ioc.scanner,
            PAYLOAD_REQUEST: self.ioc.payload_request,
            "first_seen": self.ioc.first_seen.strftime("%Y-%m-%d"),
            "last_seen": self.ioc.last_seen.strftime("%Y-%m-%d"),
            "times_seen": self.ioc.times_seen,
            "feed_type": "log4j",
        }
        serializer = FeedsResponseSerializer(data=data_)
        valid = serializer.is_valid()
        self.assertEqual(valid, True)

    def test_invalid_fields(self):
        data_ = {
            "value": True,
            SCANNER: "scanner",
            PAYLOAD_REQUEST: "payload_request",
            "first_seen": "31-2023-03",
            "last_seen": "31-2023-03",
            "times_seen": "times_seen",
            "feed_type": False,
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
            self.assertIn("feed_type", serializer.errors)
