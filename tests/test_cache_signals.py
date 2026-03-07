from django.core.cache import cache
from django.test import TestCase

from api.views.utils import VALID_FEED_TYPES_CACHE_KEY, get_valid_feed_types
from greedybear.models import GeneralHoneypot


class FeedTypesCacheTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.honeypot = GeneralHoneypot.objects.create(name="TestPot", active=True)

    def test_cache_hit_no_db_query(self):
        first_call = get_valid_feed_types()
        with self.assertNumQueries(0):
            second_call = get_valid_feed_types()
        self.assertEqual(first_call, second_call)

    def test_signal_clears_cache_on_save(self):
        get_valid_feed_types()
        self.assertIsNotNone(cache.get(VALID_FEED_TYPES_CACHE_KEY))

        GeneralHoneypot.objects.create(name="AnotherPot", active=True)
        self.assertIsNone(cache.get(VALID_FEED_TYPES_CACHE_KEY))

    def test_signal_clears_cache_on_delete(self):
        get_valid_feed_types()
        self.assertIsNotNone(cache.get(VALID_FEED_TYPES_CACHE_KEY))

        self.honeypot.delete()
        self.assertIsNone(cache.get(VALID_FEED_TYPES_CACHE_KEY))
