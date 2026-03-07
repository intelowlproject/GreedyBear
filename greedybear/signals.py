from django.core.cache import cache
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from api.views.utils import VALID_FEED_TYPES_CACHE_KEY
from greedybear.models import GeneralHoneypot


@receiver(post_save, sender=GeneralHoneypot)
@receiver(post_delete, sender=GeneralHoneypot)
def clear_feed_types_cache(sender, **kwargs):
    cache.delete(VALID_FEED_TYPES_CACHE_KEY)
