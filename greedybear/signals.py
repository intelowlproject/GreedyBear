from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.cache import cache
from greedybear.models import GeneralHoneypot

CACHE_KEY = "valid_feed_types"

@receiver(post_save, sender=GeneralHoneypot)
@receiver(post_delete, sender=GeneralHoneypot)
def invalidate_honeypot_cache(sender, instance, **kwargs):
    cache.delete(CACHE_KEY)
