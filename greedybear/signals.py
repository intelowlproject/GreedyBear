from django.core.cache import cache
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from greedybear.models import Honeypot


@receiver(post_save, sender=Honeypot)
@receiver(post_delete, sender=Honeypot)
def invalidate_valid_feed_types_cache(sender, instance, **kwargs):
    cache.delete("valid_feed_types")
