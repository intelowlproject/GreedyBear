from collections import Counter
from datetime import datetime

from django.db import connection
from django.db.models import Sum

from greedybear.models import AttackerActivityBucket


class TrendingBucketRepository:
    UPSERT_BATCH_SIZE = 10_000

    def upsert_bucket_counts(self, counters: Counter[tuple[str, str, datetime]]) -> int:
        if not counters:
            return 0

        table_name = AttackerActivityBucket._meta.db_table
        quoted_table_name = connection.ops.quote_name(table_name)
        counter_items = list(counters.items())
        with connection.cursor() as cursor:
            for batch_start in range(0, len(counter_items), self.UPSERT_BATCH_SIZE):
                batch = counter_items[batch_start : batch_start + self.UPSERT_BATCH_SIZE]
                values_sql = ",".join(["(%s, %s, %s, %s)"] * len(batch))
                params = []
                for (attacker_ip, feed_type, bucket_start), interaction_count in batch:
                    params.extend([attacker_ip, feed_type, bucket_start, interaction_count])

                query = f"""
                    INSERT INTO {quoted_table_name} (attacker_ip, feed_type, bucket_start, interaction_count)
                    VALUES {values_sql}
                    ON CONFLICT (attacker_ip, feed_type, bucket_start)
                    DO UPDATE
                    SET interaction_count = {quoted_table_name}.interaction_count + EXCLUDED.interaction_count
                """
                cursor.execute(query, params)

        return len(counters)

    def get_counts_in_window(self, window_start, window_end, feed_type: str) -> dict[str, int]:
        queryset = AttackerActivityBucket.objects.filter(bucket_start__gte=window_start, bucket_start__lt=window_end)
        if feed_type != "all":
            queryset = queryset.filter(feed_type=feed_type)

        return dict(queryset.values("attacker_ip").annotate(total=Sum("interaction_count")).values_list("attacker_ip", "total"))

    def delete_older_than(self, cutoff) -> int:
        deleted_count, _ = AttackerActivityBucket.objects.filter(bucket_start__lt=cutoff).delete()
        return deleted_count
