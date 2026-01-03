import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.models import FireHolList


class FireHolCron(Cronjob):
    def run(self) -> None:
        base_path = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"
        sources = {
            "blocklist_de": f"{base_path}/blocklist_de.ipset",
            "greensnow": f"{base_path}/greensnow.ipset",
            "bruteforceblocker": f"{base_path}/bruteforceblocker.ipset",
            "dshield": f"{base_path}/dshield.netset",
        }

        for source, url in sources.items():
            self.log.info(f"Processing {source} from {url}")
            try:
                try:
                    response = requests.get(url, timeout=60)
                    response.raise_for_status()
                except requests.RequestException as e:
                    self.log.error(f"Network error fetching {source}: {e}")
                    continue

                lines = response.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # FireHol .ipset and .netset files contain IPs or CIDRs, one per line
                    # Comments (lines starting with #) are filtered out above

                    try:
                        FireHolList.objects.get(ip_address=line, source=source)
                    except FireHolList.DoesNotExist:
                        FireHolList(ip_address=line, source=source).save()

            except Exception as e:
                self.log.exception(f"Unexpected error processing {source}: {e}")

        # Clean up old FireHolList entries
        self._cleanup_old_entries()

    def _cleanup_old_entries(self):
        """
        Delete FireHolList entries older than 30 days to keep database clean.
        """
        from datetime import datetime, timedelta

        cutoff_date = datetime.now() - timedelta(days=30)
        deleted_count, _ = FireHolList.objects.filter(added__lt=cutoff_date).delete()

        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old FireHolList entries")
