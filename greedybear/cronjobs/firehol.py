import requests
from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, FireHolList


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

        # Enrich recently added IOCs with FireHol categories
        self._enrich_recent_iocs()

        # Clean up old FireHolList entries
        self._cleanup_old_entries()

    def _enrich_recent_iocs(self):
        """
        Update firehol_categories only for recently added IOCs.
        This prevents retroactively marking old IOCs with new intelligence.
        """
        from datetime import datetime, timedelta

        # Get FireHolList entries added in the last 24 hours
        yesterday = datetime.now() - timedelta(hours=24)
        recent_firehol = FireHolList.objects.filter(added__gte=yesterday)

        self.log.info(f"Enriching {recent_firehol.count()} recent FireHol entries")

        for entry in recent_firehol:
            try:
                # Only update IOCs that were also recently added
                ioc = IOC.objects.get(name=entry.ip_address, first_seen__gte=yesterday)
                if entry.source not in ioc.firehol_categories:
                    ioc.firehol_categories.append(entry.source)
                    ioc.save()
                    self.log.debug(f"Added {entry.source} category to recently added IOC {entry.ip_address}")
            except IOC.DoesNotExist:
                # IOC doesn't exist or wasn't recently added - skip
                pass

    def _cleanup_old_entries(self):
        """
        Delete FireHolList entries older than 30 days to keep database clean.
        """
        from datetime import datetime, timedelta

        cutoff_date = datetime.now() - timedelta(days=30)
        deleted_count, _ = FireHolList.objects.filter(added__lt=cutoff_date).delete()

        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old FireHolList entries")
