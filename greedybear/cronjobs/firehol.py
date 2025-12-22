import requests
from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, FireHolList


class FireHolCron(Cronjob):
    def run(self) -> None:
        sources = {
            "blocklist_de": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
            "greensnow": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/greensnow.ipset",
            "bruteforceblocker": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bruteforceblocker.ipset",
            "dshield": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
        }

        for source, url in sources.items():
            self.log.info(f"Processing {source} from {url}")
            try:
                response = requests.get(url, timeout=60)
                if response.status_code != 200:
                    self.log.error(f"Failed to fetch {source}. Status: {response.status_code}")
                    continue

                lines = response.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # FireHol lists might contain comments or extra info in lines?
                    # ipsets usually are just IP or CIDR per line after comments.
                    # Some might have 'add setname ip' format?
                    # The files I viewed (raw content) look like IPs/CIDRs.
                    # mass_scanners used regex: r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*#\s*(.+)*"
                    # But FireHol raw files from firehol/blocklist-ipsets are usually clean lists.
                    # dshield.netset lines were just CIDRs.
                    # blocklist_de.ipset lines are IPs.
                    # We will treat the line as the value.

                    try:
                        FireHolList.objects.get(ip_address=line, source=source)
                    except FireHolList.DoesNotExist:
                        FireHolList(ip_address=line, source=source).save()
                        self._update_ioc(line, source)

            except Exception as e:
                self.log.exception(f"Error processing {source}: {e}")

    def _update_ioc(self, ip_address, source):
        try:
            ioc = IOC.objects.get(name=ip_address)
            if source not in ioc.firehol_categories:
                ioc.firehol_categories.append(source)
                ioc.save()
        except IOC.DoesNotExist:
            pass
