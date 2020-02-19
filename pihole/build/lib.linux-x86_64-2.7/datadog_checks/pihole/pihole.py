from datadog_checks.base import AgentCheck
from datadog_checks.errors import CheckException

import requests
import json

class PiholeCheck(AgentCheck):
    def check(self, instance):
        host = instance.get('host')

        if not host:
            raise ConfigurationError('Configuration error, please fix pihole.d/conf.yaml, A host parameter is required for this integration')

        url = 'http://' + host + '/admin/api.php'
        response = requests.get(url)
        if response.status_code == 200:
            try:
                data = response.json()
            except simplejson.errors.JSONDecodeError:
                raise ConfigurationError('unexpected response from server, is pihole running?')

            if data["domains_being_blocked"]:
                domains_being_blocked = data["domains_being_blocked"]
                self.gauge("pihole.domains_being_blocked",domains_being_blocked)

            if data["dns_queries_today"]:
                dns_queries_today = data["dns_queries_today"]
                self.gauge("pihole.dns_queries_today", dns_queries_today)

            if data["ads_blocked_today"]:
                ads_blocked_today = data["ads_blocked_today"]
                self.gauge("pihole.ads_blocked_today",ads_blocked_today)

            if data["ads_percentage_today"]:
                ads_percentage_today = data["ads_percentage_today"]
                self.gauge("pihole.ads_percent_blocked",ads_percentage_today)

            if data["unique_domains"]:
                unique_domains = data["unique_domains"]
                self.gauge("pihole.unique_domains",unique_domains)

            if data["queries_forwarded"]:
                queries_forwarded = data["queries_forwarded"]
                self.gauge("pihole.queries_forwarded", queries_forwarded)

            if data["queries_cached"]:
                queries_cached = data["queries_cached"]
                self.gauge("pihole.queries_cached",queries_cached)

            if data["clients_ever_seen"]:
                clients_ever_seen = data["clients_ever_seen"]
                self.gauge("pihole.clients_ever_seen", clients_ever_seen)

            if data["unique_clients"]:
                unique_clients = data["unique_clients"]
                self.gauge("pihole.unique_clients", unique_clients)

            if data["dns_queries_all_types"]:
                dns_queries_all_types = data["dns_queries_all_types"]
                self.gauge("pihole.dns_queries_today", dns_queries_today)

            if data["reply_NODATA"]:
                reply_NODATA = data["reply_NODATA"]
                self.gauge("pihole.reply_nodata", reply_NODATA)

            if data["reply_NXDOMAIN"]:
                reply_NXDOMAIN = data["reply_NXDOMAIN"]
                self.gauge("pihole.reply_nxdomain", reply_NXDOMAIN)

            if data["reply_CNAME"]:
                reply_CNAME = data["reply_CNAME"]
                self.gauge("pihole.reply_cname",reply_CNAME)

            if data["reply_IP"]:
                reply_IP = data["reply_IP"]
                self.gauge("pihole.reply_ip", reply_IP)

            if data["privacy_level"]:
                privacy_level = data["privacy_level"]
                self.gauge("pihole.privacy_level", privacy_level)
        else:
            raise ConfigurationError('Unexpected responce from server')


        pass
