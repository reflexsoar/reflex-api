import requests_cache
from requests import Session
from app.integrations.base import IntegrationBase


class IPWhoisIO(IntegrationBase):

    def action_ip_whois_lookup(self, configuration_uuid, events, ips=None, *args, **kwargs):

        action_name = 'ip_whois_lookup'

        events = self.load_events(uuid=events)

        if not events:
            raise ValueError(f"Could not find event with UUID {events}")

        api_key = None

        # fetch the API key from the configuration
        configuration = self.load_configuration(configuration_uuid)

        if not configuration:
            raise ValueError(
                f"Could not find configuration with UUID {configuration_uuid}")

        if 'global_settings' in configuration and configuration.global_settings is not None:
            if 'api_key' in configuration.global_settings:
                api_key = configuration.global_settings.api_key

        if 'cache_expiry' not in configuration.actions.ip_whois_lookup:
            configuration.actions.ip_whois_lookup.cache_expiry = 3600
        if 'cache_results' not in configuration.actions.ip_whois_lookup:
            configuration.actions.ip_whois_lookup.cache_results = True
            
        if configuration.actions.ip_whois_lookup.cache_results:
            session = requests_cache.CachedSession(
                "ipwhoisio-ip-whois", expire_after=configuration.actions.ip_whois_lookup.cache_expiry)
        else:
            session = Session()

        markdown_output = ""

        params = {}

        # If we have an API key, add it to the request with security=1
        # to pull the full data set
        if api_key:
            params = {
                'key': api_key,
                'security': 1
            }

        if isinstance(ips, str):
            ips = [ips]

        if isinstance(ips, list):
            for ip in ips:
                markdown_output += f"## IP Whois for {ip}\n"
                url = f"https://ipwhois.io/json/{ip}"                    
                request = session.get(f"https://ipwho.is/{ip}", params=params)
                if request.status_code == 200:
                    data = request.json()
                    markdown_output += self.dict_as_markdown_table(data)
                else:
                    markdown_output += f"No IP data found for {ips}"
                markdown_output += "\n\n"

        if markdown_output:
            ipwhoisio.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, markdown_output, output_format="markdown")
        else:
            ipwhoisio.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No IP data found", output_format="markdown")

    def action_test(self):
        print("HELLO WORLD THIS IS A TEST ACTION")


ipwhoisio = IPWhoisIO()
