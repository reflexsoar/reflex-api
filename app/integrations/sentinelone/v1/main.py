import json
import requests_cache
from requests import Session
from flask_restx import Resource, fields

from app.integrations.base import IntegrationBase, IntegrationApi

mod_test = IntegrationApi.model('Test', {
    'test': fields.String
})


class SentinelOne(IntegrationBase):

    def action_isolate_host(self, hostname=None, mac_address=None, ip_address=None, *args, **kwargs):
        """
        Isolates a host in SentinelOne
        """

        print(f"Isolating host {hostname} {mac_address} {ip_address}")

    def action_get_agent_details(self, configuration_uuid, hostname=None,
                                 mac_address=None, ip_address=None,
                                 hostname_source_fields=None,
                                 mac_address_source_fields=None, 
                                 ip_source_fields=None,
                                 events=None, *args, **kwargs):
        """
        Gets agent details from SentinelOne
        """

        hostname = []

        action_name = "get_agent_details"

        configuration = self.load_configuration(configuration_uuid)
        if not 'skip_load' in kwargs or not kwargs['skip_load']:
            events = self.load_events(uuid=events)

        if not configuration:
            raise ValueError(
                f"Could not find configuration with UUID {configuration_uuid}")
        
        if configuration.actions.get_agent_details.cache_results:
            s = requests_cache.CachedSession("sentinelone-get-agent-details",
                                             expire_after=configuration.actions.get_agent_details.cache_expiry)
        else:
            s = Session()

        if not hasattr(configuration, 'global_settings'):
            sentinelone.log_message(f"Configuration {configuration_uuid} does not have global settings",
                                    configuration.uuid, configuration.name, action=action_name, level="ERROR")
            raise ValueError(
                f"Configuration {configuration_uuid} does not have global settings")
        if not configuration.global_settings.api_key:
            sentinelone.log_message(f"Configuration {configuration_uuid} does not have a global API key set",
                                    configuration.uuid, configuration.name, action=action_name, level="ERROR")
            raise ValueError(
                f"Configuration {configuration_uuid} does not have a global API key set")

        s.headers.update(
            {"Authorization": f"ApiToken {configuration.global_settings.api_key}"})

        api_url = configuration.global_settings.api_url

        # Make sure the API URL does not end with a /
        if api_url.endswith('/'):
            api_url = api_url[:-1]

        endpoint = "/web/api/v2.1/agents"

        #if hostname in [None, ""]:
        #    hostname = []
            #hostname = [
            #    o.value for o in self.extract_observables_by_type(events, "host")]
        #if mac_address is None:
        #    mac_address = [
        #        o.value for o in self.extract_observables_by_type(events, "mac")]
        #if ip_address is None:
        #    ip_address = [
        #        o.value for o in self.extract_observables_by_type(events, "ip")]

        # Find the value of each source field in the events
        if hostname_source_fields:
            for event in events:
                for field in hostname_source_fields:
                    values = self.get_value_from_source_field(
                        field, event)
                    if values:
                        if isinstance(values, list):
                            hostname.extend(values)
                        else:
                            hostname.append(values)

        if not isinstance(hostname, list):
            hostname = [hostname]

        url = f"{api_url}{endpoint}?computerName__contains={','.join(hostname)}"

        if len(hostname) > 0:

            print(f"Getting agent details from {url}")

            response = s.get(url)

            if response.status_code != 200:
                sentinelone.log_message(
                    f"Could not get agent details: {response.text}", configuration.uuid, configuration.name, action="get_agent_details")
                raise Exception(f"Could not get agent details: {response.text}")

            agents = response.json()

            if 'data' in agents:
                agents = agents['data']
                if len(agents) > 0:

                    # Deduplicate the agents by their id
                    agents = {a['id']: a for a in agents}.values()

                    if not events:
                        raise ValueError("No events were provided")

                    for agent in agents:

                        markdown_output = sentinelone.dict_as_markdown_table(agent)
                        sentinelone.add_output_to_event(
                            [e.uuid for e in events], action_name, configuration, markdown_output, output_format="markdown")
                else:
                    sentinelone.log_message(
                        f"No agents found", configuration.uuid, configuration.name, action="get_agent_details", level="INFO")
                    sentinelone.add_output_to_event(
                        [e.uuid for e in events], action_name, configuration, "No agents found", output_format="markdown")
        else:
            sentinelone.log_message(
                f"No hostname provided", configuration.uuid, configuration.name, action="get_agent_details", level="INFO")
            sentinelone.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No hostname provided", output_format="markdown")


sentinelone = SentinelOne()
