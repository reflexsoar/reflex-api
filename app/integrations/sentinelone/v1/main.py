import json
import requests_cache
from requests import Session
from flask_restx import Resource, fields
from typing import List

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

    def action_get_threat_details(self, configuration_uuid, threat_id,
                                  events=None, *args, **kwargs):
        """
        Gets threat details from SentinelOne
        """

        pass

    def action_add_threat_note(self, configuration_uuid: str, ids: List[str], note: str,
                               threat_id_source_field: str = None,
                               events=None, *args, **kwargs):
        """
        Adds a note to a threat in SentinelOne
        Calls the /web/api/v2.1/threat/notes endpoint which allows for adding
        the same note to multiple threats using a list of threat IDs
        """

        action_name = "add_threat_note"
        endpoint = "/web/api/v2.1/threats/notes"

        configuration = self.load_configuration(configuration_uuid)

        if not configuration:
            raise ValueError(
                f"Could not find configuration with UUID {configuration_uuid}")
        
        if not 'from_event_rule' in kwargs or not kwargs['from_event_rule']:
            events = self.load_events(uuid=events)

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
        s.headers.update(
            {"Content-Type": "application/json"}
        )

        api_url = configuration.global_settings.api_url

        # Make sure the API URL does not end with a /
        if api_url.endswith('/'):
            api_url = api_url[:-1]

        
        if threat_id_source_field is not None:
            for event in events:
                values = self.get_value_from_source_field(
                    threat_id_source_field, event)
                if values:
                    if isinstance(values, list):
                        ids.extend(values)
                    else:
                        ids.append(values)

        if not isinstance(ids, list):
            ids = [ids]

        url = f"{api_url}{endpoint}"

        # Deduplicate the IDs
        ids = list(set(ids))

        if len(ids) > 0:

            request_payload = {
                "data": {
                    "text": note
                },
                "filter": {
                    "ids": ids
                }
            }

            response = s.post(url, json=request_payload)

            if response.status_code != 200:
                sentinelone.log_message(
                    f"Could not add note: {response.text}", configuration.uuid, configuration.name, action=action_name)
                raise Exception(f"Could not add note: {response.text}")
            
            response_json = response.json()

            if 'data' in response_json:
                print(response_json)
                if response_json['data']['affected'] == 0:
                    sentinelone.log_message(
                        f"Could not add note: {response.text}", configuration.uuid, configuration.name, action=action_name)
                    sentinelone.add_output_to_event(
                        [e.uuid for e in events], action_name, configuration, "Could not add note", output_format="markdown")
                else:
                    formatted_threat_ids = "\n".join([f"- `{i}`\n" for i in ids])
                    sentinelone.add_event_comment(events, f"A new note was added to a SentinelOne Threat.\n\n**Note**\n```\n{note}\n```\n\n**Affected Threats ({response_json['data']['affected']})**\n{formatted_threat_ids}")
        else:
            sentinelone.log_message(
                f"No threat IDs provided", configuration.uuid, configuration.name, action=action_name, level="INFO")
            sentinelone.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No threat IDs provided", output_format="markdown")     


    def action_get_agent_details(self, configuration_uuid, hostname=None,
                                 mac_address=None, ip_address=None,
                                 hostname_source_fields=None,
                                 mac_address_source_fields=None, 
                                 ip_source_fields=None,
                                 events=None, *args, **kwargs):
        """
        Gets agent details from SentinelOne
        """

        if hostname is None:
            hostname = []

        action_name = "get_agent_details"

        configuration = self.load_configuration(configuration_uuid)
        if not 'from_event_rule' in kwargs or not kwargs['from_event_rule']:
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

        ip_address = ['192.168.1.218']

        if ip_address is None:
            ip_address = []
        
        if not isinstance(ip_address, list):
            ip_address = [ip_address]

        if ip_source_fields:
            for event in events:
                for field in ip_source_fields:
                    values = self.get_value_from_source_field(
                        field, event)
                    if values:
                        if isinstance(values, list):
                            ip_address.extend(values)
                        else:
                            ip_address.append(values)

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

        url_params = []

        # Strip invalid hostnames
        hostname = [h for h in hostname if h not in [None, ""]]
        if len(hostname) > 0:
            url_params.append(f"computerName__contains={','.join(hostname)}")

        # Strip invalid ip addresses
        ip_address = [i for i in ip_address if i not in [None, ""]]
        if len(ip_address) > 0:
            url_params.append(f"networkInterfaceInet__contains={','.join(ip_address)}")

        #if len(mac_address) > 0:
        #    url_params.append(f"mac__contains={','.join(mac_address)}")

        url = f"{api_url}{endpoint}?{'&'.join(url_params)}"

        if len(url_params) > 0:

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
                    
                    # Remove this request from the cache
                    if configuration.actions.get_agent_details.cache_results:
                        s.cache.delete_url(url)
        else:
            sentinelone.log_message(
                f"No hostnames, IP Addresses or MAC Addresses provided", configuration.uuid, configuration.name, action="get_agent_details", level="INFO")
            sentinelone.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No hostnames, IP Addresses or MAC Addresses provided", output_format="markdown")


sentinelone = SentinelOne()
