import requests_cache
import chevron
from requests import Session
from app.integrations.base import IntegrationBase
from .templates import (
    IP_COMMENT_TEMPLATE,
    FILE_REPORT_HASH_COMMENT_TEMPLATE,
    DOMAIN_REPORT_COMMENT_TEMPLATE
)


class VirusTotal(IntegrationBase):

    comment_template_map = {
        'get_domain_report': DOMAIN_REPORT_COMMENT_TEMPLATE,
        'get_ip_report': IP_COMMENT_TEMPLATE,
        'get_file_report_by_hash': FILE_REPORT_HASH_COMMENT_TEMPLATE
    }

    def _load_configuration_elements(self, uuid, events):
        """ Helper function to load the settings that each action will
        require to run.  Prevents duplicate code in each action function."""

        events = self.load_events(uuid=events)

        if not events:
            raise ValueError(f"Could not find event with UUID {events}")

        api_key = None

        # fetch the API key from the configuration
        configuration = self.load_configuration(uuid)

        if not configuration:
            raise ValueError(
                f"Could not find configuration with UUID {uuid}")

        if 'global_settings' in configuration and configuration.global_settings is not None:
            if 'api_key' in configuration.global_settings:
                api_key = configuration.global_settings.api_key

        return api_key, configuration, events

    def _total_analysis_platforms(self, last_analysis_stats):
        """ Helper function to summarize the last analysis stats """

        total_engines = 0
        for assertion in last_analysis_stats:
            total_engines += last_analysis_stats[assertion]

        return total_engines

    def action_scan_file(self, configuration_uuid, events, files=None, *args, **kwargs):
        pass

    def action_scan_url(self, configuration_uuid, events, urls=None, *args, **kwargs):
        pass

    def action_get_domain_report(self, configuration_uuid, events, domain=None, *args, **kwargs):

        action_name = 'get_domain_report'

        api_key, configuration, events = self._load_configuration_elements(
            configuration_uuid, events)

        comment_template = self.get_comment_template(configuration, action_name)

        session = Session()

        markdown_output = ""

        comments = []

        if isinstance(domain, str):
            domain = [domain]

        if api_key:
            if isinstance(domain, list):
                for d in domain:
                    request = session.get(
                        f"https://www.virustotal.com/api/v3/domains/{d}", headers={'x-apikey': api_key})
                    if request.status_code == 200:
                        data = request.json()
                        markdown_output += f"## Domain Report for {d}\n"
                        markdown_output += self.dict_as_markdown_table(
                            data['data']['attributes'])
                        markdown_output += "\n\n"
                        if comment_template:
                            comments.append(chevron.render(comment_template, data))

        if markdown_output:
            virustotal.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, markdown_output, output_format="markdown")
            virustotal.add_event_comment_as_artifact(events, "\n".join(
                comments), action=action_name, configuration=configuration_uuid)
        else:
            virustotal.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No Domain data found", output_format="markdown")

    def action_get_ip_report(self, configuration_uuid, events, ip=None, *args, **kwargs):

        action_name = 'get_ip_report'

        api_key, configuration, events = self._load_configuration_elements(
            configuration_uuid, events)

        comment_template = self.get_comment_template(configuration, action_name)

        session = Session()

        markdown_output = ""

        # Collect any comments we want to add to the event
        comments = []

        if isinstance(ip, str):
            ip = [ip]

        if api_key:
            if isinstance(ip, list):
                for i in ip:
                    request = session.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{i}", headers={'x-apikey': api_key})
                    if request.status_code == 200:
                        data = request.json()
                        markdown_output += f"## IP Report for {i}\n"
                        markdown_output += self.dict_as_markdown_table(
                            data['data']['attributes'])
                        markdown_output += "\n\n"
                        if comment_template:
                            comments.append(chevron.render(comment_template, data))

        if markdown_output:
            virustotal.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, markdown_output, output_format="markdown")
            virustotal.add_event_comment_as_artifact(events, "\n".join(
                comments), action=action_name, configuration=configuration_uuid)
        else:
            virustotal.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No IP data found", output_format="markdown")

    def action_get_url_report(self, configuration_uuid, events, urls=None, *args, **kwargs):
        pass

    def action_get_file_report_by_hash(self, configuration_uuid, events, file_hash=None, *args, **kwargs):

        action_name = 'get_file_report_by_hash'

        api_key, configuration, events = self._load_configuration_elements(
            configuration_uuid, events)

        comment_template = self.get_comment_template(configuration, action_name)

        session = Session()

        # Define an empty Markdown output
        markdown_output = ""

        # Collect any comments we want to add to the event
        comments = []

        if isinstance(file_hash, str):
            file_hash = [file_hash]

        if api_key:
            if isinstance(file_hash, list):
                for h in file_hash:
                    request = session.get(
                        f"https://www.virustotal.com/api/v3/files/{h}", headers={'x-apikey': api_key})
                    if request.status_code == 200:
                        data = request.json()
                        markdown_output += f"## File Report for {h}\n"
                        markdown_output += self.dict_as_markdown_table(
                            data['data']['attributes'])
                        markdown_output += "\n\n"
                        if comment_template:
                            comments.append(chevron.render(comment_template, data))

        if markdown_output:
            virustotal.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, markdown_output, output_format="markdown")
            virustotal.add_event_comment_as_artifact(events, "\n".join(
                comments), action=action_name, configuration=configuration_uuid)
        else:
            virustotal.add_output_to_event(
                [e.uuid for e in events], action_name, configuration, "No Hash Report found", output_format="markdown")

virustotal = VirusTotal()
