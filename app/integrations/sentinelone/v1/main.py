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

    def action_get_agent_details(self, configuration_uuid, hostname=None, mac_address=None, ip_address=None, *args, **kwargs):
        """
        Gets agent details from SentinelOne
        """

        configuration = self.load_configuration(configuration_uuid)

        print(configuration)

        print(f"Getting agent details for host {hostname} {mac_address} {ip_address}")


sentinelone = SentinelOne()