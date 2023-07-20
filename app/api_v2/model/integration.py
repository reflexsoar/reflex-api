"""
app/api_v2/model/integration.py

Contains the model defining the Integration object.  Integrations are 
how the API connects to external services or coordinates with the agent
to connect to external services.  Integrations are created by the
organization administrator and the configurations are stored as JSON strings
in an IntegrationConfiguration object.
"""

import json
import fnmatch
from . import (
    base,
    Document,
    Keyword,
    Text,
    Boolean,
    Float,
    Integer,
    Date,
    Object,
    Nested,
    Ip
)


class Integration(Document):
    """
    Defines an integration that users can use to create configuration objects

    Example:  SentinelOne is an available integration.  The Integration object
    defines the basic information about the integration and the IntegrationConfiguration
    object defines the configuration for the integration on a per tenant basis.
    """

    name = Keyword()  # The name of the integration
    product_identifier = Keyword()  # The a unique key that identifies the integration
    # The description of the integration
    description = Keyword(fields={'text': Text()})
    author = Keyword()  # The author of the integration
    contributor = Keyword()  # The contributor of the integration
    license_name = Keyword()  # The license name of the integration
    enabled = Boolean()  # Whether the integration is enabled or not
    manifest = Keyword()  # Contains a JSON string that defines what actions are available for the integration and what fields are required for each action
    version = Keyword()  # The version of the integration
    logo = Keyword()  # Base64 encoded logo for the integration

    class Index:
        name = 'reflex-integrations'
        settings = {
            'refresh_interval': '5s',
        }

    #@classmethod
    #def _matches(cls, hit):
    #    return fnmatch(hit["_index"], f'{cls._index._name}-*')

    @classmethod
    def load_manifest(cls, data):
        """
        Creates a new Integration object from the manifest file
        """

        # Validate that the data provide is valid JSON and convert it to a dictionary
        try:
            with open(data, 'r') as data:
                manifest = json.load(data)
        except Exception as e:
            raise Exception(f'Invalid JSON provided for manifest file {data}')

        # Check to see if an Integration object already exists for the product identifier
        integration = cls.search().filter(
            'term', product_identifier=manifest['product_identifier']).execute()
        if integration:
            raise Exception(
                f'WARNING - Integration with product identifier {manifest["product_identifier"]} already exists')

        # Create the new Integration object
        integration = cls(
            name=manifest['name'],
            product_identifier=manifest['product_identifier'],
            description=manifest['description'],
            author=manifest['author'],
            contributor=manifest['contributor'],
            license_name=manifest['license'],
            enabled=manifest['enabled'],
            manifest=json.dumps(manifest['manifest']),
            version=manifest['version'],
            logo=manifest['logo']
        )
        integration.save()


class IntegrationConfiguration(base.Document):
    """
    Defines the configuration for an integration.  The configuration is stored as a JSON string
    """

    name = Keyword()  # The name of the integration
    integration_uuid = Keyword()  # The UUID of the integration this configuration is for
    # Contains a JSON string that defines the configuration for the integration
    configuration = Keyword()

    class Index:
        name = 'reflex-integration-configurations'
        settings = {
            'refresh_interval': '5s',
        }
