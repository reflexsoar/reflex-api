"""
app/api_v2/model/integration.py

Contains the model defining the Integration object.  Integrations are 
how the API connects to external services or coordinates with the agent
to connect to external services.  Integrations are created by the
organization administrator and the configurations are stored as JSON strings
in an IntegrationConfiguration object.
"""

import json
import uuid
from fnmatch import fnmatch
from . import (
    base,
    Document,
    Keyword,
    Text,
    Boolean,
    Object,
    Search
)


class Integration(Document):
    """
    Defines an integration that users can use to create configuration objects

    Example:  SentinelOne is an available integration.  The Integration object
    defines the basic information about the integration and the IntegrationConfiguration
    object defines the configuration for the integration on a per tenant basis.
    """

    uuid = Keyword()  # The unique identifier for the integration
    name = Keyword()  # The name of the integration
    product_identifier = Keyword()  # The a unique key that identifies the integration
    # The description of the integration
    description = Keyword(fields={'text': Text()})
    author = Keyword()  # The author of the integration
    contributor = Keyword()  # The contributor of the integration
    license_name = Keyword()  # The license name of the integration
    enabled = Boolean()  # Whether the integration is enabled or not
    manifest = Object()  # Contains a JSON string that defines what actions are available for the integration and what fields are required for each action
    version = Keyword()  # The version of the integration
    logo = Keyword()  # Base64 encoded logo for the integration
    tags = Keyword()
    category = Keyword()

    class Index:
        name = 'reflex-integrations'
        settings = {
            'refresh_interval': '5s',
        }

    @classmethod
    def search(cls, using=None, index=None, skip_org_check=False):
        """
        Creates an :class:`~elasticsearch_dsl.Search` instance that will search 
        over this ``Document``
        """
        s = Search(using=cls._get_using(using),
                   index=cls._default_index(index), doc_type=[cls])
        return s

    @classmethod
    def _matches(cls, hit):
        return fnmatch(hit["_index"], f'{cls.Index.name}-*')

    @classmethod
    def get(cls, uuid: str, **kwargs):
        """
        Finds the integration by the product_identifier
        """

        search = cls.search()
        search = search.filter('term', product_identifier=uuid)
        if kwargs:
            for key, value in kwargs.items():
                search = search.filter('term', **{key: value})
        results = search.execute()

        if results:
            return results[0]

        return None
    

    def get_action(self, action_uuid):
        """
        Returns the action configuration specified via the UUID
        """
        search = IntegrationConfiguration.search()
        search = search.filter('term', uuid=action_uuid)
        results = search.execute()

        if results:
            return results[0]
        
        return None
    
    def save(self, **kwargs):
        '''
        Overrides the default Document save() function and adds
        audit fields created_at, updated_at and a default uuid field
        '''
        if not self.uuid:
                    self.uuid = uuid.uuid4()
        return super().save(**kwargs)

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
            'term', product_identifier=manifest['product_identifier']).filter('term', version=manifest['version']).execute()
        if integration:
            raise Exception(
                f'WARNING - Integration with product identifier {manifest["product_identifier"]} already exists')

        # Validate that the manifest file contains the required fields
        required_fields = [
            'name',
            'product_identifier',
            'description',
            'author',
            'license',
            'version',
            'manifest'
        ]
        missing_fields = []
        for field in required_fields:
            if field not in manifest:
                missing_fields.append(field)

        if missing_fields:
            raise Exception(
                f'Manifest file is missing the following required fields: {missing_fields}')

        # Validate that fields are the correct type
        field_type_map = {
            'name': str,
            'product_identifier': str,
            'description': str,
            'author': str,
            'license': str,
            'version': str,
            'manifest': dict,
            'contributor': list,
            'enabled': bool,
            'logo': str,
            'tags': list,
            'category': list
        }

        invalid_fields = []
        for field in manifest:
            if field in field_type_map:
                if not isinstance(manifest[field], field_type_map[field]):
                    error = f"Field {field} is a {type(manifest[field])} but should be a {field_type_map[field]}"
                    invalid_fields.append(error)

        if invalid_fields:

            raise Exception(
                f'Manifest file contains the following fields with invalid types: {invalid_fields}')

        # Create the new Integration object
        integration = cls(
            name=manifest['name'],
            product_identifier=manifest['product_identifier'],
            description=manifest['description'],
            author=manifest['author'],
            contributor=manifest['contributor'],
            license_name=manifest['license'],
            enabled=manifest['enabled'],
            manifest=manifest['manifest'],
            version=manifest['version'],
            logo=manifest['logo'],
            tags=manifest['tags'],
            category=manifest['category']
        )
        integration.save()


class IntegrationConfiguration(base.BaseDocument):
    """
    Defines the configuration for an integration.  The configuration is stored as a JSON string
    """

    name = Keyword()  # The name of the integration
    action = Keyword()  # The name of the action
    integration_uuid = Keyword()  # The UUID of the integration this configuration is for
    # Contains a JSON string that defines the configuration for the integration
    configuration = Object()

    class Index:
        name = 'reflex-integration-configurations'
        settings = {
            'refresh_interval': '5s',
        }
