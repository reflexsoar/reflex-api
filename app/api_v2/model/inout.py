from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Nested,
    Object,
    Integer,
    AttrList,
    InnerDoc,
    Date,
    Q
)

VALID_DATA_TYPES = [
    "none",
    "url",
    "user",
    "sid",
    "sha256hash",
    "sha1hash",
    "process",
    "port",
    "pid",
    "md5hash",
    "mac",
    "ip",
    "imphash",
    "host",
    "generic",
    "fqdn",
    "filepath",
    "email_subject",
    "email",
    "domain",
    "detection_id",
    "command",
]


class FieldMap(InnerDoc):
    '''
    FieldMaps tell the agent what source field in the input to map to a
    Reflex field
    '''

    field = Keyword()
    data_type = Text(fields={'keyword': Keyword()})
    sigma_field = Keyword()
    tlp = Integer()
    ioc = Boolean()
    safe = Boolean()
    spotted = Boolean()
    signature_field = Boolean()
    tag_field = Boolean()
    observable_field = Boolean()
    tags = Keyword()


class FieldMappingTemplate(base.BaseDocument):
    '''
    A FieldMappingTemplate can be applied globally to many inputs
    '''

    name = Keyword()
    description = Text(fields={'keyword': Keyword()})
    # Higher priority templates are applied last and override lower priority
    priority = Integer()
    field_mapping = Nested(FieldMap)
    is_global = Boolean()

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-field-mapping-templates'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def get_by_name(self, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search()

        response = response.filter('term', name=name)
        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if response:
            user = response[0]
            return user
        return response
    
    @classmethod
    def get_global_templates(self):
        '''
        Returns all the global templates
        '''
        response = self.search()

        response = response.filter('term', is_global=True)

        # Set size to 0 to return all results
        response = response[0:0]

        response = response.scan()
        return [template for template in response]


class Input(base.BaseDocument):
    '''
    An input defines where an Agent should fetch information.
    Example the agent should pull information from a specific Elasticsearch
    index
    '''

    name = Keyword()
    description = Text(fields={'keyword': Keyword()})

    # Renamed from 'plugin'.
    # The name of the ingestor being used e.g. 'elasticsearch' or 'ews'
    source = Text(fields={'keyword': Keyword()})
    enabled = Boolean()  # Default to False
    detections_only = Boolean()  # Default to False (True means it is only used for detections)
    config = Object()
    credential = Keyword()  # The UUID of the credential in use
    tags = Keyword()
    field_templates = Keyword()  # A list of field templates to apply to the alert
    field_mapping = Nested(FieldMap)
    index_fields = Keyword()  # A list of all the fields on the index via _mapping
    index_fields_last_updated = Date()
    field_mapping_templates = Keyword()  # A list of UUIDs of FieldMappingTemplates
    # What sigma backend pysigma should convert to when this input is used
    sigma_backend = Keyword()
    # What sigma pipeline pysigma should use when this input is used
    sigma_pipeline = Keyword()
    # What sigma field mapping pysigma should use when this input is used
    sigma_field_mapping = Keyword()
    mitre_data_sources = Keyword()  # What MITRE data sources does this input cover?
    data_source_templates = Keyword()

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-inputs'
        settings = {
            'refresh_interval': '1s'
        }

    def __hash__(self) -> int:
        return hash(('uuid', self.uuid, 'name', self.name))

    @property
    def _config(self):
        ''' Returns the configuration as a dict '''
        if isinstance(self.config, AttrList):
            return self.config[0].to_dict()
        return self.config.to_dict()

    @property
    def _field_mapping(self):
        ''' Returns the field mapping as a dict '''

        # Pull any field mapping templates assigned to this input and merge them
        # if hasattr(self, 'field_mapping_templates') and len(self.field_mapping_templates) > 0:awd

        if isinstance(self.field_mapping, AttrList):
            if self.field_mapping and len(self.field_mapping) >= 1:
                return self.field_mapping[0].to_dict()
            else:
                return {}
        return self.field_mapping.to_dict()

    @classmethod
    def get_by_name(self, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search()
        response = response.filter('term', name=name)

        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if response:
            user = response[0]
            return user
        return response

    def get_field_settings(self):
        '''Provides a list of field settings for this input'''

        final_fields = []

        if self.field_templates:
            templates = FieldMappingTemplate.search(skip_org_check=True)

            # The templates assigned to this detection but only if they belong to the same org
            # or are flagged as global
            templates = templates.filter(
                'bool',
                should=[
                    Q('bool', must=[Q('term', is_global=True), Q('terms', uuid=self.field_templates)]),
                    Q('bool', must=[Q('term', organization=self.organization), Q('terms', uuid=self.field_templates)])
                ]
            )

            templates = [t for t in templates.scan()]

            for template in templates:
                for template_field in template.field_mapping:
                    replaced = False
                    for field in final_fields:
                        if field['field'] == template_field['field']:
                            # If the field is currently a signature field make sure it stays that way
                            if 'signature_field' in field and field['signature_field'] is True:
                                template_field['signature_field'] = True

                            final_fields[final_fields.index(
                                field)] = template_field
                            
                            replaced = True
                            break

                    if not replaced:
                        final_fields.append(template_field)
        else:
            if hasattr(self.field_mapping, 'fields'):
                final_fields = self.field_mapping.fields
            else:
                final_fields = []

        return final_fields
