from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Nested,
    Object,
    Integer,
    AttrList,
    InnerDoc
)

class FieldMap(InnerDoc):
    '''
    FieldMaps tell the agent what source field in the input to map to a
    Reflex field
    '''

    field = Keyword()
    data_type = Text()
    tlp = Integer()
    tags = Keyword()


class Input(base.BaseDocument):
    '''
    An input defines where an Agent should fetch information.
    Example the agent should pull information from a specific Elasticsearch
    index
    '''

    name = Keyword()
    description = Text()

    # Renamed from 'plugin'.
    # The name of the ingestor being used e.g. 'elasticsearch' or 'ews'
    source = Text()
    enabled = Boolean()  # Default to False
    config = Object()
    credential = Text()  # The UUID of the credential in use
    tags = Keyword()
    field_mapping = Nested(FieldMap)

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-inputs'

    @property
    def _config(self):
        ''' Returns the configuration as a dict '''
        if isinstance(self.config, AttrList):
            return self.config[0].to_dict()
        return self.config.to_dict()

    @property
    def _field_mapping(self):
        ''' Returns the field mapping as a dict '''
        if isinstance(self.field_mapping, AttrList):
            return self.field_mapping[0].to_dict()
        return self.field_mapping.to_dict()

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            user = response[0]
            return user
        return response
