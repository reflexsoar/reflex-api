import re
import datetime
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Date,
    system
)

class ThreatList(base.BaseDocument):
    '''
    A threat list contains observable values that are used to
    tag tag observables on ingest.  Threat lists can contain
    values from external sources via URL polling
    '''

    name = Keyword()
    description = Text()
    list_type = Text()  # value or pattern
    data_type_uuid = Keyword()
    tag_on_match = Boolean()  # Default to False
    values = Keyword()  # A list of values to match on
    url = Text() # A url to pull threat information from
    poll_interval = Integer() # How often to pull from this list
    last_polled = Date() # The time that the list was last fetched
    active = Boolean()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-threat-lists'

    @property
    def data_type(self):
        data_type = system.DataType.get_by_uuid(uuid=self.data_type_uuid)
        if data_type:
            return data_type
        return []

    def check_value(self, value):
        '''
        Checks to see if a value matches a value list or a regular expression
        based list and returns the number of hits on that list'
        '''
        hits = 0

        if self.list_type == 'values':
            hits = len([v for v in self.values if v.lower() == value.lower()])
        elif self.list_type == 'patterns':
            hits = len([v for v in self.values if re.match(v, value) is not None])

        return hits

    def set_values(self, values: list, from_poll=False):
        '''
        Sets the values of the threat list from a list of values
        '''
        if len(values) > 0:
            self.values = values

        if from_poll:
            self.last_polled = datetime.datetime.utcnow()
        self.save()

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

    @classmethod
    def get_by_data_type(self, data_type):
        '''
        Fetches the threat list by the data_type
        it should be associated with
        '''
        data_type = system.DataType.get_by_name(name=data_type)
        try:
            response = self.search().query('term', data_type_uuid=data_type.uuid).execute()
        except AttributeError:
            return []
        if response:
            return list(response)
        return []

