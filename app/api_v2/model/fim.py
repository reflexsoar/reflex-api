from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer
)

class FimRule(base.BaseDocument):

    name = Keyword(fields={'text': Text()})
    description = Keyword(fields={'text': Text()})
    severity = Integer()
    risk_score = Integer()
    paths = Keyword()
    recursive = Boolean()
    file_types = Keyword()
    include_patterns = Keyword()
    exclude_patterns = Keyword()
    max_file_size = Integer()
    max_parallel_files = Integer()
    check_interval = Integer()
    hashes = Keyword()
    alert = Boolean()
    collect_additional_data = Boolean()
    tags = Keyword()
    schedules = Keyword()

    class Index:

        name = 'reflex-fim-rules'
        settings = {
            'refresh_interval': '5s',
        }

    @classmethod
    def get_by_name(cls, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = cls.search()

        if isinstance(name, list):
            response = response.filter('terms', name=name)
        else:
            response = response.filter('term', name=name)
        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if response:
            usr = response[0]
            return usr
        return response
