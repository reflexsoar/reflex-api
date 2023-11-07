


    
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
    severity = Keyword()
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
