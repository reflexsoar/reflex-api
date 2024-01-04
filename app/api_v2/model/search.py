from . import (
    InnerDoc,
    Keyword,
    Text,
    Boolean,
    Integer,
    base,
    Object,
    Date,
    Q,
    UpdateByQuery
)


class SearchProxyJob(base.BaseDocument):

    job_details = Object(enabled=False)
    status = Keyword() # pending, running, complete
    assigned_agent = Keyword()
    complete = Boolean()
    results = Object(enabled=False)

    class Index:
        name = "reflex-search-proxy-jobs"
        settings = {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "1s",
            "max_result_window": 500000
        }
        version = "1.0.5"
