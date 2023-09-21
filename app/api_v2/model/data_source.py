from . import (
    Keyword,
    Text,
    base,
    Nested,
    Integer,
    InnerDoc,
    Boolean
)

class DataSourceDefinition(InnerDoc):
    """
    Defines a DataSourceDefinition model that can be used to automatically assess
    data inputs and determine if they have the correct MITRE ATT&CK data sources.
    """

    name = Keyword(fields={'keyword': Keyword()})
    query = Keyword()
    description = Text(fields={'keyword': Keyword()})
    prequisites = Text(fields={'keyword': Keyword()})


class DataSourceTemplate(base.BaseDocument):
    """
    Defines a DataSourceTemplate model that can be used to automatically assess
    data inputs and determine if they have the correct MITRE ATT&CK data sources
    within their data set.

    Example Document:
    {
      "uuid": "abababab-abab-abab-abab-abababababab",
      "name": "Windows",
      "sources": [{
        "uuid": "0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a",
        "name": "Process: Process Creation",
        "query": "(winlog.channel: security AND event.code: 4688) OR (winlog.channel: sysmon AND event.code: 1)",
        "prerequisites": "Install Microsoft Sysmon and enabled Event ID 1 rules.\nEnable Process Auditing in Windows Security Event Logs."
      }],
      "revision": 1
    }
    """

    name = Keyword(fields={'keyword': Keyword()})
    description = Text(fields={'keyword': Keyword()})
    sources = Nested(DataSourceDefinition)
    revisions = Integer()
    is_global = Boolean()

    class Index:
        name = 'reflex-data-source-templates'
        settings = {
            'refresh_interval': '1s'
        }