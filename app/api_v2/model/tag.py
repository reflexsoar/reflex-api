from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer
)

class AgentTag(base.BaseDocument):
    '''
    A Tag is a way to group agents together for easier management.  An example
    may be tagging all agents that are in the same department or all agents that
    are in the same location.

    namespace: The namespace of the tag.  This is used to group tags together
    value: The value of the tag.  This is used to group tags together
    description: A description of the tag
    color: A color to represent the tag
    dynamic: Is this tag dynamic or static?
    criteria: The criteria to use for dynamic tags using RQL

    Example Tag:
    os: windows
    dynamic: true
    criteria: os.name contains windows
    '''
    
    namespace = Keyword(fields={'text': Text()})
    value = Keyword(fields={'text': Text()})
    description = Keyword(fields={'text': Text()})
    color = Keyword()
    dynamic = Boolean()
    criteria = Keyword()

    class Index:
    
        name = 'reflex-agent-tags'
        settings = {
            'refresh_interval': '5s',
        }
