from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer
)

from app.api_v2.rql.parser import QueryParser

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
    query = Keyword()

    class Index:
    
        name = 'reflex-agent-tags'
        settings = {
            'refresh_interval': '5s',
        }

    @classmethod
    def set_agent_tags(cls, agent):
        '''
        Checks the agent against all tags and applies the tags that match
        '''

        tags = cls.search().filter('term', organization=agent.organization).scan()

        agent_data = agent.to_dict()
        tags_to_apply = []
        for tag in tags:
            if tag.check_tag(agent_data) is True:
                tags_to_apply.append({
                    'namespace': tag.namespace,
                    'value': tag.value,
                    'color': tag.color,
                })

        return tags_to_apply

    def check_tag(self, agent: dict) -> bool:
        '''
        Checks if the agent matches the tag criteria
        '''
        
        if not self.query:
            return False
        
        try:
            qp = QueryParser()
            parsed_query = qp.parser.parse(self.query)
        except:
            print(f"Error parsing query: {self.query}")
            return False

        results = [r for r in qp.run_search({'agent': agent}, parsed_query)]
        
        if len(results) > 0:
            return True
        return False
