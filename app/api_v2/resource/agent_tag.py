from flask_restx import Resource, Namespace, fields

from app.api_v2.model import (
    AgentTag,
    Agent
)

from app.api_v2.rql.parser import QueryParser

from .shared import NullableString, ISO8601, mod_user_list
from ..utils import token_required, user_has

api = Namespace('Agent Tag', path="/agent_tag", description='Agent Tags dynamically group agents together')

mod_agent_tag = api.model('AgentTag', {
    'namespace': fields.String(required=True, description='The namespace of the tag'),
    'organization': fields.String(required=False, description='The organization the tag belongs to'),
    'value': fields.String(required=True, description='The value of the tag'),
    'description': NullableString(required=False, description='A description of the tag'),
    'color': fields.String(required=False, description='A color to represent the tag in hex format'),
    'dynamic': fields.Boolean(required=False, description='Is this tag dynamic or static?'),
    'query': fields.String(required=False, description='The criteria to use for dynamic tags using RQL'),
    'full_name': fields.String(required=False, description='The full name of the tag')
})

mod_agent_tag_short = api.model('AgentTagShort', {
    'uuid': fields.String,
    'namespace': fields.String,
    'value': fields.String,
    'color': fields.String
})

mod_agent_tag_detailed = api.inherit('AgentTagDetailed', mod_agent_tag, {
    'uuid': fields.String(required=True, description='The ID of the tag'),
    'created_at': ISO8601,
    'updated_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list)
})

mod_agent_tag_list = api.model('AgentTagList', {
    'total': fields.Integer(required=True, description='The total number of tags'),
    'tags': fields.List(fields.Nested(mod_agent_tag_detailed))
})

mod_tag_test = api.model('TagTest', {
    'agent_uuid': fields.String(required=True, description='The agent UUID to test the tag against'),
    'applied_tags': fields.List(fields.Nested(mod_agent_tag_detailed))
})

agent_tag_parser = api.parser()

agent_tag_parser.add_argument('namespace', type=str, action='split', default=None, required=False, help='The namespace of the tag')
agent_tag_parser.add_argument('value', type=str, action='split', default=None, required=False, help='The value of the tag')
agent_tag_parser.add_argument('organization', type=str, required=False, action='split', default=None, help='The organization the tag belongs to')

@api.route('')
class AgentTagList(Resource):
    '''Shows a list of all agent tags, and lets you POST to add new tags'''

    @api.doc(security="Bearer")
    @api.marshal_list_with(mod_agent_tag_list)
    @api.expect(agent_tag_parser, validate=True)
    @token_required
    @user_has('view_agent_tags')
    def get(self, current_user):
        '''List all agent tags'''

        args = agent_tag_parser.parse_args()

        search = AgentTag.search()

        if current_user.is_default_org() and args.organization:
            search = search.filter('terms', organization=args.organization)

        if args.namespace:
            search = search.filter('terms', namespace=args.namespace)

        if args.value:
            search = search.filter('terms', value=args.value)

        tags = [t for t in search.scan()]

        return {
            'total': len(tags),
            'tags': tags
        }

    @api.doc(security="Bearer")
    @api.expect(mod_agent_tag, validate=True)
    @api.marshal_with(mod_agent_tag_detailed, code=201)
    @token_required
    @user_has('create_agent_tag')
    def post(self, current_user):
        '''Create a new agent tag'''

        # Check to see if a tag with the same namespace and value already exists
        search = AgentTag.search()

        if 'organization' in api.payload:
            if current_user.is_default_org():
                search = search.filter('term', organization=api.payload['organization'])
            else:
                if api.payload['organization'] != current_user.organization:
                    api.abort(403, 'You can only create tags for your own organization')

        search = search.filter('term', namespace=api.payload['namespace'])
        search = search.filter('term', value=api.payload['value'])

        if search.count() > 0:
            api.abort(400, 'Tag with the same namespace and value already exists')

        new_tag = AgentTag(**api.payload)
        new_tag.save()

        return new_tag, 201


@api.route('/<tag_uuid>')
class AgentTagDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_tag_detailed)
    @token_required
    @user_has('view_agent_tags')
    def get(self, tag_uuid, current_user):
        '''Get a specific agent tag'''

        tag = AgentTag.get_by_uuid(tag_uuid)

        if tag:
            if current_user.is_default_org() is False or current_user.organization != tag.organization:
                api.abort(403, 'Tag not found')

            return tag
        else:
            api.abort(404, 'Tag not found')

    @api.doc(security="Bearer")
    @api.expect(mod_agent_tag, validate=True)
    @api.marshal_with(mod_agent_tag_detailed)
    @token_required
    @user_has('update_agent_tag')
    def put(self, tag_uuid, current_user):
        '''Update a specific agent tag'''

        tag = AgentTag.get_by_uuid(tag_uuid)

        if tag:
            if current_user.is_default_org() is False or current_user.organization != tag.organization:
                api.abort(404, 'Tag not found')

            # Check to see if a tag with the same namespace and value already exists
            search = AgentTag.search()
            
            search = search.filter('term', organization=tag.organization)
            search = search.filter('term', namespace=api.payload['namespace'])
            search = search.filter('term', value=api.payload['value'])

            existing_tag = search.execute()
            if len(existing_tag) > 0:
                if existing_tag[0].uuid != tag_uuid:
                    api.abort(400, 'Tag with the same namespace and value already exists')

            tag.update(**api.payload)

            return tag
        else:
            api.abort(404, 'Tag not found')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_tag_detailed)
    @token_required
    @user_has('delete_agent_tag')
    def delete(self, tag_uuid, current_user):
        '''Delete a specific agent tag'''

        tag = AgentTag.get_by_uuid(tag_uuid)

        if tag:
            if current_user.is_default_org() is False and current_user.organization != tag.organization:
                api.abort(404, 'Tag not found')

            tag.delete()

            return tag
        else:
            api.abort(404, 'Tag not found')




mod_tag_test = api.model('TagTest', {
    'query': fields.String(required=True, description='The query to test'),
    'organization': fields.String(required=False, description='The organization to test against')
})

mod_tag_test_results = api.model('TagTestResults', {
    'hits': fields.Integer(required=True, description='The number of hits')
})

@api.route("/test")
class AgentTagTestAll(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_tag_test, validate=True)
    @api.marshal_with(mod_tag_test_results)
    @token_required
    @user_has('view_agent_tags')
    def post(self, current_user):

        if 'query' not in api.payload:
            api.abort(400, 'A query is required')
        
        if api.payload['query'] in ['',' ']:
            api.abort(400, 'A query is required')

        organization = current_user.organization
        if 'organization' in api.payload:
            if api.payload['organization'] != current_user.organization and current_user.is_default_org() is False:
                api.abort(403, 'You can only test tags for your own organization')
            organization = api.payload['organization']
                
        search = Agent.search()

        search = search.filter('term', organization=organization)

        agents = [{'agent': a.to_dict()} for a in search.scan()]

        qp = QueryParser()
        try:
            parsed_query = qp.parser.parse(api.payload['query'])
        except ValueError as e:
            api.abort(400, f'Error parsing query: {e}')
            
        results = [r for r in qp.run_search(agents, parsed_query)]

        return {
            'hits': len(results)
        }

    
@api.route('/test/<agent_uuid>')
class AgentTagTest(Resource):

    @api.doc(security="Bearer")
    @api.marshal_list_with(mod_tag_test)
    @token_required
    @user_has('view_agent_tags')
    def get(self, agent_uuid, current_user):
        '''Test the agent tag criteria against an agent'''

        agent = Agent.get_by_uuid(agent_uuid)

        if current_user.is_default_org() is False or current_user.organization != agent.organization:
            api.abort(403, 'You can only test tags for your own organization')

        if agent:

            tag_search = AgentTag.search()

            tag_search = tag_search.filter('term', organization=agent.organization)

            tags = [t for t in tag_search.scan()]

            applied_tags = []
            for tag in tags:
                if tag.check_tag(agent.to_dict()):
                    applied_tags.append(tag)
                
        return {
            'agent_uuid': agent_uuid,
            'applied_tags': applied_tags
        }