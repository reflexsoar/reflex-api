from flask_restx import Resource, Namespace, fields

from app.api_v2.model import (
    ApplicationInventory
)

from ..utils import token_required, user_has

api = Namespace('Application', path="/application", description='Application Inventory allows for the tracking of applications installed on agents')

mod_application = api.model('Application', {
    'name': fields.String(description='The name of the application'),
    'version': fields.String(description='The version of the application'),
    'vendor': fields.String(description='The vendor of the application'),
    'identifying_number': fields.String(description='The identifying number of the application'),
    'install_date': fields.String(description='The install date of the application'),
    'install_source': fields.String(description='The install source of the application'),
    'local_package': fields.String(description='The local package of the application'),
    'package_cache': fields.String(description='The package cache of the application'),
    'package_code': fields.String(description='The package code of the application'),
    'url_info_about': fields.String(description='The url info about of the application'),
    'language': fields.String(description='The language of the application')
})

mod_agent_info = api.model('AgentInfo', {
    'name': fields.String(description='The name of the agent'),
    'uuid': fields.String(description='The uuid of the agent')
})

mod_endpoint_application = api.clone('EndpointApplication', mod_application, {
    'agent': fields.Nested(mod_agent_info, description='The agent that has this application installed')
})

mod_application_summary = api.model('ApplicationSummary', {
    'name': fields.String(description='The name of the application'),
    'vendor': fields.String(description='The vendor of the application'),
    'version_count': fields.Integer(description='The number of versions of this application'),
    'endpoint_count': fields.Integer(description='The number of endpoints with this application installed')
})

mod_application_list = api.model('ApplicationList', {
    'total': fields.Integer(required=True, description='The total number of applications'),
    'applications': fields.List(fields.Nested(mod_application_summary))
})

mod_application_list_endpoints = api.model('ApplicationListEndpoints', {
    'total': fields.Integer(required=True, description='The total number of endpoints'),
    'endpoints': fields.List(fields.Nested(mod_endpoint_application))
})

application_parser = api.parser()

application_parser.add_argument('name', type=str, action='split', default=None, required=False, help='The name of the application')
application_parser.add_argument('agent', type=str, default=None, required=False, help='The agent name')
application_parser.add_argument('version', type=str, action='split', default=None, required=False, help='The version of the application')
application_parser.add_argument('vendor', type=str, required=False, action='split', default=None, help='The vendor of the application')
application_parser.add_argument('organization', type=str, required=False, action='split', default=None, help='The organization of the application')

@api.route('/summary')
class ApplicationListView(Resource):

    @api.doc(security="Bearer")
    @api.expect(application_parser)
    @api.marshal_with(mod_application_list)
    @api.response(200, 'Success')
    @api.response(400, 'Bad Request')
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        '''List all applications inventoried across all agents'''

        args = application_parser.parse_args()

        search = ApplicationInventory.search()

        # Apply any args passed in
        if args['name']:
            search = search.filter('terms', name=args['name'])

        if args['version']:
            search = search.filter('terms', version=args['version'])

        if args['vendor']:
            search = search.filter('terms', vendor=args['vendor'])

        if args['agent']:
            search = search.filter('terms', name=args['agent'])

        if args['organization'] and current_user.is_default_org():
            search = search.filter('terms', organization=args['organization'])

        # Set a search size of 0 to return only aggregations
        search = search.extra(size=0)

        # Aggregate by the software name, vendor and count the total versions per vendor and number of endpoints
        search.aggs.bucket('name', 'terms', field='name', size=10000) \
        .bucket('vendor', 'terms', field='vendor', size=50)

        

        # Aggregate endpoint_count and version_count by name as well in case vendor is not specified
        search.aggs['name'].bucket('version_count', 'cardinality', field='version')
        search.aggs['name'].bucket('endpoint_count', 'cardinality', field='agent.name')

        # Aggregate endpoint_count and version_count by vendor
        search.aggs['name'].aggs['vendor'].bucket('version_count', 'cardinality', field='version')
        search.aggs['name'].aggs['vendor'].bucket('endpoint_count', 'cardinality', field='agent.name')
        
        # Execute the search
        response = search.execute()

        # Summarize the data for each application into a list of dictionaries that look like
        # { name: <name>, version_count: <version_count>, endpoint_count: <endpoint_count> }
        applications = []
        for name in response.aggregations.name.buckets:
            if len(name.vendor.buckets) == 0:
                applications.append({
                    'name': name.key,
                    'vendor': 'N/A',
                    'version_count': name.version_count.value,
                    'endpoint_count': name.endpoint_count.value
                })
            else:
                for vendor in name.vendor.buckets:
                    applications.append({
                        'name': name.key,
                        'vendor': vendor.key,
                        'version_count': vendor.version_count.value,
                        'endpoint_count': vendor.endpoint_count.value
                    })

        return {
            'total': len(applications),
            'applications': applications
        }

@api.route('/summary/endpoints')
class ApplicationDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_application_list_endpoints)
    @api.expect(application_parser)
    @api.response(200, 'Success')
    @api.response(400, 'Bad Request')
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        '''List all endpoints with a specific application installed'''

        args = application_parser.parse_args()

        search = ApplicationInventory.search()

        # Apply any args passed in
        if args['name']:
            search = search.filter('terms', name=args['name'])

        if args['version']:
            search = search.filter('terms', version=args['version'])

        if args['vendor']:
            search = search.filter('terms', vendor=args['vendor'])

        if args['organization'] and current_user.is_default_org():
            search = search.filter('terms', organization=args['organization'])

        print(search.to_dict())

        results = [r for r in search.scan()]

        return {
            'endpoints': results,
            'total': len(results)
        }
