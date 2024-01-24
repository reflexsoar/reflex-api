import datetime
from flask_restx import Resource, Namespace, fields

from app.api_v2.model import (
    ApplicationInventory,
    AgentApplicationInventory
)

from ..utils import token_required, user_has

api = Namespace('Application', path="/application", description='Application Inventory allows for the tracking of applications installed on agents')

mod_application = api.model('Application', {
    'name': fields.String(required=True, description='The name of the application', example='Google Chrome'),
    'version': fields.String(description='The version of the application', example='1.0.0'),
    'vendor': fields.String(description='The vendor of the application', example='Google Inc.'),
    'identifying_number': fields.String(description='The identifying number of the application'),
    'install_date': fields.String(description='The install date of the application', example='2024-01-17T07:00:00.000Z'),
    'install_source': fields.String(description='The install source of the application', example='C:\\Users\\user\\Downloads\\ChromeSetup.exe'),
    'install_location': fields.String(description='The install location of the application', example='C:\\Program Files\\Google\\Chrome\\Application\\'),
    'local_package': fields.String(description='The local package of the application', example='C:\\Windows\\Installer\\1a2b3c.msi'),
    'package_cache': fields.String(description='The package cache of the application', example='C:\\Windows\\Installer\\1a2b3c.msi'),
    'package_code': fields.String(description='The package code of the application', example='{1A2B3C4D-5E6F-7G8H-9I0J-1A2B3C4D5E6F}'),
    'url_info_about': fields.String(description='The url info about of the application', example='https://www.google.com/chrome/'),
    'language': fields.String(description='The language of the application', example='en-US'),
    'application_signature': fields.String(required=False, description='The application signature, a sha265 hash of the name, vendor, version, platform', example='1a2b3c4d5e6f7g8h9i0j1a2b3c4d5e6f7g8h9i0j1a2b3c4d5e6f7g8h9i0j1a2b3c4d5e6f7g8h9i0j'),
    'platform': fields.String(required=True, description='The platform the application is installed on (windows, linux, macos, etc)', example='windows'),
    'architecture': fields.String(description='The architecture of the application', example='x86_64'),
    '_op_type': fields.String(required=True, description='The operation type for the document, add, update, delete', example='add'),
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
application_parser.add_argument('page_size', type=int, default=10, required=False, help='The number of results to return per page')

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

        if args['organization'] and current_user.is_default_org():
            search = ApplicationInventory.search(skip_org_check=True)
            search = search.filter('terms', organization=args['organization'])
        else:
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

        # Aggregation only, set size to 0
        search = search.extra(size=0)

        # Aggregate on the platform
        search.aggs.bucket('platforms', 'terms', field='platform', size=10000)
        search.aggs.bucket('app_count', 'cardinality', field='application_signature')
        # Sub-aggregate on the application name
        search.aggs['platforms'].bucket('names', 'terms', field='name', size=10000)
        # Sub-aggregate on the application vendor and application_signature
        search.aggs['platforms']['names'].bucket('vendors', 'terms', field='vendor', size=10000)
        search.aggs['platforms']['names']['vendors'].bucket('application_signatures', 'terms', field='application_signature', size=10000)

        # Execute the search
        response = search.execute()
        
        # Run a second search to get the number of endpoints for each application name and vendor
        search = AgentApplicationInventory.search().extra(size=0)
        search.aggs.bucket('names', 'terms', field='name', size=10000)
        # Sub-aggregate on the application vendor and application_signature
        search.aggs['names'].bucket('vendors', 'terms', field='vendor', size=10000)
        search.aggs['names']['vendors'].bucket('agent_count', 'cardinality', field='agent.uuid')
        response2 = search.execute()

        # Collapse the results into a lookup table for the count of endpoints for each application
        _endpoint_count = {}
        for name in response2.aggregations.names.buckets:
            for vendor in name.vendors.buckets:
                _endpoint_count[f'{name.key}|{vendor.key}'] = vendor.agent_count.value

        try:
            applications = []
            for application in response.aggregations.platforms.buckets:
                for name in application.names.buckets:
                    for vendor in name.vendors.buckets:
                        _endpoints = _endpoint_count[f'{name.key}|{vendor.key}'] if f'{name.key}|{vendor.key}' in _endpoint_count else 0
                        if _endpoints > 0:
                            applications.append({
                                'name': name.key,
                                'vendor': vendor.key,
                                'version_count': len(vendor.application_signatures.buckets),
                                'endpoint_count': _endpoints
                            })
        except Exception as e:
            api.logger.error(e)
            applications = []

        return {
            'total': response.aggregations.app_count.value,
            'applications': applications
        }
    
mod_create_applications = api.model('CreateApplications', {
    'applications': fields.List(fields.Nested(mod_application))
})
    
@api.route("")
class ApplicationList(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_create_applications)
    @api.response(200, 'Success')
    @api.response(400, 'Bad Request')
    @token_required
    #@user_has('update_applications')
    def post(self, current_user):

        # Create an empty list of application_signatures, this will be used
        # later to determine if the application is new in the system or not
        _application_signatures = []

        if 'applications' in api.payload and len(api.payload['applications']) > 0:

            for _app_entry in api.payload['applications']:
                if 'vendor' not in _app_entry:
                    _app_entry['vendor'] = 'Unknown'
                if 'application_signature' not in _app_entry:
                    _app_entry['application_signature'] = ApplicationInventory.compute_signature(_app_entry['name'], _app_entry['version'], _app_entry['vendor'], _app_entry['platform'])

            # Create a list of application signatures to use for comparison
            # later to determine if the application is new or not
            _application_signatures = [x['application_signature'] for x in api.payload['applications']]

            # Create query to count the number of docs by application_signature
            # if the count is greater than 0, then the application already exists
            # in the system. If the count is 0, then the application is new
            search = ApplicationInventory.search().extra(size=0)
            search = search.filter('terms', application_signature=_application_signatures)
            search.aggs.bucket('application_signatures', 'terms', field='application_signature', size=10000)
            response = search.execute()

            # Create a list of application signatures that already exist in the system
            _existing_application_signatures = [x.key for x in response.aggregations.application_signatures.buckets]

            # Create a list of applications that are new to the system
            _new_applications = [x for x in api.payload['applications'] if x['application_signature'] not in _existing_application_signatures]

            # Bulk add the new application
            _now = datetime.datetime.utcnow()
            _applications = [ApplicationInventory(
                created_at=_now,
                organization=current_user.organization,
                name=x['name'],
                version=x['version'],
                vendor=x['vendor'],
                application_signature=x['application_signature'],
                platform=x['platform'],
                architecture=x['architecture'] if 'architecture' in x else None,
                is_vulnerable=False
            ) for x in _new_applications]

            # Bulk add the new applications
            ApplicationInventory._bulk(_applications)

            # Applications the agent has marked as new
            _agent_new = [x for x in api.payload['applications'] if x['_op_type'] == 'add']

            # Applications the agent has marked as removed
            _agent_removed = [x['application_signature'] for x in api.payload['applications'] if x['_op_type'] == 'delete']

            # Create a list of AgentApplicationInventory objects to bulk add
            _agent_doc_fields = [
                'identifying_number',
                'install_date',
                'install_source',
                'install_location',
                'local_package',
                'package_cache',
                'package_code',
                'url_info_about',
                'language',
                'application_signature',
                'name',
                'vendor',
                'version',
                'platform'
            ]

            _agent_applications = [AgentApplicationInventory(
                created_at=_now,
                organization=current_user.organization,
                agent={
                    'name': current_user['name'] if 'name' in current_user else None,
                    'uuid': current_user['uuid']
                },
                **{k: v for k, v in x.items() if k in _agent_doc_fields}
            ) for x in _agent_new]

            if len(_agent_applications) > 0:
                search = AgentApplicationInventory.search().extra(size=0)
                search = search.filter('terms', application_signature=[s.application_signature for s in _agent_applications])
                search = search.filter('term', agent__uuid=current_user.uuid)
                search.aggs.bucket('application_signatures', 'terms', field='application_signature', size=10000)
                response = search.execute()

                AgentApplicationInventory.bulk([x for x in _agent_applications if x.application_signature not in [y.key for y in response.aggregations.application_signatures.buckets]])

            # Delete any applications that the agent has marked as removed
            if len(_agent_removed) > 0:

                # Delete the applications the agent has marked as removed from the
                # Agent Application Inventory
                AgentApplicationInventory.delete_by_agent_and_application_sig(
                    agent_uuid=current_user.uuid,
                    application_signatures=_agent_removed
                )

        return {
            'message': 'success'
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

        if args['organization'] and current_user.is_default_org():
            search = ApplicationInventory.search(skip_org_check=True)
            search = search.filter('terms', organization=args['organization'])
        else:
            search = ApplicationInventory.search()

        # Apply any args passed in
        if args['name']:
            search = search.filter('terms', name=args['name'])

        if args['version']:
            search = search.filter('terms', version=args['version'])

        if args['vendor']:
            search = search.filter('terms', vendor=args['vendor'])

        results = [r for r in search.scan()]

        # Create a list of application signatures to pull from the AgentApplicationInventory
        _application_signatures = [x.application_signature for x in results]

        if args['organization'] and current_user.is_default_org():
            search = AgentApplicationInventory.search(skip_org_check=True)
            search = search.filter('terms', organization=args['organization'])
        else:
            search = AgentApplicationInventory.search()

        search = search.filter('terms', application_signature=_application_signatures)

        endpoints = [r for r in search.scan()]

        return {
            'endpoints': endpoints,
            'total': len(endpoints)
        }
