from flask_restx import Resource, Namespace, fields

from app.api_v2.model import (
    Agent
)

from app.api_v2.rql.parser import QueryParser

from .shared import NullableString, ISO8601, mod_user_list
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

mod_application_summary = api.model('ApplicationSummary', {
    'name': fields.String(description='The name of the application'),
    'vendor': fields.String(description='The vendor of the application'),
    'version_count': fields.Integer(description='The number of versions of this application'),
    'endpoint_count': fields.Integer(description='The number of endpoints with this application installed')
})

mod_application_version_summary = api.model('ApplicationVersionSummary', {
    'version': fields.String(description='The version of the application'),
    'endpoint_count': fields.Integer(description='The number of endpoints with this application installed')
})

mod_application_list = api.model('ApplicationList', {
    'total': fields.Integer(required=True, description='The total number of applications'),
    'applications': fields.List(fields.Nested(mod_application_summary))
})

application_parser = api.parser()

application_parser.add_argument('name', type=str, action='split', default=None, required=False, help='The name of the application')
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

        search = Agent.search()

        # Apply any args passed in
        if args['name']:
            search = search.filter('terms', host_information__installed_software__name=args['name'])

        if args['version']:
            search = search.filter('terms', host_information__installed_software__version=args['version'])

        if args['vendor']:
            search = search.filter('terms', host_information__installed_software__vendor=args['vendor'])

        if args['organization'] and current_user.is_default_org():
            search = search.filter('terms', organization=args['organization'])

        # Set a search size of 0 to return only aggregations
        search = search.extra(size=0)

        # Search for applications in the agents installed_software field
        # aggregated by name, with a version_count and endpoint_count cardinality
        # aggregation.  We have to nest twice, once for host_information and again
        # for installed_software
        search.aggs.bucket('host_info', 'nested', path='host_information') \
            .bucket('applications', 'nested', path='host_information.installed_software') \
            .bucket('names', 'terms', field='host_information.installed_software.name', size=10000) \
            .bucket('vendors', 'terms', field="host_information.installed_software.vendor", size=50)
        
        # Add a version_count per vendor and per app name
        search.aggs['host_info'].aggs['applications'].aggs['names'].aggs['vendors'] \
            .bucket('version_count', 'cardinality', field='host_information.installed_software.version')
        search.aggs['host_info'].aggs['applications'].aggs['names'].aggs['vendors'] \
            .bucket('version_count', 'cardinality', field='host_information.installed_software.version')
        
        # Add a reverse nest under vendors to get the unique endpoint count
        search.aggs['host_info'].aggs['applications'].aggs['names'].aggs['vendors'] \
            .bucket('endpoint', 'reverse_nested') \
            .bucket('endpoint_count', 'cardinality', field='name')
        
        # Add a reverse nest under names to get the unique endpoint count
        search.aggs['host_info'].aggs['applications'].aggs['names'] \
            .bucket('endpoint', 'reverse_nested') \
            .bucket('endpoint_count', 'cardinality', field='name')
        
        # Execute the search
        response = search.execute()

        # Summarize the data for each application into a list of dictionaries that look like
        # { name: <name>, version_count: <version_count>, endpoint_count: <endpoint_count> }
        applications = []
        for application in response.aggregations.host_info.applications.names.buckets:
            if len(application.vendors.buckets) > 0:
                # For each vendor in the application, add a summary
                for vendor in application.vendors.buckets:
                    applications.append({
                        'name': application.key,
                        'vendor': vendor.key,
                        'version_count': vendor.version_count.value,
                        'endpoint_count': vendor.endpoint.endpoint_count.value
                    })
            else:
                # If there are no vendors, add a summary with a blank vendor
                applications.append({
                    'name': application.key,
                    'vendor': 'N/A',
                    'version_count': application.version_count.value,
                    'endpoint_count': application.endpoint.endpoint_count.value
                })

        return {
            'total': len(applications),
            'applications': applications
        }
