import base64

from hashlib import sha256
from flask_restx import Resource, Namespace, fields, inputs as xinputs

from .shared import ISO8601, AsAttrDict, mod_user_list
from ..utils import token_required, user_has

from ..model.package import Package

api = Namespace('Package', description='Package Management', path='/package')

mod_package_brief = api.model('PackageBrief', {
    'uuid': fields.String(required=True, description='The Package UUID'),
    'name': fields.String(required=True, description='The Package Name'),
    'filename': fields.String(required=True, description='The Package Filename'),
    'version': fields.String(required=True, description='The Package Version'),
    'description': fields.String(required=True, description='The Package Description'),
    'start_command': fields.String(required=True, description='The Package Start Command'),
    'stop_command': fields.String(required=True, description='The Package Stop Command'),
    'install_command': fields.String(description='The Package Install Command'),
    'uninstall_command': fields.String(description='The Package Uninstall Command'),
    'variables': fields.Nested(AsAttrDict, description='The Package Variables')
})

mod_package_create = api.inherit('PackageCreate', mod_package_brief, {
    'package_data': fields.String(required=True, description='The Package Data'),
    'organization': fields.String(required=False, description='The Organization UUID')
})

mod_package_update = api.model('PackageUpdate', {
    'name': fields.String(description='The Package Name'),
    'version': fields.String(description='The Package Version'),
    'description': fields.String(description='The Package Description'),
    'package_data': fields.String(description='The Package Data'),
    'start_command': fields.String(description='The Package Start Command'),
    'stop_command': fields.String(description='The Package Stop Command'),
    'install_command': fields.String(description='The Package Install Command'),
    'uninstall_command': fields.String(description='The Package Uninstall Command'),
    'organization': fields.String(description='The Organization UUID')
})

mod_package = api.inherit('Package', mod_package_brief, {
    'uuid': fields.String(required=True, description='The Package UUID'),
    'package_type': fields.String(required=True, description='The Package Type'),
    'checksum': fields.String(required=True, description='The Package Checksum'),
    'created_at': ISO8601(required=True, description='The Package Creation Date'),
    'updated_at': ISO8601(required=True, description='The Package Last Update Date'),
    'created_by': fields.Nested(mod_user_list, description='The User that Created the Package'),
    'updated_by': fields.Nested(mod_user_list, description='The User that Last Updated the Package'),
    'organization': fields.String(required=False, description='The Organization UUID')
})

mod_package_list = api.model('PackageList', {
    'packages': fields.List(fields.Nested(mod_package), description='The List of Packages')
})

# List Packages
@api.route('')
class PackageList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_list_with(mod_package_list)
    @token_required
    #@user_has('view_packages')
    def get(self, current_user):
        '''List Packages'''

        packages = Package.search().scan()
        return {'packages': [p for p in packages]}

    @api.doc(security="Bearer")
    @api.expect(mod_package_create)
    @api.marshal_with(mod_package)
    @token_required
    #@user_has('create_package')
    def post(self, current_user):
        '''Create Package'''

        organization_uuid = api.payload.get('organization', None)

        # If the user is supplying the organization check to see if they have access to that
        # organization
        if organization_uuid:
            if not current_user.is_default_org() and current_user.organization.uuid != organization_uuid:
                api.abort(403, 'Unable to create package for organization. Unauthorized.')

        # Check to see if an package with the same name and version already exists
        package = Package.search()
        package = package.filter('term', name=api.payload.get('name'))
        package = package.filter('term', version=api.payload.get('version'))
        
        if organization_uuid:
            package = package.filter('term', organization=organization_uuid)

        package = package.execute()

        if package:
            api.abort(409, 'Package with the same name and version already exists')


        # Convert the package_data string from base64 to bytes
        api.payload['package_data'] = bytes(api.payload['package_data'], 'utf-8')
        
        # Calculate the checksum
        hasher = sha256()
        hasher.update(base64.b64decode(api.payload['package_data']))
        api.payload['checksum'] = hasher.hexdigest()

        # Create the package
        package = Package(**api.payload)

        package.save()
        
        return package

# Update Package

# Delete Package