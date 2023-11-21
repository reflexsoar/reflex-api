import base64

from hashlib import sha256
from flask_restx import Resource, Namespace, fields, inputs as xinputs

from .shared import ISO8601, AsAttrDict, mod_user_list
from ..utils import token_required, user_has

from ..model.package import Package

api = Namespace('Package', description='Package Management', path='/package')

mod_package_brief = api.model('PackageBrief', {
    'name': fields.String(required=True, description='The Package Name'),
    'version': fields.String(required=True, description='The Package Version'),
    'description': fields.String(required=True, description='The Package Description'),
    'source': fields.String(required=True, description='The Package Source'),
    'source_checksum': fields.String(required=True, description='The Package Source Checksum'),
    'install_command': fields.String(required=True, description='The Package Install Command'),
    'install_working_directory': fields.String(required=True, description='The Package Install Working Directory'),
    'install_timeout': fields.Integer(required=True, description='The Package Install Timeout'),
    'configuration_source': fields.String(required=True, description='The Package Configuration Source'),
    'configuration_destination': fields.String(required=True, description='The Package Configuration Destination'),
    'config_checksum': fields.String(required=True, description='The Package Configuration Checksum'),
    'start_command': fields.String(required=True, description='The Package Start Command'),
    'stop_command': fields.String(required=True, description='The Package Stop Command'),
    'uninstall_command': fields.String(description='The Package Uninstall Command'),
    'reconfigure_command': fields.String(description='The Package Reconfigure Command'),
    'dependencies': fields.String(description='The Package Dependencies'),
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
    'created_at': ISO8601(required=True, description='The Package Creation Date'),
    'updated_at': ISO8601(required=True, description='The Package Last Update Date'),
    'created_by': fields.Nested(mod_user_list, description='The User that Created the Package'),
    'updated_by': fields.Nested(mod_user_list, description='The User that Last Updated the Package'),
    'organization': fields.String(required=False, description='The Organization UUID')
})

mod_package_list = api.model('PackageList', {
    'packages': fields.List(fields.Nested(mod_package), description='The List of Packages')
})

# Individual Package Operations

@api.route('<uuid>')
class PackageDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_package)
    @token_required
    @user_has('view_packages')
    def get(self, current_user, uuid):
        '''Get Package Details'''

        package = Package.get(uuid)

        if not package:
            api.abort(404, 'Package not found')

        return package
    
    @api.doc(security="Bearer")
    @api.expect(mod_package_update)
    @api.marshal_with(mod_package)
    @token_required
    @user_has('update_package')
    def put(self, current_user, uuid):
        '''Update Package'''

        package = Package.get(uuid)

        if not package:
            api.abort(404, 'Package not found')

        # If the user is supplying the organization check to see if they have access to that
        # organization
        if 'organization' in api.payload:
            if not current_user.is_default_org() and current_user.organization != api.payload['organization']:
                api.abort(403, 'Unable to update package for organization. Unauthorized.')

        # Check to see if an package with the same name and version already exists
        search = Package.search()
        search = search.filter('term', name=api.payload.get('name'))
        search = search.filter('term', version=api.payload.get('version'))

        if 'organization' in api.payload:
            search = search.filter('term', organization=api.payload['organization'])

        existing_package = search.execute()

        if existing_package:
            if existing_package[0].uuid != uuid:
                api.abort(409, 'Package with the same name and version already exists')

        # Convert the package_data string from base64 to bytes
        if 'package_data' in api.payload:
            api.payload['package_data'] = bytes(api.payload['package_data'], 'utf-8')
        
            # Calculate the checksum
            hasher = sha256()
            hasher.update(base64.b64decode(api.payload['package_data']))
            api.payload['checksum'] = hasher.hexdigest()

        package.update(**api.payload)

        return package
    
    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_package')
    def delete(self, current_user, uuid):
        '''Delete Package'''

        package = Package.get(uuid)

        if not package:
            api.abort(404, 'Package not found')

        package.delete()

        return {'success': True}


# List Packages
@api.route('')
class PackageList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_list_with(mod_package_list)
    @token_required
    @user_has('view_packages')
    def get(self, current_user):
        '''List Packages'''

        packages = Package.search().scan()
        return {'packages': [p for p in packages]}

    @api.doc(security="Bearer")
    @api.expect(mod_package_create)
    @api.marshal_with(mod_package)
    @token_required
    @user_has('create_package')
    def post(self, current_user):
        '''Create Package'''

        organization_uuid = api.payload.get('organization', None)

        # If the user is supplying the organization check to see if they have access to that
        # organization
        if organization_uuid:
            if not current_user.is_default_org() and current_user.organization != organization_uuid:
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
        if 'package_data' in api.payload:
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