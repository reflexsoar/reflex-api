from uuid import uuid4
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    DataSourceTemplate,
    DataSourceDefinition
)
from .shared import mod_pagination, ISO8601, mod_user_list
from ..utils import token_required, user_has, ip_approved

api = Namespace(
    'DataSourceTemplates', description='Manage Data Source Templates which are used to automatically assess an input for the proper MITRE ATT&CK data sources',
    path='/data_source_template', strict=True)

mod_data_source_definition_details = api.model('DataSourceDefinitionDetails', {
    'name': fields.String,
    'query': fields.String,
    'description': fields.String,
    'prerequisites': fields.String
})

mod_data_source_definition_create = api.model('DataSourceDefinitionCreate', {
    'name': fields.String(required=True),
    'query': fields.String(required=True),
    'description': fields.String(required=False),
    'prerequisites': fields.String(required=False)
})

mod_data_source_template_details = api.model('DataSourceTemplateDetails', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'sources': fields.List(fields.Nested(mod_data_source_definition_details)),
    'revision': fields.Integer,
    'is_global': fields.Boolean,
})

mod_data_source_template_create = api.model('DataSourceTemplateCreate', {
    'name': fields.String(required=True),
    'description': fields.String(required=False),
    'sources': fields.List(fields.Nested(mod_data_source_definition_create), required=False),
    'organization': fields.String(required=False),
    'is_global': fields.Boolean(required=False)
}, validate=True)

mod_data_source_template_update = api.model('DataSourceTemplateUpdate', {
    'name': fields.String,
    'description': fields.String,
    'sources': fields.List(fields.Nested(mod_data_source_definition_create)),
    'organization': fields.String,
    'is_global': fields.Boolean
})

mod_data_source_template_list = api.model('DataSourceTemplateList', {
    'templates': fields.List(fields.Nested(mod_data_source_template_details))
})

dst_parser = api.parser()
dst_parser.add_argument('organization', type=str, help='Organization', location='args')

@api.route("")
class DataSourceTemplateList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_source_template_list)
    @api.expect(dst_parser)
    @token_required
    @user_has('view_data_source_templates')
    def get(self, current_user):
        '''
        Returns a list of data source templates
        '''

        args = dst_parser.parse_args()

        templates = DataSourceTemplate.search(skip_org_check=True)

        if args.organization:
            if current_user.is_default_org():
                templates = templates.filter('bool', should=[
                    {'term': {'organization': args.organization}},
                    {'term': {'is_global': True}}
                ])
            else:
                templates = templates.filter('bool', should=[
                    {'term': {'organization': current_user.organization}},
                    {'term': {'is_global': True}}
                ])
        else:
            if not current_user.is_default_org():
                templates = templates.filter('bool', should=[
                    {'term': {'organization': current_user.organization}},
                    {'term': {'is_global': True}}
                ])

        templates = templates.scan()

        return {'templates': [t for t in templates]}

    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_source_template_details)
    @api.expect(mod_data_source_template_create, validate=True)
    @token_required
    @user_has('create_data_source_template')
    def post(self, current_user):
        '''
        Creates a new data source template
        '''

        data = api.payload

        # If the user is trying to set the organization make sure they have the proper
        # permissions to do so
        organization = current_user.organization
        if 'organization' in data:
            if current_user.is_default_org():
                organization = data['organization']

        # Prevent normal users from setting Data Source Templates as global
        is_global = False
        if 'is_global' in data:
            is_global = data['is_global']
            if not current_user.is_default_org() and is_global:
                api.abort(400, 'Cannot set the is_global field on a data source template, user not authorized')
        
        # Check to see if the template already exists by name
        existing_template = DataSourceTemplate.exists_by_field('name', data['name'], organization=organization)
        if existing_template is not None:
            api.abort(400, 'A data source template with that name already exists')

        sources = []
        if 'sources' in data:
            sources = data['sources']
        
        if data['name'] in [None, '']:
            api.abort(400, 'The Name field is required.')

        template = DataSourceTemplate(
            name=data['name'],
            description=data['description'],
            revision=1,
            organization=organization,
            sources=sources,
            is_global=is_global
        )

        template.save()

        return template

@api.route("/<string:uuid>")
class DataSourceTemplateDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_source_template_details)
    @token_required
    @user_has('view_data_source_templates')
    def get(self, current_user, uuid):
        '''
        Returns the details of a data source template
        '''

        template = DataSourceTemplate.get(uuid)

        if not template:
            api.abort(404, 'Data Source Template not found')

        if not current_user.is_default_org():
            if template.organization != current_user.organization:
                api.abort(404, 'Data Source Template not found.')

        return template
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_source_template_details)
    @api.expect(mod_data_source_template_update)
    @token_required
    @user_has('update_data_source_template')
    def put(self, current_user, uuid):
        '''
        Updates the details of a data source template
        '''

        template = DataSourceTemplate.get_by_uuid(uuid)

        if not template:
            api.abort(404, 'Data Source Template not found')

        if not current_user.is_default_org():
            if template.organization != current_user.organization:
                api.abort(404, 'Data Source Template not found.')

        data = api.payload

        if 'organization' in data and not current_user.is_default_org():
            api.abort(400, 'Cannot change the organization of a data source template, user not authorized')

        # Check to see if the template already exists by name
        if 'name' in data:

            if data['name'] in [None, '']:
                api.abort(400, 'The Name field is required.')

            existing_template = DataSourceTemplate.exists_by_field('name', data['name'], organization=template.organization)
            if existing_template is not None and existing_template.uuid != template.uuid:
                api.abort(400, 'A data source template with that name already exists')
        
        # Prevent normal users from setting Data Source Templates as global
        if 'is_global' in data:
            is_global = data['is_global']
            if not current_user.is_default_org() and is_global:
                api.abort(400, 'Cannot set the is_global field on a data source template, user not authorized')
            
            if current_user.is_default_org() and is_global and template.organization != current_user.organization:
                api.abort(400, 'Only the default organization can have global data source templates')

        template.update(**data, refresh=True)

        return template
    
    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_data_source_template')
    def delete(self, current_user, uuid):
        '''
        Deletes a data source template
        '''

        template = DataSourceTemplate.get_by_uuid(uuid)

        if not template:
            api.abort(404, 'Data Source Template not found')

        if not current_user.is_default_org():
            if template.organization != current_user.organization:
                api.abort(404, 'Data Source Template not found.')

        template.delete()

        return {'success': True}        
