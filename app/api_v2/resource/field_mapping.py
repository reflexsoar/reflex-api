
import datetime
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    FieldMappingTemplate,
    Organization,
    VALID_DATA_TYPES
)
from .shared import FormatTags, mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import check_org, token_required, user_has, ip_approved, page_results, generate_token, default_org
from .agent_group import mod_agent_group_list
from ..schemas import mod_input_list

api = Namespace(
    'FieldMappingTemplate', description='Field Mapping Template administration', path='/field_template', validate=True)


mod_field_mapping = api.model('FieldMapping', {
    'field': fields.String(required=True),
    'alias': fields.String(required=False),
    'data_type': fields.String(required=True, enum=VALID_DATA_TYPES),
    'sigma_field': fields.String(required=False),
    'tlp': fields.Integer(required=True),
    'tags': fields.List(fields.String, required=False),
}, strict=True)


mod_create_field_mapping_template = api.model('FieldMappingCreate', {
    'name': fields.String(required=True),
    'description': fields.String(required=False),
    'priority': fields.Integer(required=False, default=1),
    'tags': fields.List(fields.String, required=False),
    'field_mapping': fields.List(fields.Nested(mod_field_mapping), required=True),
    'organization': fields.String(required=False),
    'is_global': fields.Boolean(required=False, default=False)
}, strict=True)

mod_field_mapping_template_details = api.model('FieldMappingTemplateDetails', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'priority': fields.Integer,
    'field_mapping': fields.List(fields.Nested(mod_field_mapping)),
    'organization': fields.String,
    'is_global': fields.Boolean,
    'tags': fields.List(fields.String),
    'created_at': ISO8601,
    'updated_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list)
})

mod_paged_field_mapping_template_list = api.model('PagedFieldMappingTemplateList', {
    'templates': fields.List(fields.Nested(mod_field_mapping_template_details)),
    'pagination': fields.Nested(mod_pagination)
})


@api.route("/<uuid>")
class FieldMappingTemplateDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_field_mapping_template_details)
    @token_required
    @default_org
    @user_has('view_inputs')
    def get(self, uuid, user_in_default_org, current_user):

        if user_in_default_org:
            template = FieldMappingTemplate.get_by_uuid(uuid)
        else:
            template = FieldMappingTemplate.get_by_uuid(uuid, current_user.organization)

        if template:
            return template
        else:
            api.abort(404, 'Field Mapping Template not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_field_mapping_template_details)
    @api.expect(mod_create_field_mapping_template)
    @token_required
    @check_org
    @default_org
    @user_has('update_input')
    def put(self, uuid, user_in_default_org, current_user):

        if user_in_default_org:
            template = FieldMappingTemplate.get_by_uuid(uuid)
        else:
            template = FieldMappingTemplate.get_by_uuid(uuid, current_user.organization)

        if template:

            if 'name' in api.payload:
                if user_in_default_org:
                    if 'organization' in api.payload:
                        exists = FieldMappingTemplate.get_by_name(api.payload['name'], organization=api.payload['organization'])
                    else:
                        exists = FieldMappingTemplate.get_by_name(api.payload['name'], organization=template.organization)
                else:
                    exists = FieldMappingTemplate.get_by_name(api.payload['name'], template.organization)
        
                if exists and exists.uuid != uuid:
                    api.abort(409, "Field Mapping Template with this name already exists")

            template.update(**api.payload, refresh=True)
            return template
        else:
            api.abort(404, 'Field Mapping Template not found.')

    
field_mapping_template_parser = api.parser()
field_mapping_template_parser.add_argument('organization', location='args', required=False)
field_mapping_template_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
field_mapping_template_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
field_mapping_template_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
field_mapping_template_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@api.route("")
class FieldMapList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_paged_field_mapping_template_list)
    @token_required
    @default_org
    @user_has('view_inputs')
    def get(self, user_in_default_org, current_user):
        '''
        Returns a list of all field mappings
        '''

        args = field_mapping_template_parser.parse_args()

        templates = FieldMappingTemplate.search()

        if user_in_default_org:
            if args.organization:
                templates = templates.filter('term', organization=args.organization)

        sort_by = args.sort_by
        if sort_by not in ['name']:
            sort_by = 'created_at'

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        templates = templates.sort(sort_by)

        templates, total_results, pages = page_results(templates, args.page, args.page_size)

        templates = templates.execute()

        return {
            'templates': list(templates),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }

    @api.doc(security="Bearer")
    @api.expect(mod_create_field_mapping_template)
    @api.marshal_with(mod_create_field_mapping_template)
    @token_required
    @check_org
    @default_org
    @user_has('add_input')
    def post(self, user_in_default_org, current_user):
        '''
        Create a new field mapping template that can be used by inputs
        to define what fields should mapped to what data types
        '''

        field_mapping_template = None
        if user_in_default_org:
            if 'organization' in api.payload:
                field_mapping_template = FieldMappingTemplate.get_by_name(api.payload['name'], api.payload['organization'])
            else:
                field_mapping_template = FieldMappingTemplate.get_by_name(api.payload['name'])
        else:
            field_mapping_template = FieldMappingTemplate.get_by_name(api.payload['name'], current_user.organization)

        if 'organization' in api.payload:
            org = Organization.get_by_uuid(api.payload['organization'])
            if not org:
                api.abort(404, 'Organization not found.')

        if not user_in_default_org and 'is_global' in api.payload and api.payload['is_global']:
            api.abort(403, 'Only admins of the Default Organization can create global field mapping templates')

        if not field_mapping_template:
            field_mapping_template = FieldMappingTemplate(**api.payload)
            field_mapping_template.save()
        else:
            api.abort(409, 'Field Mapping Template already exists')
        
        return field_mapping_template