import base64
import datetime
import fnmatch
import json

from flask_restx import Namespace, Resource, fields
from flask_restx import inputs as xinputs

from ..model import Input
from ..utils import default_org, page_results, token_required, user_has
from .shared import ISO8601, JSONField, mod_pagination

api = Namespace(
    'Input', description='Input related information', path='/input')

mod_input_list = api.model('InputList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'plugin': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String,
    'tags': fields.List(fields.String),
    'config': JSONField(attribute="_config"),
    'field_mapping': JSONField(attribute="_field_mapping"),
    'field_mapping_templates': fields.List(fields.String),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'index_fields': fields.List(fields.String),
    'index_fields_last_updated': ISO8601(attribute='index_fields_last_updated'),
    'sigma_backend': fields.String,
    'sigma_pipeline': fields.String,
    'sigma_field_mapping': fields.String,
    'mitre_data_sources': fields.List(fields.String)
})

mod_input_list_paged = api.model('InputListPaged', {
    'inputs': fields.Nested(mod_input_list),
    'pagination': fields.Nested(mod_pagination)
})

mod_input_create = api.model('CreateInput', {
    'name': fields.String,
    'organization': fields.String,
    'description': fields.String,
    'plugin': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String(required=True),
    'tags': fields.List(fields.String),
    'config': fields.String,
    'field_mapping': fields.String,
    'field_mapping_templates': fields.List(fields.String),
    'sigma_backend': fields.String,
    'sigma_pipeline': fields.String,
    'sigma_field_mapping': fields.String,
    'mitre_data_sources': fields.List(fields.String)
})
mod_input_list_brief = api.model('InputBrief', {
    'uuid': fields.String,
    'name': fields.String
})

mod_input_index_fields = api.model('InputIndexFields', {
    'index_fields': fields.List(fields.String)
})


input_list_parser = api.parser()
input_list_parser.add_argument('name', location='args', required=False)
input_list_parser.add_argument('organization', location='args', required=False)
input_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
input_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
input_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
input_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)
input_list_parser.add_argument(
    'mitre_data_sources', type=str, location='args', required=False, action='split'
)


@api.route("")
class InputList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_list_paged, as_list=True)
    @api.expect(input_list_parser)
    @token_required
    @default_org
    @user_has('view_inputs')
    def get(self, user_in_default_org, current_user):
        ''' Returns a list of inputs '''

        args = input_list_parser.parse_args()

        inputs = Input.search()

        if user_in_default_org:
            if args.organization:
                inputs = inputs.filter('term', organization=args.organization)

        if args.name:
            inputs = inputs.filter('wildcard', name=args.name+'*')

        if args.mitre_data_sources:
            inputs = inputs.filter('terms', mitre_data_sources=args.mitre_data_sources)

        inputs, total_results, pages = page_results(
            inputs, args.page, args.page_size)

        sort_by = args.sort_by
        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        inputs = inputs.sort(sort_by)

        inputs = inputs.execute()

        response = {
            'inputs': list(inputs),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_input_create)
    @api.response('409', 'Input already exists.')
    @api.response('200', 'Successfully create the input.')
    @token_required
    @default_org
    @user_has('add_input')
    def post(self, user_in_default_org, current_user):
        ''' Creates a new input '''
        _tags = []

        if user_in_default_org:
            if 'organization' in api.payload:
                inp = Input.get_by_name(
                    name=api.payload['name'], organization=api.payload['organization'])
            else:
                inp = Input.get_by_name(
                    name=api.payload['name'], organization=current_user.organization)
        else:
            inp = Input.get_by_name(
                name=api.payload['name'], organization=current_user.organization)

        if not inp:

            if 'credential' in api.payload:
                cred_uuid = api.payload.pop('credential')
                api.payload['credential'] = cred_uuid

            # Strip the organization field if the user is not a member of the default
            # organization
            # TODO: replace with @check_org wrapper
            if 'organization' in api.payload and hasattr(current_user, 'default_org') and not current_user.default_org:
                api.payload.pop('organization')

            if 'config' in api.payload:
                try:
                    api.payload['config'] = json.loads(base64.b64decode(
                        api.payload['config']).decode('ascii').strip())
                except Exception:
                    api.abort(
                        400, 'Invalid JSON configuration, check your syntax')

            if 'field_mapping' in api.payload:
                try:
                    api.payload['field_mapping'] = json.loads(base64.b64decode(
                        api.payload['field_mapping']).decode('ascii').strip())
                except Exception:
                    api.abort(
                        400, 'Invalid JSON in field_mapping, check your syntax')
            else:
                api.abort(
                    400, 'Field mappings are required.'
                )

            inp = Input(**api.payload)
            inp.save()

            if len(_tags) > 0:
                inp.tags += _tags
                inp.save()
        else:
            api.abort(409, 'Input already exists.')
        return {'message': 'Successfully created the input.'}


@api.route("/<uuid>")
class InputDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('view_inputs')
    def get(self, uuid, current_user):
        ''' Returns information about an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            return inp
        else:
            api.abort(404, 'Input not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_input_create)
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('update_input')
    def put(self, uuid, current_user):
        ''' Updates information for an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            if 'name' in api.payload and Input.get_by_name(name=api.payload['name']):
                api.abort(409, 'Input name already exists.')
            else:
                inp.update(**api.payload)
                return inp
        else:
            api.abort(404, 'Input not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_input')
    def delete(self, uuid, current_user):
        ''' Deletes an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            inp.delete()
            return {'message': 'Sucessfully deleted input.'}


input_list_index_fields_parser = api.parser()
input_list_index_fields_parser.add_argument(
    'name__like', location='args', required=False
)
input_list_index_fields_parser.add_argument(
    'organization', location='args', required=False
)
input_list_index_fields_parser.add_argument(
    'limit', type=int, location='args', default=25, required=False
)


@api.route("/<uuid>/index_fields")
class InputIndexFields(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_index_fields)
    @api.expect(input_list_index_fields_parser)
    @token_required
    @default_org
    @user_has('view_inputs')
    def get(self, uuid, user_in_default_org, current_user):

        args = input_list_index_fields_parser.parse_args()

        if args.limit > 100:
            api.abort(400, "'limit' can not exceed 1000")

        inp = Input.search()
        inp = inp.filter('term', uuid=uuid)

        if user_in_default_org and args.organization:
            inp = inp.filter('term', organization=args.organization)

        inp = inp.execute()

        if inp:
            inp = inp[0]

            if hasattr(inp, 'index_fields') and inp.index_fields != None:
                fields = inp.index_fields
            else:
                fields = []

            if args.name__like and len(fields) > 0:
                fields = fnmatch.filter(fields, f"{args.name__like}*")

            return {
                'index_fields': fields[0:args.limit]
            }
        else:
            api.abort(404, 'Input not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_input_index_fields)
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('update_input')
    def put(self, uuid, current_user):
        '''
        Updates the fields that an input may have associated with its underlying indices
        '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            if 'index_fields' in api.payload and api.payload['index_fields'] != None:
                inp.update(
                    index_fields=api.payload['index_fields'],
                    index_fields_last_updated=datetime.datetime.utcnow(),
                    refresh=True)
        else:
            api.abort(404, 'Input not found.')
