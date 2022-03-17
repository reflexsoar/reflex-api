from ..utils import check_org, default_org, token_required, user_has, ip_approved, page_results
from flask_restx import Resource, Namespace, fields
from ..model import ThreatList, DataType
from .shared import ISO8601, ValueCount, AsNewLineDelimited, mod_pagination

api = Namespace('Lists', description="Intel List operations", path="/list")

mod_data_type_list = api.model('DataTypeList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'regex': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_list_list = api.model('ListView', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'list_type': fields.String,
    'tag_on_match': fields.Boolean,
    'data_type': fields.Nested(mod_data_type_list),
    'url': fields.String,
    'poll_interval': fields.Integer,
    'last_polled': ISO8601(attribute='last_polled'),
    'values': AsNewLineDelimited(attribute='values'),
    #'values_list': fields.List(fields.String, attribute='values'),
    'to_memcached': fields.Boolean,
    'active': fields.Boolean,
    'value_count': ValueCount(attribute='values'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_list_list_paged = api.model('ListViewPaged', {
    'lists': fields.Nested(mod_list_list),
    'pagination': fields.Nested(mod_pagination)
})

mod_list_create = api.model('ListCreate', {
    'name': fields.String(required=True, example='SpamHaus eDROP'),
    'organization': fields.String,
    'list_type': fields.String(required=True, example='values'),
    'tag_on_match': fields.Boolean(example=False),
    'data_type_uuid': fields.String(required=True),
    'values': fields.String(example='127.0.0.1\n4.4.4.4\n1.1.1.1'),
    'polling_interval': fields.Integer(example=3600),
    'url': fields.Url(description='A URL to pull threat data from', example='https://www.spamhaus.org/drop/edrop.txt'),
    'to_memcached': fields.Boolean,
    'active': fields.Boolean(example=True)
})

mod_list_values = api.model('ListValues', {
    'values': fields.List(fields.String)
})

list_parser = api.parser()
list_parser.add_argument(
    'data_type', location='args', required=False)
list_parser.add_argument(
    'organization', location='args', required=False
)
list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@api.route("")
class ThreatListList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_list_list_paged, as_list=True)
    @api.expect(list_parser)
    @token_required
    @default_org
    @user_has('view_lists')
    def get(self, user_in_default_org, current_user):
        ''' Returns a list of ThreatLists '''

        args = list_parser.parse_args()

        lists = ThreatList.search()

        if args.data_type:
            data_type = DataType.get_by_name(name=args.data_type)
            if data_type:
                lists = lists.filter('term', data_type_uuid=data_type.uuid)

        if user_in_default_org and args.organization:
            lists = lists.filter('term', organization=args.organization)

        #lists, total_results, pages = page_results(lists, args.page, args.page_size)

        lists = list(lists.scan())

        response = {
            'lists': lists,
            'pagination': {
                'total_results': len(lists),
                'pages': 1,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }
        
        return response

    @api.doc(security="Bearer")
    @api.expect(mod_list_create, validate=True)
    @api.marshal_with(mod_list_list)
    @api.response('409', 'ThreatList already exists.')
    @api.response('200', "Successfully created the list.")
    @token_required
    @user_has('add_list')
    def post(self, current_user):
        '''Creates a new ThreatList
        
        A threat list is what the system uses to determine if an observable
        is malicious or suspicious in nature.  ThreatLists can be consumed
        via target URLs or manually entered in to the system, or added to
        via the API. 

        Supported list types: `values|pattern`

        When `url` is populated the `values` field will be ignored.

        '''

        value_list = ThreatList.get_by_name(name=api.payload['name'])

        if value_list:
            api.abort(409, "ThreatList already exists.")

        if api.payload['list_type'] not in ['values', 'patterns']:
            api.abort(400, "Invalid list type.")

        # Remove any values entered by the user as they also want to pull
        # from a URL and the URL will overwrite their additions
        if 'url' in api.payload:
            del api.payload['values']

            # The polling interval must exist in the URL field exists
            if 'poll_interval' not in api.payload or api.payload['poll_interval'] is None:
                api.abort(400, 'Missing poll_interval')

            # Don't let the user define an insanely fast polling interval
            if int(api.payload['poll_interval']) < 60:
                api.abort(400, 'Invalid polling interval, must be greater than or equal to 60')


        if 'values' in api.payload:
            _values = api.payload.pop('values')
            if not isinstance(_values, list):
                _values = _values.split('\n')
            values = []
            for value in _values:
                if value == '':
                    continue
                values.append(value)

            api.payload['values'] = values

        if 'data_type_uuid' in api.payload and DataType.get_by_uuid(api.payload['data_type_uuid']) is None:
            api.abort(400, "Invalid data type")

        value_list = ThreatList(**api.payload)
        value_list.save()
        return value_list            


@api.route("/<uuid>")
class ThreatListDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_list_create)
    @api.marshal_with(mod_list_list)
    @token_required
    @user_has('update_list')
    @check_org
    def put(self, uuid, current_user):
        ''' Updates a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:

            if 'name' in api.payload:
                l = ThreatList.get_by_name(name=api.payload['name'])
                if l and l.uuid != uuid:
                    api.abort(
                        409, 'ThreatList with that name already exists.')

            if 'values' in api.payload:

                # Get the current values in the list
                if value_list.values:
                    current_values = [v for v in value_list.values]
                else:
                    current_values = []

                # Determine what the new values should be, current, new or removed
                _values = api.payload.pop('values')

                # Detect if the user sent it as a list or a \n delimited string
                if _values and not isinstance(_values, list):
                    _values = _values.split('\n')
                else:
                    _values = []

                removed_values = [
                    v for v in current_values if v not in _values and v != '']
                new_values = [
                    v for v in _values if v not in current_values and v != '']

                # For all values not in the new list
                # delete them from the database and disassociate them
                # from the list
                for v in removed_values:
                    value_list.values.remove(v)

                for v in new_values:
                    if value_list.values:
                        value_list.values.append(v)
                    else:
                        value_list.values = [v]

                # Dedupe
                value_list.values = list(set(value_list.values))

                value_list.save()

            # Update the list with all other fields
            if len(api.payload) > 0:
                value_list.update(**api.payload)

            return value_list
        else:
            api.abort(404, 'ThreatList not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_list')
    def delete(self, uuid, current_user):
        ''' Removes a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            value_list.delete()
            return {'message': 'ThreatList successfully delete.'}
        else:
            api.abort(404, 'ThreatList not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_list_list)
    @token_required
    @user_has('view_lists')
    def get(self, uuid, current_user):
        ''' Gets the details of a ThreatList '''

        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            return value_list
        else:
            api.abort(404, 'ThreatList not found.')


@api.route("/<uuid>/add_value")
class AddValueToThreatList(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_list_values)
    @token_required
    @user_has('update_list')
    def put(self, uuid, current_user):
        ''' Adds values to a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:

            if 'values' in api.payload and api.payload['values'] not in [None,'']:
                if not value_list.values:
                    value_list.values = []

                [value_list.values.append(v) for v in api.payload['values'] if v not in value_list.values]

                value_list.save()
                return {'message': 'Succesfully added values to list.'}
            else:
                api.abort(400, {'message':'Values are required.'})
        else:
            api.abort(404, 'ThreatList not found.')


@api.route('/<uuid>/remove_value')
class RemoveValueFromThreatList(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_list_values)
    @token_required
    @user_has('update_list')
    def delete(self, uuid, current_user):
        ''' Deletes values from a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:

            if 'values' in api.payload and api.payload['values'] not in [None,'']:
                value_list.values = [v for v in value_list.values if v not in api.payload['values']]
                value_list.save()
                return {'message': 'Succesfully removed values from list.'}
            else:
                api.abort(400, {'message':'Values are required.'})
        else:
            api.abort(404, 'ThreatList not found.')