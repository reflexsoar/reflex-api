import datetime
from app.api_v2.model.threat import ThreatValue
from ..utils import check_org, default_org, token_required, user_has, ip_approved, page_results
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import ThreatList, DataType, Q
from .shared import ISO8601, mod_pagination
from ... import ep


class ThreatValueList(fields.Raw):
    ''' Returns values in the correct format'''

    def format(self, value):
        return '\n'.join([v['value'] for v in value])

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

mod_threat_value = api.model('ThreatValue', {
    'value': fields.String,
    'record_id': fields.String,
    'organization': fields.String,
    'from_poll': fields.Boolean,
    'poll_interval': fields.Integer,
    'key_field': fields.String,
    'data_type': fields.String,
    'list_uuid': fields.String,
    'list_name': fields.String,
    'event_hits': fields.Integer,
    'created_at': ISO8601
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
    'values': ThreatValueList(),
    #'values_list': fields.List(fields.String, attribute='values'),
    'to_memcached': fields.Boolean,
    'active': fields.Boolean,
    'value_count': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'csv_headers': fields.String,
    'csv_headers_data_types': fields.String,
    'case_sensitive': fields.Boolean,
    'flag_ioc': fields.Boolean,
    'flag_safe': fields.Boolean,
    'flag_spotted': fields.Boolean,
    'global_list': fields.Boolean(default=False)
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
    'active': fields.Boolean(example=True),
    'csv_headers': fields.String,
    'csv_headers_data_types': fields.String,
    'case_sensitive': fields.Boolean,
    'flag_ioc': fields.Boolean,
    'flag_safe': fields.Boolean,
    'flag_spotted': fields.Boolean,
    'global_list': fields.Boolean(default=False)
})

mod_list_values = api.model('ListValues', {
    'values': fields.List(fields.String)
})

mod_list_match = api.model('ListMatch', {
    'name': fields.String,
    'value': fields.String,
    'matched': fields.Boolean
})

mod_list_multi_match = api.model('ListMultiMatch', {
    'values': fields.List(fields.String, required=True)
})

mod_list_values_paged = api.model('ListValuesPaged', {
    'values': fields.Nested(mod_threat_value),
    'pagination': fields.Nested(mod_pagination)
})

list_parser = api.parser()
list_parser.add_argument(
    'data_type', location='args', required=False)
list_parser.add_argument(
    'organization', location='args', required=False
)
list_parser.add_argument(
    'name__like', location='args', required=False
)
list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)

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

        lists = ThreatList.search(skip_org_check=True)

        # If the organization args are set and the user is not in the default org
        if current_user.is_default_org() and args.organization:
            lists = lists.filter('term', organization=args.organization)
            
        if not current_user.is_default_org():
            # Search for the current_users organization or any global_list
            lists = lists.filter(
                'bool',
                should=[
                    Q('term', organization=current_user.organization),
                    Q('term', global_list=True)
                ]
            )

        lists, total_results, pages = page_results(lists, args.page, args.page_size)

        lists = lists.execute()

        response = {
            'lists': list(lists),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
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

        Supported list types: `values|pattern|csv`

        When `url` is populated the `values` field will be ignored.

        '''

        value_list = ThreatList.get_by_name(name=api.payload['name'])

        if value_list:
            api.abort(409, "ThreatList already exists.")

        if api.payload['list_type'] not in ['values', 'patterns', 'csv']:
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
        
        if api.payload['list_type'] == 'csv':
            
            if not 'csv_headers' in api.payload:
                api.abort(400, 'CSV headers are required')

            if not 'csv_headers_data_types' in api.payload:
                api.abort(400, 'CSV header to data type mapping is required')

            mapping = {}
            headers = api.payload['csv_headers'].split(',')
            data_types = api.payload['csv_headers_data_types'].split(',')
            for i in range(0, len(headers)-1):
                if data_types[i] not in ("none","null",""):
                    if headers[i] not in mapping:
                        mapping[data_types[i]] = [headers[i]]
                    else:
                        mapping[data_types[i]].append(headers[i])

            # Store the data_type to field mapping
            api.payload['csv_header_map'] = mapping

        if 'values' in api.payload:
            _values = api.payload.pop('values')
            if not isinstance(_values, list):
                _values = _values.split('\n')
            values = []
            for value in _values:
                if value == '':
                    continue
                values.append(value)

        # TODO: Get rid of this uuid association entirely at some point
        if 'data_type_uuid' in api.payload:
            data_type = DataType.get_by_uuid(api.payload['data_type_uuid'])
            if data_type is None:
                api.abort(400, "Invalid data type")
            else:
                api.payload['data_type_name'] = data_type.name

        value_list = ThreatList(**api.payload)
        value_list.save()

        if not 'url' in api.payload:
            value_list.set_values(values)

        ep.restart_workers(organization=value_list.organization)

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

        if 'url' in api.payload and api.payload['url']:
            del api.payload['values']

            # The polling interval must exist in the URL field exists
            if 'poll_interval' not in api.payload or api.payload['poll_interval'] is None:
                api.abort(400, 'Missing poll_interval')

            # Don't let the user define an insanely fast polling interval
            if int(api.payload['poll_interval']) < 60:
                api.abort(400, 'Invalid polling interval, must be greater than or equal to 60')

        value_list = ThreatList.get_by_uuid(uuid=uuid)

        if value_list:

            if 'global_list' in api.payload:
                current_state = getattr(value_list, 'global_list')
                if current_state != api.payload['global_list'] and not current_user.is_default_org():
                    api.abort(403, 'You do not have permission to change the global_list setting.')

            if 'name' in api.payload:
                l = ThreatList.get_by_name(name=api.payload['name'])
                if l and l.uuid != uuid:
                    api.abort(
                        409, 'ThreatList with that name already exists.')

            if api.payload['list_type'] == 'csv':
            
                if not 'csv_headers' in api.payload:
                    api.abort(400, 'CSV headers are required')

                if not 'csv_headers_data_types' in api.payload:
                    api.abort(400, 'CSV header to data type mapping is required')

                mapping = {}
                headers = api.payload['csv_headers'].split(',')
                data_types = api.payload['csv_headers_data_types'].split(',')
                for i in range(0, len(headers)-1):
                    if data_types[i] not in ("none","null",""):
                        if headers[i] not in mapping:
                            mapping[data_types[i]] = [headers[i]]
                        else:
                            mapping[data_types[i]].append(headers[i])

                # Store the data_type to field mapping
                api.payload['csv_header_map'] = mapping

                # CSV lists contain multiple values so we don't set a base data_type
                #api.payload['data_type_uuid'] = 'multiple'

            if 'values' in api.payload:

                values = api.payload.pop('values').split('\n')
                if len(values) > 0:
                    value_list.set_values(values)
                    value_list.remove_values(values)

            # Update the list with all other fields
            if len(api.payload) > 0:
                value_list.update(**api.payload, refresh=True)
                ep.restart_workers()

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
            values = ThreatValue.search()
            values = values.filter('term', list_uuid=value_list.uuid)
            value_list.delete()
            values.delete()
            
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


@api.route('/test/<uuid>/<value>')
class ThreatListTest(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_list_match)
    @token_required
    @user_has('view_lists')
    def get(self,current_user, uuid,value):

        intel_list = ThreatList.get_by_uuid(uuid)
        if intel_list:
            if intel_list.check_value(value):
                return {
                    'name': intel_list.name,
                    'value': value,
                    'matched': True
                }
            else:
                return {
                    'name': intel_list.name,
                    'value': value,
                    'matched': False
                }
        else:
            api.abort(404, {'message': 'Intel List not found'})

@api.route('/test/<uuid>')
class ThreatListMultiTest(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_list_multi_match)
    @token_required
    @user_has('view_lists')
    def post(self, current_user, uuid):
        '''
        Takes a list of values to check against a list.  If the value appears
        in the list add it to a dictionary of matched values with the value
        as a key and True as the value.
        '''

        if 'values' not in api.payload or len(api.payload['values']) == 0:
            api.abort(400, 'Values are required.')

        if len(api.payload['values']) > 10000:
            api.abort(400, 'Too many values.  Can not exceed 10000 values.')

        values = ThreatValue.find(list_uuid=uuid, values=api.payload['values'])

        return {v['value']: True for v in values}


list_stats_parser = api.parser()
list_stats_parser.add_argument('list', location='args', type=str, action='split', required=False)
list_stats_parser.add_argument('value', location='args', type=str, action='split', required=False)
list_stats_parser.add_argument('value__like', location='args', type=str, required=False)
list_stats_parser.add_argument('list_name__like', location='args', type=str, required=False)
list_stats_parser.add_argument('record_id', location='args', type=str, required=False)
list_stats_parser.add_argument('data_type', location='args', type=str, action='split', required=False)
list_stats_parser.add_argument('from_poll', location='args', type=xinputs.boolean, required=False)
list_stats_parser.add_argument('top', location='args', default=10, type=int, required=False)
list_stats_parser.add_argument('start', location='args', default=(datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
list_stats_parser.add_argument('end', location='args', default=(datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
list_stats_parser.add_argument('interval', location='args', default='day', required=False, type=str)
list_stats_parser.add_argument('metrics', location='args', action='split', default=['list','value','data_type','from_poll'])
list_stats_parser.add_argument('organization', location='args', action='split', required=False)
@api.route('/stats')
class IntelListStats(Resource):

    @api.doc(security="Bearer")
    @api.expect(list_stats_parser)
    @token_required
    @user_has('view_lists')
    def get(self, current_user):
        
        args = list_stats_parser.parse_args()
        
        search_filters = []

        if args.value__like and args.value__like != '':
            search_filters.append({
                'type': 'wildcard',
                'field': 'value',
                'value': "*"+args.value__like+"*"
            })

        if args.list_name__like and args.list_name__like != '':
            search_filters.append({
                'type': 'wildcard',
                'field': 'list_name',
                'value': "*"+args.list_name__like.lower().replace(' ','_')+"*"
            })

        if args.list and args.list != '':
            search_filters.append({
                'type': 'terms',
                'field': 'list_uuid',
                'value': args.list
            })

        if args.value and args.value != '':
            search_filters.append({
                'type': 'terms',
                'field': 'value',
                'value': args.value
            })

        if args.data_type and args.data_type != '':
            search_filters.append({
                'type': 'terms',
                'field': 'data_type',
                'value': args.data_type
            })

        if args.from_poll and args.from_poll != '':
            search_filters.append({
                'type': 'term',
                'field': 'from_poll',
                'value': args.from_poll
            })

        if args.record_id and args.record_id != '':
            search_filters.append({
                'type': 'term',
                'field': 'record_id',
                'value': args.record_id
            })

        search = ThreatValue.search()        

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        search.aggs.bucket('range', 'filter', range={'created_at': {
                        'gte': args.start,
                        'lte': args.end
                    }})

        if 'list' in args.metrics:
            search.aggs['range'].bucket('lists', 'terms', field='list_uuid', size=args.top)

        if 'value' in args.metrics:
            search.aggs['range'].bucket('values', 'terms', field='value', size=args.top)

        if 'data_type' in args.metrics:
            search.aggs['range'].bucket('data_types', 'terms', field='data_type', size=args.top)

        if 'from_poll' in args.metrics:
            search.aggs['range'].bucket('from_poll', 'terms', field='from_poll', size=args.top)

        search = search[0:0]
        
        values = search.execute()

        search = ThreatList.search()

        search = search.filter('terms', uuid=[v['key'] for v in values.aggs.range.lists.buckets])

        search = search[0:args.top]
        lists = list(search.scan())

        data = {}

        if 'list' in args.metrics:
            data['list'] = {v['key']: v['doc_count'] for v in values.aggs.range.lists.buckets}

        if 'value' in args.metrics:
            data['value'] = {v['key']: v['doc_count'] for v in values.aggs.range.values.buckets}

        if 'data_type' in args.metrics:
            data['data_type'] = {v['key']: v['doc_count'] for v in values.aggs.range.data_types.buckets}

        if 'from_poll' in args.metrics:
            data['from_poll'] = {v['key']: v['doc_count'] for v in values.aggs.range.from_poll.buckets}

        data['lists'] = {l.uuid: l.name for l in lists}
        
        return data

list_value_parser = api.parser()
list_value_parser.add_argument('list', location='args', action='split', required=False)
list_value_parser.add_argument('value', location='args', action='split', required=False)
list_value_parser.add_argument('data_type', location='args', action='split', required=False)
list_value_parser.add_argument('from_poll', location='args', type=xinputs.boolean, required=False)
list_value_parser.add_argument('value__like', location='args', required=False)
list_value_parser.add_argument('list_name__like', location='args', required=False)
list_value_parser.add_argument('record_id', location='args', type=str, required=False)
list_value_parser.add_argument('organization', location='args', required=False)
list_value_parser.add_argument('page', type=int, location='args', default=1, required=False)
list_value_parser.add_argument('page_size', type=int, location='args', default=10, required=False)
@api.route('/values')
class IntelListValues(Resource):

    @api.doc(security="Bearer")
    @api.expect(list_value_parser)
    @api.marshal_with(mod_list_values_paged)
    @token_required
    @default_org
    @user_has('view_lists')
    def get(self, user_in_default_org, current_user):

        args = list_value_parser.parse_args()

        lists = None

        if args.list_name__like:
            intel_list = ThreatList.search()

            if user_in_default_org and args.organization:
                intel_list = intel_list.filter('term', organization=args.organization)

            intel_list = intel_list.filter('wildcard', name=args.list_name__like+"*")
            lists = list(intel_list.scan())
        
        values = ThreatValue.search()

        if args.list:
            if lists:
                args.list += [l.uuid for l in lists]
            values = values.filter('terms', list_uuid=args.list)
        elif lists:
            values = values.filter('terms', list_uuid=[l.uuid for l in lists])

        if args.value:
            values = values.filter('terms', value=args.value)

        if args.data_type:
            values = values.filter('terms', data_type=args.data_type)

        if args.from_poll:
            values = values.filter('term', from_poll=args.from_poll)

        if args.record_id:
            values = values.filter('term', record_id=args.record_id)

        values, total_results, pages = page_results(values, args.page, args.page_size)

        values = values.execute()

        response = {
            'values': list(values),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response


@api.route("/<uuid>/replace_values")
class ReplaceValuesInThreatList(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_list_values)
    @token_required
    @user_has('update_list')
    def put(self, uuid, current_user):
        ''' Replaces all the values in the list with the values
        provided in the API call'''

        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:

            #if current_user.has_org_permission(value_list.organization, 'update_list') is False:
            #    api.abort(403, 'You do not have permission to update this list.')

            if 'values' in api.payload and api.payload['values'] not in [None, '']:
                tv = ThreatValue.search()
                tv = tv.filter('term', list_uuid=uuid)
                tv.delete()
                value_list.set_values(api.payload['values'])
                return {'message': 'Succesfully replaced values in list.'}    
            api.abort(400, {'message':'Values are required.'})
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

            #if current_user.has_org_permission(value_list.organization, 'update_list') is False:
            #    api.abort(403, 'You do not have permission to update this list.')

            if 'values' in api.payload and api.payload['values'] not in [None,'']:
                value_list.set_values(api.payload['values'])
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
            #if current_user.has_org_permission(value_list.organization, 'update_list') is False:
            #    api.abort(403, 'You do not have permission to update this list.')

            if 'values' in api.payload:
                values = ThreatValue.search()
                values = values.filter('term', list_uuid=uuid)
                values = values.filter('terms', values=api.payload['values'])
                values.delete()
                
                return {'message': 'Succesfully removed values from list.'}
            api.abort(400, {'message':'Values are required.'})
        api.abort(404, 'ThreatList not found.')