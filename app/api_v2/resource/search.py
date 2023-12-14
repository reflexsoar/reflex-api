import re
import math
import uuid
from flask_restx import Resource, Namespace, fields

from ..utils import token_required, user_has
from .shared import ISO8601, mod_user_list

from app.api_v2.model import Event, Case, EventRelatedObject, AgentLogMessage, Search

api = Namespace('Search', description='Search Workspace', path='/search')

mod_search_filter = api.model('SearchFilter', {
    'field': fields.String(required=True),
    'value': fields.List(fields.String(required=True)),
    'operator': fields.String(required=True),
    'active': fields.Boolean(required=True),
    'exclude': fields.Boolean(required=True)
})

mod_date_range = api.model('DateRange', {
    'start': fields.String(required=True),
    'end': fields.String(required=True)
})

mod_search_query = api.model('SearchQuery', {
    'query': fields.String(required=True),
    'dataset': fields.String(required=True),
    'index': fields.String(required=False),
    'filters': fields.List(fields.Nested(mod_search_filter), required=False),
    'date_range': fields.Nested(mod_date_range, required=False)
})

mod_search_results = api.model('SearchResults', {
    'response': fields.Raw(),
    'pages': fields.Integer(),
    'search_id': fields.String(),
    'details': fields.Raw(),
    'timefield': fields.String()
})


@api.route("/query")
class HuntingQuery(Resource):

    @token_required
    @api.expect(mod_search_query)
    @api.marshal_with(mod_search_results)
    def post(self, current_user):

        dataset_mapping = {
            'events': Event,
            'cases': Case,
            'artifacts': EventRelatedObject,
            'agent-logs': AgentLogMessage,
            'logs': None
        }

        page_size = 500
        page = 1
        if page == 1:
            start_from = 0
        else:
            start_from = page_size * page

        date_field = '@timestamp'

        if 'datefield' in api.payload:
            date_field = api.payload['datefield']

        if 'dataset' not in api.payload:
            api.abort(400, 'Dataset is required.')

        # if 'dataset' in api.payload and api.payload['dataset'] not in dataset_mapping:
        #    api.abort(400, 'Invalid dataset.')

        if 'query' not in api.payload:
            api.abort(400, 'Query is required.')

        if api.payload['dataset'] not in dataset_mapping:

            # This will be a proxied search, we need to return a search_id and
            # tell a search proxy agent to complete the search, the UI will then
            # monitor the search using search-status and get the results from
            # the search-results endpoint
            index = api.payload['dataset']

            # We don't want to allow users to search certain system indexes
            if index == '*' or index.startswith('reflex') or index.startswith('*') or index.startswith('.'):
                api.abort(400, 'Invalid dataset.')

            # If the index has a wildcard check if it would match against the word reflex and
            # if it does then abort
            if '*' in index:
                expression = re.compile(index.replace('*', '.*'))
                if expression.match('reflex'):
                    api.abort(400, 'Invalid dataset.')

            # Create a search against an index using the global connection
            search = Search(index=index)
        else:
            search = dataset_mapping[api.payload['dataset']].search()

            date_field = 'created_at'

        search = search.query('query_string', query=api.payload['query'])

        if 'filters' in api.payload:
            _not_filters = []
            filter_map = {}
            for f in api.payload['filters']:
                if f['exclude']:
                    search = search.exclude(
                        'match_phrase', **{f['field']: f['value']})
                else:
                    search = search.filter(
                        'match_phrase', **{f['field']: f['value']})

            extended_bounds = None

            if 'date_range' in api.payload:

                start = None
                end = None
                if 'start' in api.payload['date_range']:
                    start = api.payload['date_range']['start']

                if 'end' in api.payload['date_range']:
                    end = api.payload['date_range']['end']

                if start is None:
                    start = 'now-15m'

                # If only a start is provided
                if start and not end:
                    search = search.filter(
                        'range', **{date_field: {'gte': start}})

                # If only an end is provided
                if end and not start:
                    search = search.filter(
                        'range', **{date_field: {'lte': end}})

                # If both are provided
                if start and end:
                    search = search.filter(
                        'range', **{date_field: {'gte': start, 'lte': end}})

                if start is not None:
                    if '+' in start:
                        extended_bounds = {
                            'max': start
                        }

                        if end is not None:
                            extended_bounds['min'] = end
                    else:
                        extended_bounds = {
                            'min': start
                        }

                        if end is not None:
                            extended_bounds['max'] = end

            bucket_options = {
                'field': date_field,
                'fixed_interval': '12h',
                'min_doc_count': 0
            }

            if extended_bounds is not None:
                bucket_options['extended_bounds'] = extended_bounds

            search.aggs.bucket(
                'time_buckets', 'date_histogram', **bucket_options)

            # Set the search size to 500
            search = search[0:500]

            search_dict = search.to_dict()

            try:
                results = search.execute()
            except Exception as e:
                api.abort(400, f'Invalid search. {e}')

            # Calculate the number of pages based on the page size

            if 'page_size' in api.payload:
                page_size = api.payload['page_size']

            pages = math.ceil(results.hits.total.value / page_size)

            response = {
                'response': results.to_dict(),
                'pages': pages,
                # TODO: This will be used for the search proxy
                'search_id': str(uuid.uuid4()),
                'details': search_dict,
                'timefield': date_field
            }

            return response
