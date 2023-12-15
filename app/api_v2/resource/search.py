import re
import math
import uuid
import random
import json
from flask_restx import Resource, Namespace, fields
from flask import render_template, make_response, request
from flask_socketio import send, emit, join_room, leave_room

from ..utils import _check_token, token_required, user_has
from .shared import ISO8601, mod_user_list

from app.api_v2.model import (
    Event, Case, EventRelatedObject, AgentLogMessage, Search,
    SearchProxyJob, Agent
)

from app.api_v2.utils import _check_token

from app import sock

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
    'timefield': fields.String(),
    'proxied': fields.Boolean(),
    'search_channel': fields.String(),
    'total_results': fields.Integer()
})

@api.route("/proxy_jobs/<uuid>/status")
class ProxyJobStatus(Resource):

    @api.doc(security='Bearer')
    @token_required
    def get(self, current_user, uuid):
        ''' Returns the status of a single proxy job '''

        job = SearchProxyJob.get_by_uuid(uuid)

        if job is None:
            api.abort(404, 'Job not found.')

        return {
            'status': job.status
        }

@api.route("/proxy_jobs")
class ProxyJobList(Resource):

    @api.doc(security='Bearer')
    @token_required
    def get(self, current_user):\
    
        jobs = SearchProxyJob.search().filter('term', complete=False).execute()

        return {
            'response': jobs.to_dict()
        }

@api.route("/query")
class HuntingQuery(Resource):

    @api.doc(security='Bearer')
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

            api.payload['timefield'] = date_field

            proxy_job = SearchProxyJob(
                job_details=api.payload,
                status='pending',
                complete=False
            )
            proxy_job.save(refresh='wait_for')

            response = {
                'response': [],
                'pages': 0,
                'details': {},
                'timefield': date_field,
                'proxied': True,
                'search_id': proxy_job.uuid,
                'search_channel': f"{proxy_job.uuid}:{proxy_job.organization}",
                'total_results': 0
            }

            return response

        else:
            search = dataset_mapping[api.payload['dataset']].search()

            date_field = 'created_at'

        search = search.query('query_string', query=api.payload['query'])

        # Default sort by the date_field with the newest first
        search = search.sort({date_field: {'order': 'desc'}})

        if 'filters' in api.payload:
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
                'fixed_interval': '12h', # TODO: Make this configurable or auto
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

            proxy_job = SearchProxyJob(
                job_details=api.payload,
                status='complete',
                complete=True
            )
            proxy_job.save(refresh='wait_for')

            response = {
                'response': results.to_dict(),
                'pages': pages,
                'search_id': proxy_job.uuid,
                'proxied': False,
                'search_channel': f"{proxy_job.uuid}:{proxy_job.organization}",
                'details': search_dict,
                'timefield': date_field,
                'total_results': results.hits.total.value
            }

            return response

"""
WEBSOCKET HANDLERS
"""

def ws_token_required(f):
    """
    Checks the clients HTTP headers for an authorization token
    and if it is valid then the current_user is set to the
    user object for the token.  If the token is invalid then
    the current_user is set to None.  Also attempts to
    split the room name into the search_uuid and organization
    """

    def wrapper(*args, **kwargs):
        
        current_user = None
        search_uuid = None
        organization = None
        room = None

        try:
            current_user = _check_token()
        except Exception as e:
            pass

        return f(*args, **kwargs, current_user=current_user)

    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper

def room_required(f):

    def wrapper(*args, **kwargs):

        room = None
        search_uuid = None
        organization = None

        data = args[0]
        if data and isinstance(data, dict):
            if 'room' in data:
                room = data['room']
                search_uuid, organization = room.split(':')

        return f(*args, **kwargs, search_uuid=search_uuid, organization=organization, room=room)

    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper

def check_user_permissions(user, organization):
    """
    Returns True if the user a member of the provided
    organization or if the user is a default org user
    """

    if user:
        if user.is_default_org():
            return True
    
        if user.organization == organization:
            return True
    
    return False

@sock.on('join-agent-sp-control')
@ws_token_required
def agent_control(data, current_user):
    """ Joins a client to the room to exchange information.  The room
    name is a combination of the search_uuid and the organization the
    search belongs to search_uuid:organization_uuid
    """

    emit('join-ack', {
        'message': f'{current_user.uuid} has joined'})
    
    join_room(f"agent-sp-control:{current_user.organization}")

    
@sock.on('join')
@ws_token_required
@room_required
def join(data, current_user, search_uuid, organization, room):
    """ Joins a client to the room to exchange information.  The room
    name is a combination of the search_uuid and the organization the
    search belongs to search_uuid:organization_uuid
    """
    
    job = SearchProxyJob.get_by_uuid(search_uuid)

    if job is None:
        return False

    join_room(room)

    emit('message', {
    'message': f'{current_user.uuid} has joined'}, to=room)

    # Find the next available healthy agent that is a member of the search
    # jobs organization and has the searchproxy role
    agent = Agent.search()
    #agent = agent.filter('term', healthy=True)
    agent = agent.filter('term', organization=organization)
    #agent = agent.filter('term', roles='searchproxy')
    agent = agent.execute()

    if len(agent.hits) == 0:
        emit('message', {
            'message': 'No agents available to run search.'}, to=room)
        
        # Abort the job
        job.status = 'failed'
        job.reason = 'No agents available to run search.'
        job.complete = True
        job.save(refresh='wait_for')

        return False
    
    # Select a random agent from the list of healthy agents
    agent = random.choice(agent.hits)

    # Assign the job to the agent
    job.assigned_agent = agent.uuid
    job.status = 'running'
    job.save(refresh='wait_for')

    # Let the client know that the job is running
    emit('message', {
        'message': 'Sending job to agent.'}, to=room)

    # Send the job to the agent
    emit('job', {
        **job.to_dict()['job_details'], 'uuid': job.uuid, 'organization': job.organization }, to=f"agent-sp-control:{organization}")


@sock.on('search-failed')
@ws_token_required
@room_required
def search_failed(data, current_user, search_uuid, organization, room):

    job = SearchProxyJob.get_by_uuid(search_uuid)

    if job is None:
        return False

    job.status = 'failed'
    job.reason = data['reason']
    job.complete = True
    job.save(refresh='wait_for')

    emit('message', {
        'message': f'Search failed. {data["reason"]}'}, to=room)
    
@sock.on('results-push')
@ws_token_required
@room_required
def results_push(data, current_user, search_uuid, organization, room):
    """
    Receives results from the agent and pushes them to the search
    UI.
    """
    # Chunk the results into 200 item chunks
    hits = data['hits']

    emit('result-hits', hits, to=room)

@sock.on('search-finish')
@ws_token_required
@room_required
def results(data, current_user, search_uuid, organization, room):

    emit('result-summary', data['results'], to=room)

    # Locate the search job and mark it as complete
    job = SearchProxyJob.get_by_uuid(search_uuid)

    if job is None:
        return False
    
    job.complete = True
    job.assigned_agent = current_user.uuid
    job.status = 'complete'
    job.save(refresh='wait_for')

    emit('result-finish', {}, to=room)

    leave_room(room)
