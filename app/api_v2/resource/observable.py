from flask_restx import fields, Namespace, Resource
from .shared import mod_pagination
from ..utils import token_required, user_has, default_org
from ..model import (
    Event,
    Q,
    ThreatValue,
    ThreatList
)

api = Namespace('Observable', description="Observable operations", path="/observable")

mod_observable_update = api.model('ObservableUpdate', {
    'tags': fields.List(fields.String),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String
})

mod_observable_list = api.model('ObservableList', {
    'tags': fields.List(fields.String),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String,
    'uuid': fields.String,
    'case': fields.String,
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_observable_list_paged = api.model('PagedObservableList', {
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'pagination': fields.Nested(mod_pagination)
})


mod_observable_create = api.model('ObservableCreate', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String(required=True),
    'tags': fields.List(fields.String),
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_bulk_add_observables = api.model('BulkObservables', {
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'organization': fields.String
})

mod_threat_list_hits = api.model('ThreatListHits', {
    'name': fields.String,
    'uuid': fields.String,
    'list_type': fields.String,
    'external_feed': fields.Boolean,
    'url': fields.String,
    'hits': fields.Integer
})

mod_top_events = api.model('TopEvents', {
    'title': fields.String,
    'hits': fields.Integer,
})

mod_observable_event_hits = api.model('ObservableEventHits', {
    'system_wide_events': fields.Integer,
    'total_org_events': fields.Integer,
    'total_org_cases': fields.Integer,
    'threat_list_hits': fields.List(fields.Nested(mod_threat_list_hits)),
    'top_events': fields.List(fields.Nested(mod_top_events))
})

observable_parser = api.parser()
observable_parser.add_argument('organization', location='args', type=str, help='Organization UUID')

@api.route('/<string:value>/hits')
class ObservableHits(Resource):

    @api.doc(security="Bearer")
    @api.expect(observable_parser)
    @api.marshal_with(mod_observable_event_hits)
    @token_required
    @default_org
    @user_has('view_events')    
    def get(self, value, user_in_default_org, current_user):
        '''
        Get observables that match a value
        '''

        args = observable_parser.parse_args()

        search = Event().search()
        search = search.query('nested', path='event_observables', query=Q('term', event_observables__value__keyword=value))
        total_events = search.count()

        search = Event().search()
        if args['organization'] and user_in_default_org:
            search = search.filter('term', organization=args['organization'])
        else:
            search = search.filter('term', organization=current_user.organization)
        search = search.query('nested', path='event_observables', query=Q('term', event_observables__value__keyword=value))

        search.aggs.bucket('event_titles', 'terms', field='title', size=100)
        results = search.execute()
        event_titles = results.aggregations.event_titles.buckets
        organization_events = results.hits.total.value

        top_events = [{'title': e.key, 'hits': e.doc_count} for e in event_titles]

        search = Event().search()
        search = search.query('bool', must=[Q('nested', path='event_observables', query={'term': {'event_observables.value.keyword': value}}), Q('term', organization=current_user.organization)])
        search.aggs.bucket('cases', 'cardinality', field='case')

        results = search.execute()
        total_cases = results.aggregations.cases.value

        threat_search = ThreatValue.search()
        threat_search = threat_search.filter('term', value=value)
        threat_search = threat_search.filter('term', organization=current_user.organization)
        threat_search.aggs.bucket('lists', 'terms', field='list_uuid', size=1000)
        threat_results = threat_search.execute()
        lists = threat_results.aggregations.lists.buckets

        hits = {l.key: l.doc_count for l in lists}

        list_data = ThreatList.search().filter('terms', uuid=[l.key for l in lists]).filter('term', active=True).scan()

        def is_external_feed(l):
            return True if hasattr(l, 'url') and l.url else False

        def list_url(l):
            return l.url if hasattr(l, 'url') and l.url else ''

        list_data = [{'uuid': l.uuid, 'name': l.name, 'list_type': l.list_type, 'hits': hits[l.uuid], 'external_feed': is_external_feed(l), 'url': list_url(l) } for l in list_data]

        response = {'system_wide_events': total_events,
                    'total_org_events': organization_events,
                    'total_org_cases': total_cases,
                    'threat_list_hits': list_data,
                    'top_events': top_events
                }

        return response
