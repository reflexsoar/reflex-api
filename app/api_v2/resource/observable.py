from functools import lru_cache
import re
import json
import base64
import urllib
import requests
import ipaddress
from flask_restx import fields, Namespace, Resource
from .shared import mod_pagination
from .utils import check_ip_whois_io
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
    'top_events': fields.List(fields.Nested(mod_top_events)),
    'base64_decoded_values': fields.List(fields.String),
    'ip_whois': fields.Raw,
    'url_haus': fields.Raw,
})

def check_url_haus(value, data_type):
    ''' Connects to urlhaus-api.abuse.ch and pulls information '''

    lookup_key = {
        'ip': 'host',
        'domain': 'host',
        'url': 'url',
    }

    post_data = {lookup_key[data_type]: value}
    try:
        r = requests.post('https://urlhaus-api.abuse.ch/v1/host/', data=post_data)
        if r.status_code == 200:
            return r.json()
    except:
        return {}

observable_parser = api.parser()
observable_parser.add_argument('organization', location='args', type=str, help='Organization UUID')
observable_parser.add_argument('data_type', location='args', type=str, help='Data type of the observable')

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

        value = urllib.parse.unquote(value)

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

        organization_events = search.count()

        search.aggs.bucket('event_titles', 'terms', field='title', size=100)
        results = search.execute()
        event_titles = results.aggregations.event_titles.buckets

        top_events = [{'title': e.key, 'hits': e.doc_count} for e in event_titles]

        search = Event().search()
        search = search.query('bool', must=[Q('nested', path='event_observables', query={'term': {'event_observables.value.keyword': value}}), Q('term', organization=current_user.organization)])
        search.aggs.bucket('cases', 'cardinality', field='case')

        results = search.execute()
        total_cases = results.aggregations.cases.value

        

        threat_search = ThreatValue.search()
        threat_search = threat_search.filter('term', value=value)

        if not current_user.is_default_org():
            intel_lists = ThreatList.search(skip_org_check=True)
            intel_lists = intel_lists.filter('term', active=True)
            intel_lists = intel_lists.filter(
                'bool',
                should=[
                    Q('term', organization=current_user.organization),
                    Q('term', global_list=True)
                ]
            )
            results = intel_lists.scan()
            list_uuids = [l.uuid for l in results]
            threat_search = threat_search.filter('terms', list_uuid=list_uuids)

        threat_search.aggs.bucket('lists', 'terms', field='list_uuid', size=1000)

        threat_results = threat_search.execute()
        lists = threat_results.aggregations.lists.buckets

        hits = {l.key: l.doc_count for l in lists}

        list_data = ThreatList.search(skip_org_check=True).filter('terms', uuid=[l.key for l in lists]).filter('term', active=True).scan()

        def is_external_feed(l):
            return True if hasattr(l, 'url') and l.url else False

        def list_url(l):
            return l.url if hasattr(l, 'url') and l.url else ''

        list_data = [{
            'uuid': l.uuid,
            'name': l.name,
            'list_type': l.list_type,
            'hits': hits[l.uuid],
            'external_feed': is_external_feed(l),
            'url': list_url(l)
            } for l in list_data]


        # Attempt to base64 decode any values that are base64 encoded
        decoded_values = []
        try:
            pattern = re.compile(r'\s+([A-Za-z0-9+/]{20}\S+)')
            matches = pattern.findall(value)
            if matches:
                for match in matches:
                    
                    decoded_value = base64.b64decode(match)
                    encoding = json.detect_encoding(decoded_value)
                    decoded_values.append(decoded_value.decode(encoding))
        except Exception as e:
            pass

        ip_whois = {}
        ip_whois = check_ip_whois_io(value)

        #if args.data_type in ['domain','url','ip']:
        #    url_haus = check_url_haus(value, args.data_type)
        #else:
        #    url_haus = {}

        overall_risk_score = 0


        response = {'system_wide_events': total_events,
                    'risk_score': overall_risk_score,
                    'total_org_events': organization_events,
                    'total_org_cases': total_cases,
                    'threat_list_hits': list_data,
                    'top_events': top_events,
                    'base64_decoded_values': decoded_values,
                    'ip_whois': ip_whois,
                    #'url_haus': url_haus
                }

        return response
