from flask_restx import fields, Namespace, Resource
from .shared import mod_pagination
from ..utils import token_required, user_has
from ..model import (
    Event,
    Q
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

mod_observable_event_hits = api.model('ObservableEventHits', {
    'system_wide_events': fields.Integer,
    'total_org_events': fields.Integer,
    'total_org_cases': fields.Integer
})



@api.route('/<string:value>/hits')
class ObservableHits(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_observable_event_hits)
    @token_required
    @user_has('view_events')    
    def get(self, value, current_user):
        '''
        Get observables that match a value
        '''
        search = Event().search()
        search = search.query('nested', path='event_observables', query=Q('match', event_observables__value=value))
        total_events = search.count()

        search = Event().search()
        search = search.filter('term', organization=current_user.organization)
        search = search.query('nested', path='event_observables', query=Q('match', event_observables__value=value))
        organization_events = search.count()

        search = Event().search()
        search = search.query('bool', must=[Q('nested', path='event_observables', query={'match': {'event_observables.value': value}}), Q('term', organization=current_user.organization)])
        search.aggs.bucket('cases', 'cardinality', field='case')
        
        results = search.execute()
        total_cases = results.aggregations.cases.value

        return {'system_wide_events': total_events, 'total_org_events': organization_events, "total_org_cases": total_cases}
