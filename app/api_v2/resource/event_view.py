from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    EventView,
    Q
)
from .shared import mod_pagination, ISO8601, mod_user_list
from ..utils import token_required, user_has, ip_approved

api = Namespace(
    'EventView', description='Reflex Event Views', path='/event_view', strict=True
)

mod_event_view_details = api.model('EventViewDetails', {
    'uuid': fields.String,
    'name': fields.String,
    'filter_string': fields.String,
    'shared': fields.Boolean,
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'modified_at': ISO8601,
    'modified_by': fields.Nested(mod_user_list)
})

mod_event_view_create = api.model('EventViewCreate', {
    'name': fields.String,
    'filter_string': fields.String,
    'shared': fields.Boolean
})

mod_event_view_list = api.model('EventViewList', {
    'views': fields.List(fields.Nested(mod_event_view_details))
})

@api.route("")
class EventViewList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_view_list)
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        '''
        Returns a list of event views
        '''

        views = []
        private_search = EventView.search()
        private_search = private_search.filter('term', private=True)
        private_search = private_search.filter('term', organization=current_user.organization)
        private_search = private_search.filter('nested', path='created_by', query=Q('term', created_by__uuid__keyword=current_user.uuid))

        private_views = private_search.execute()

        if private_views:
            views += private_views

        public_search = EventView.search()
        public_search = public_search.filter('term', private=False)
        public_search = public_search.filter('term', organization=current_user.organization)

        public_views = public_search.execute()

        if public_views:
            views += public_views

        return {
            'views': views,
        }

    @api.doc(security="Bearer")
    @api.expect(mod_event_view_create)
    @api.marshal_with(mod_event_view_details)
    @token_required
    @user_has('view_events')
    def post(self, current_user):

        view = EventView.get_by_name(api.payload['name'])
        if view:
            api.abort(409, "A view with that name already exists")

        view = EventView(**api.payload)
        view.save()

        return view
