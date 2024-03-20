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

mod_event_view_update = api.model('EventViewUpdate', {
    'name': fields.String,
    'filter_string': fields.String,
    'shared': fields.Boolean
})

mod_event_view_list = api.model('EventViewList', {
    'views': fields.List(fields.Nested(mod_event_view_details))
})

@api.route("/<string:uuid>")
class EventViewView(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_view_details)
    @token_required
    @user_has('view_events')
    def put(self, current_user, uuid):
        '''
        Updates an event view
        '''

        view = EventView.get_by_uuid(uuid=uuid)

        if not view:
            api.abort(404, "View not found")

        # Check if the user is allowed to modify this view
        # If the view is shared, then anyone can modify it
        # If the view is not shared, then only the creator can modify it
        if view.shared and view.created_by.uuid != current_user.uuid:
            api.abort(400, "You do not have permission to modify this view")

        view.update(**api.payload)

        return view


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
        try:
            private_search = EventView.search()
            private_search = private_search.filter('term', shared=False)
            private_search = private_search.filter('term', organization=current_user.organization)
            private_search = private_search.filter('nested', path='created_by', query=Q('term', created_by__uuid__keyword=current_user.uuid))

            private_views = private_search.scan()
        except Exception as e:
            private_views = None

        if private_views:
            views.extend(private_views)

        public_search = EventView.search()
        public_search = public_search.filter('term', shared=True)
        public_search = public_search.filter('term', organization=current_user.organization)

        public_views = public_search.scan()

        if public_views:
            views.extend(public_views)

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
