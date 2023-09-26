from uuid import uuid4
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Schedule
)
from .shared import mod_pagination, ISO8601, mod_user_list
from ..utils import token_required, user_has, ip_approved

api = Namespace(
    'Schedules', description='Manage system wide schedules that are consumed by Event Rules, Detections and other schedulable components',
    path='/schedule', validate=True)

mod_day_hour = api.model('DayHour', {
    'start': fields.String(default='00:00'),
    'end': fields.String(default='23:59')
})

mod_day = api.model('Day', {
    'hours': fields.List(fields.Nested(mod_day_hour)),
    'custom': fields.Boolean,
    'active': fields.Boolean(default=True)
})

mod_schedule_details = api.model('ScheduleDetails', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'monday': fields.Nested(mod_day),
    'tuesday': fields.Nested(mod_day),
    'wednesday': fields.Nested(mod_day),
    'thursday': fields.Nested(mod_day),
    'friday': fields.Nested(mod_day),
    'saturday': fields.Nested(mod_day),
    'sunday': fields.Nested(mod_day),
    'timezone': fields.String,
    'active': fields.Boolean,
    'schedule_active': fields.Boolean,
    'created_at': ISO8601,
    'updated_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list)
})

mod_schedule_create = api.model('ScheduleCreate', {
    'name': fields.String(required=True),
    'organization': fields.String(required=False),
    'description': fields.String(required=False),
    'monday': fields.Nested(mod_day),
    'tuesday': fields.Nested(mod_day),
    'wednesday': fields.Nested(mod_day),
    'thursday': fields.Nested(mod_day),
    'friday': fields.Nested(mod_day),
    'saturday': fields.Nested(mod_day),
    'sunday': fields.Nested(mod_day),
    'active': fields.Boolean(required=False),
    'timezone': fields.String(required=True)
}, validate=True)

mod_schedule_update = api.model('ScheduleUpdate', {
    'name': fields.String,
    'organization': fields.String,
    'description': fields.String,
    'monday': fields.Nested(mod_day),
    'tuesday': fields.Nested(mod_day),
    'wednesday': fields.Nested(mod_day),
    'thursday': fields.Nested(mod_day),
    'friday': fields.Nested(mod_day),
    'saturday': fields.Nested(mod_day),
    'sunday': fields.Nested(mod_day),
    'active': fields.Boolean,
    'timezone': fields.String
}, strict=True)

mod_schedule_list = api.model('ScheduleList', {
    'schedules': fields.List(fields.Nested(mod_schedule_details))
})

schedule_list_parser = api.parser()
schedule_list_parser.add_argument('active', type=xinputs.boolean, default=True, required=False, help='Filter by active status')
schedule_list_parser.add_argument('organization', required=False, type=str, help='Filter by organization')

@api.route("")
class ScheduleList(Resource):
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_schedule_list)
    @token_required
    @user_has('view_schedules')
    def get(self, current_user):
        ''' Returns a list of schedules. '''

        args = schedule_list_parser.parse_args()
        
        search = Schedule.search()
        if current_user.is_default_org() and args.organization:
            search = search.filter('term', organization=args.organization)

        if args.active is not None:
                search = search.filter('term', active=True)

        return { 'schedules': [s for s in search.scan()] }
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_schedule_details)
    @api.expect(mod_schedule_create)
    @token_required
    @user_has('create_schedule')
    def post(self, current_user):
        ''' Creates a new schedule. '''

        if 'name' not in api.payload or api.payload['name'] in ['', None]:
            api.abort(400, 'Missing required parameter: name')

        organization = current_user.organization
        if 'organization' in api.payload:
            if not current_user.is_default_org():
                api.payoad['organization'] = current_user.organization
            else:
                organization = api.payload['organization']

        exists = Schedule.exists_by_field('name', api.payload['name'], organization=organization)
        if exists:
            api.abort(409, 'Schedule with that name already exists.')

        # Create the schedule
        schedule = Schedule(**api.payload)
        schedule.active = True
        schedule.save()

        # Return the schedule
        return schedule
    

@api.route("/<string:uuid>")
class ScheduleDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_schedule_details)
    @token_required
    @user_has('view_schedules')
    def get(self, current_user, uuid):
        ''' Returns the details for a schedule. '''

        # Get the schedule
        schedule = Schedule.get_by_uuid(uuid)

        if not schedule:
            api.abort(404, 'Schedule not found.')

        # Return the schedule
        return schedule
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_schedule_details)
    @api.expect(mod_schedule_update, validate=True)
    @token_required
    @user_has('update_schedule')
    def put(self, current_user, uuid):
        ''' Updates a schedule. '''

        # Get the schedule
        schedule = Schedule.get_by_uuid(uuid)

        if not schedule:
            api.abort(404, 'Schedule not found.')

        organization = current_user.organization
        if 'organization' in api.payload:
            if not current_user.is_default_org():
                del api.payoad['organization']
            else:
                organization = api.payload['organization']

        if 'name' in api.payload:
            exists = Schedule.exists_by_field('name', api.payload['name'], organization=organization)
            if exists:
                if exists.uuid != schedule.uuid:
                    api.abort(409, 'Schedule with that name already exists.')

        # Update the schedule
        schedule.update(**api.payload)

        # Return the schedule
        return schedule
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_schedule_details)
    @token_required
    @user_has('delete_schedule')
    def delete(self, current_user, uuid):
        ''' Deletes a schedule. '''

        # Get the schedule
        schedule = Schedule.get_by_uuid(uuid)

        if not schedule:
            api.abort(404, 'Schedule not found.')

        # Delete the schedule
        schedule.delete()

        # Return the schedule
        return {}
