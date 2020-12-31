from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs
from ..schemas import *
from .models import User, Event, RawLog

api_v2 = Blueprint("api2", __name__, url_prefix="/api/v2.0")

api2 = Api(api_v2)

''' BEGIN NAMESPACES '''
ns_user_v2 = api2.namespace('User', description='User operations', path='/user')
ns_event_v2 = api2.namespace(
    'Event', description='Event operations', path='/event')
''' END NAMESPACES '''

''' BEGIN SCHEMA REGISTRATION '''
for model in schema_models:
    api2.models[model.name] = model
''' END SCHEMA REGISTRATION '''

''' BEGIN ROUTES '''
user_parser = api2.parser()
user_parser.add_argument('username', location='args', required=False)

@ns_user_v2.route("")
class UserList2(Resource):

    #@api.doc(security="Bearer")
    #@api.marshal_with(mod_user_full, as_list=True)
    @api2.expect(user_parser)
    #@token_required
    #@user_has('view_users')
    def get(self):
        ''' Returns a list of users '''
        users = User.query(current_app.elasticsearch)
        return users

@ns_event_v2.route("")
class EventList2(Resource):

    @api2.marshal_with(mod_event_list, as_list=True)
    def get(self):
        ''' Returns a list of events '''
        events = Event.query(current_app.elasticsearch)
        return events
    
    @api2.expect(mod_event_create)
    def post(self):
        ''' Creates a new event '''

        _observables = []
        _tags = []
        
        event = Event.get(current_app.elasticsearch, key_field='reference', key_value=api2.payload['reference'])
        
        if not event:

            ''' Create new tags, associate existing tags '''
            if 'tags' in api2.payload: 
                tags = api2.payload.pop('tags')
                print(tags)
                #_tags = parse_tags(tags, current_user.organization.uuid)

            ''' Create new observables, associate existing observables '''
            if 'observables' in api2.payload:
                observables = api2.payload.pop('observables')
                print(observables)
                #_observables = create_observables(observables, current_user.organization.uuid)

            ''' Create the raw_log entry '''
            raw_log = RawLog(source_log=api2.payload['raw_log'])
            current_app.elasticsearch.add([raw_log])

            #event = Event(organization_uuid=current_user.organization.uuid, **api.payload)
            api2.payload['raw_log'] = raw_log.uuid
            print(api2.payload)

            # Set the default status to New
            #event_status = EventStatus.query.filter_by(name="New", organization_uuid=current_user.organization.uuid).first()
            #event.status = event_status
            #event.save()

            #if len(_tags) > 0:
            #    event.tags += _tags
            #    event.save()

            #if len(_observables) > 0:
            #    event.observables += _observables
            #    event.save()

            #event.hash_event()

            return {'message': 'Successfully created the event.'}
        else:
            ns_event_v2.abort(409, 'Event already exists.')