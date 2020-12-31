from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs
from ..schemas import *
from .models import User, Event, RawLog, Tag, Observable

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

''' BEGIN HELPER FUNCTIONS '''
def parse_tags(tags):
    ''' Tags a list of supplied tags and creates Tag objects for each one '''
    _tags = []
    for t in tags:
        tag = Tag.get(current_app.elasticsearch, key_field='name', key_value=t)
        if not tag:
            tag = Tag(name=t)
            current_app.elasticsearch.add([tag])
            _tags += [tag.uuid]
        else:
            _tags += [tag.uuid]
    return _tags



def create_observables(observables):
    _observables = []
    _tags = []
    for o in observables:
        if 'tags' in o:
            tags = o.pop('tags')
            _tags = parse_tags(tags)

        
        if len(_tags) > 0:
            o['tags'] = _tags

        

        observable = Observable.get(current_app.elasticsearch, key_field='value', key_value=o['value'])
        if observable:
            _observables += [observable.uuid]
        else:
            observable = Observable(**o)
            current_app.elasticsearch.add([observable])
            _observables += [observable.uuid]

        # TODO: Add threat list matching back in!

        ''' observable_type = DataType.query.filter_by(name=o['dataType'], organization_uuid=organization_uuid).first()
        if observable_type:
            intel_lists = List.query.filter_by(organization_uuid=organization_uuid, tag_on_match=True, data_type_uuid=observable_type.uuid).all()

            o['dataType'] = observable_type
            observable = Observable(organization_uuid=organization_uuid, **o)
            observable.create()
            _observables += [observable]

            if len(_tags) > 0:
                observable.tags += _tags
                observable.save()

            # Intel list matching, if the value is on a list
            # put the list name in an array so we can tag the observable
            list_matches = []
            for l in intel_lists:
                hits = 0
                if l.list_type == 'values':
                    hits = len([v for v in l.values if v.value.lower() == o['value'].lower()])
                if l.list_type == 'patterns':
                    hits = len([v for v in l.values if re.match(v.value, o['value']) != None])
                if hits > 0:
                    list_matches.append(l.name.replace(' ','-').lower())

            # Process the tags based on the matched intel lists
            if len(list_matches) > 0:
                list_tags = []
                for m in list_matches:
                    tag = Tag.query.filter_by(organization_uuid=organization_uuid, name='list:%s' % m).first()
                    if tag:
                        list_tags.append(tag)
                    else:
                        tag = Tag(organization_uuid=organization_uuid, **{'name':'list:%s' % m, 'color': '#ffffff'})
                        list_tags.append(tag)
                observable.tags += list_tags
                observable.save()
        '''

    return _observables       


''' END HELPER FUNCTIONS '''

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

            # Create new tags, associate existing tags
            if 'tags' in api2.payload: 
                tags = api2.payload.pop('tags')
                _tags = parse_tags(tags)

            # Create new observables, associate existing observables
            if 'observables' in api2.payload:
                observables = api2.payload.pop('observables')
                _observables = create_observables(observables)

            # Create a raw_log entry
            raw_log = RawLog(source_log=api2.payload['raw_log'])
            current_app.elasticsearch.add([raw_log])

            # Assign the raw_log UUID to the event so we can correlate on it
            api2.payload['raw_log'] = raw_log.uuid

            if len(_tags) > 0:
                api2.payload['tags'] = _tags
            
            if len(_observables) > 0:
                api2.payload['observables'] = _observables

            # Create the event object and insert into Elasticsearch 
            event = Event(**api2.payload)
            print(event.observables)
            event.hash_event()
            current_app.elasticsearch.add([event])

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