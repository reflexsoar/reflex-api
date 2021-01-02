import datetime
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs
from .schemas import *
from .models import Event, Observable, User, Role
from .utils import token_required, user_has

# Instantiate a new API object
api_v2 = Blueprint("api2", __name__, url_prefix="/api/v2.0")
api2 = Api(api_v2)

# All the API namespaces
ns_user_v2 = api2.namespace('User', description='User operations', path='/user')
ns_auth_v2 = api2.namespace('Auth', description='Authentication operations', path='/auth')
ns_event_v2 = api2.namespace(
    'Event', description='Event operations', path='/event')

# Register all the schemas from flask-restx
for model in schema_models:
    api2.models[model.name] = model


'''
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

         observable_type = DataType.query.filter_by(name=o['dataType'], organization_uuid=organization_uuid).first()
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

    return _observables       
'''

@ns_auth_v2.route("/login")
class Login(Resource):
    
    @api2.expect(mod_auth)
    @api2.response(200, 'Success', mod_auth_success_token)
    @api2.response(401, 'Incorrect username or password')
    def post(self):
        '''
        Log a user in to the platform and provide them with an access_token a refresh_token
        '''

        # Find the user based on their username, if their account is locked don't return a user
        # object to prevent processing any more failed logons
        user = User.search().filter('term', username=api2.payload['username']).execute()
        if not user:
            ns_auth_v2.abort(401, 'Incorrect username or password')
    
        user = user[0]
        if user.check_password(api2.payload['password']):

            # Generate an access token
            _access_token = user.create_access_token()

            # Generate a refresh tokenn
            _refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))

            # Update the users failed_logons and last_logon entries
            user.update(failed_logons=0, last_logon=datetime.datetime.utcnow())

            return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200

        if user.failed_logons == None:
            user.update(failed_logons= 0)

        # TODO: Move this back to a global setting when settings is migrated
        if user.failed_logons >= 5:
            user.update(locked=True)
        else:
            user.update(failed_logons=user.failed_logons+1)

        ns_auth_v2.abort(401, 'Incorrect username or password')


@ns_auth_v2.route('/logout')
class Logout(Resource):

    #@api2.doc(security="Bearer")
    @api2.response(200, 'Successfully logged out.')
    @api2.response(401, 'Not logged in.')
    #@token_required
    def get(self): # NOTE: add current_user back after enabling token_required
        '''
        Logs a user out of the platform and invalidates their access_token
        so that they can't use it again.  The token is stored in a blocked token
        index for lookup when calling the API
        '''
        try:
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            b_token = AuthTokenBlacklist(auth_token=access_token)
            b_token.create()
            return {'message': 'Successfully logged out.'}, 200
        except:
            return {'message': 'Not logged in.'}, 401

        ns_auth.abort(401, 'Not logged in.')


@ns_user_v2.route("/me")
class UserInfo(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_self)
    @token_required
    def get(self, current_user):
        ''' Returns information about the currently logged in user '''
        
        role = Role.search().filter('term', members=current_user.meta.id).execute()[0]
        current_user.role = role

        return current_user


@ns_user_v2.route('/generate_api_key')
class UserGenerateApiKey(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_api_key)
    @token_required
    @user_has('use_api')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        return current_user.generate_api_key()


user_parser = api2.parser()
user_parser.add_argument('username', location='args', required=False)

@ns_user_v2.route("")
class UserList2(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_full, as_list=True)
    @api2.expect(user_parser)
    @token_required
    @user_has('view_users')
    def get(self, current_user):
        ''' Returns a list of users '''
        s = User.search()
        response = s.execute()
        print()
        return [user._source for user in response['hits']['hits']]

    def post(self):
        raise NotImplementedError

event_list_parser = api2.parser()
event_list_parser.add_argument('query', type=str, location='args', required=False)
event_list_parser.add_argument('page', type=int, location='args', default=1, required=False)
event_list_parser.add_argument('page_size', type=int, location='args', default=10, required=False)
event_list_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
event_list_parser.add_argument('sort_desc', type=xinputs.boolean, location='args', default=True, required=False)

@ns_event_v2.route("")
class EventList2(Resource):

    @api2.marshal_with(mod_event_list, as_list=True)
    @api2.expect(event_list_parser)
    def get(self):
        ''' Returns a list of events '''
    
        args = event_list_parser.parse_args()
        
        s = Event.search()
        response = s.execute()

        return [event._source for event in response['hits']['hits']]
        #return []
    
    @api2.expect(mod_event_create)
    def post(self):

        ''' Creates a new event '''

        _observables = []
        _tags = []
        
        event = Event.search().filter('term', reference=api2.payload['reference']).execute()
                
        if not event:
            event = Event(**api2.payload)
            event.save()
            return {'message': 'Successfully created the event.'}
        else:
            ns_event_v2.abort(409, 'Event already exists.')