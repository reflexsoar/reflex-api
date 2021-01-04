import base64
import datetime
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs
from .schemas import *
from .models import Event, EventRule, Observable, User, Role, Settings, Credential, Input, Agent, ThreatList, ExpiredToken
from .utils import token_required, user_has, generate_token

# Instantiate a new API object
api_v2 = Blueprint("api2", __name__, url_prefix="/api/v2.0")
api2 = Api(api_v2)

# All the API namespaces
ns_user_v2 = api2.namespace('User', description='User operations', path='/user')
ns_auth_v2 = api2.namespace('Auth', description='Authentication operations', path='/auth')
ns_event_v2 = api2.namespace('Event', description='Event operations', path='/event')
ns_settings_v2 = api2.namespace('Settings', description='Settings operations', path='/settings')
ns_credential_v2 = api2.namespace('Credential', description='Credential operations', path='/credential')
ns_input_v2 = api2.namespace('Input', description='Input operations', path='/input')
ns_agent_v2 = api2.namespace('Agent', description='Agent operations', path='/agent')
ns_list_v2 = api2.namespace('List', description='Lists API endpoints for managing indicator lists, lists may be string values or regular expressions', path='/list')
ns_event_rule_v2 = api2.namespace('EventRule', description='Event Rules control what happens to an event on ingest', path='/event_rule')

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
        user = User.get_by_username(api2.payload['username'])
        if not user:
            ns_auth_v2.abort(401, 'Incorrect username or password')
    
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
        if user.failed_logons >= Settings.load().logon_password_attempts:
            user.update(locked=True)
        else:
            user.update(failed_logons=user.failed_logons+1)

        ns_auth_v2.abort(401, 'Incorrect username or password')


@ns_auth_v2.route('/logout')
class Logout(Resource):

    @api2.doc(security="Bearer")
    @api2.response(200, 'Successfully logged out.')
    @api2.response(401, 'Not logged in.')
    @token_required
    def get(self, current_user):
        '''
        Logs a user out of the platform and invalidates their access_token
        so that they can't use it again.  The token is stored in a blocked token
        index for lookup when calling the API
        '''
        try:
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            b_token = ExpiredToken(token=access_token)
            b_token.save()
            return {'message': 'Successfully logged out.'}, 200
        except:
            return {'message': 'Not logged in.'}, 401

        ns_auth_v2.abort(401, 'Not logged in.')


@ns_user_v2.route("/me")
class UserInfo(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_self)
    @token_required
    def get(self, current_user):
        ''' Returns information about the currently logged in user '''
        
        role = Role.get_by_member(uuid=current_user.uuid)
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


@ns_user_v2.route("/<uuid>/unlock")
class UnlockUser(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_full)
    @token_required
    @user_has('unlock_user')
    def put(self, uuid, current_user):
        ''' Unlocks a user and resets their failed logons back to 0 '''
        user = User.get_by_uuid(uuid)
        print(user.locked)
        if user:
            user.unlock()
            return user
        else:
            ns_user_v2.abort(404, 'User not found.')


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

        args = user_parser.parse_args()

        if args['username']:
            user = User.get_by_username(args['username'])
            if user:
                return [user]
            else:
                return []
        else:
            s = User.search()
            response = s.execute()
            return [user for user in response]

    @api2.doc(security="Bearer")
    @api2.expect(mod_user_create)
    @api2.marshal_with(mod_user_create_success)
    @api2.response('409', 'User already exists.')
    @api2.response('200', "Successfully created the user.")
    @token_required
    @user_has('add_user')
    def post(self, current_user):
        ''' Creates a new user '''

        # Check to see if the user already exists
        user = User.get_by_email(api2.payload['email'])
        if user:
            ns_user_v2.abort(409, "User with this e-mail already exists.")
        else:
            user_password = api2.payload.pop('password')
            user = User(**api2.payload)
            user.set_password(user_password)
            user.save()
            return {'message': 'Successfully created the user.', 'user': user}  


@ns_user_v2.route("/<uuid>")
class UserDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_full)
    @token_required
    @user_has('view_users')
    def get(self, uuid, current_user):
        ''' Returns information about a user '''
        user = User.get_by_uuid(uuid)
        if user:
            return user
        else:
            ns_user_v2.abort(404, 'User not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_user_create)
    @api2.marshal_with(mod_user_full)
    @token_required
    @user_has('update_user')
    def put(self, uuid, current_user):
        ''' Updates information for a user '''

        user = User.get_by_uuid(uuid)
        if user:
            if 'username' in api2.payload:
                target_user = User.get_by_username(api2.payload['username'])
                if target_user:
                    if target_user.uuid == uuid:
                        del api2.payload['username']
                    else:
                        ns_user_v2.abort(409, 'Username already taken.')

            if 'email' in api2.payload:
                target_user = User.get_by_email(api2.payload['email'])
                if target_user:
                    if target_user.uuid == uuid:
                        del api2.payload['email']
                    else:
                        ns_user_v2.abort(409, 'Email already taken.')
            
            if 'password' in api2.payload and not current_user.has_right('reset_user_password'):
                api2.payload.pop('password')
            if 'password' in api2.payload and current_user.has_right('reset_user_password'):
                pw = api2.payload.pop('password')
                user.set_password(pw)
                user.save()
            
            user.update(**api2.payload)
            return user
        else:
            ns_user_v2.abort(404, 'User not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_user')
    def delete(self, uuid, current_user):
        ''' 
        Deletes a user 
        
        Users are soft deleted, meaning they never get removed from the database.  Instead,
        their deleted attribute is set and they do not show up in the UI.  This is 
        used to preserve database relationships like ownership, comment history.
        Deleted users can not be restored at this time.        
        '''
        user = User.get_by_uuid(uuid)
        if user:
            if current_user.uuid == user.uuid:
                ns_user_v2.abort(403, 'User can not delete themself.')
            else:
                user.deleted = True
                user.locked = True
                user.save()
                return {'message': 'User successfully deleted.'}
        else:
            ns_user_v2.abort(404, 'User not found.')


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
        
        event = Event.get_by_reference(api2.payload['reference'])
                
        if not event:
            event = Event(**api2.payload)
            event.save()
            return {'message': 'Successfully created the event.'}
        else:
            ns_event_v2.abort(409, 'Event already exists.')


@ns_event_rule_v2.route("")
class EventRuleList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, current_user):
        ''' Gets a list of all the event rules '''
        event_rules = EventRule.search().execute()
        if event_rules:
            return [r for r in event_rules]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_rule_create)
    @api2.response('200', 'Successfully created event rule.')
    @token_required
    @user_has('create_event_rule')
    def post(self, current_user):
        ''' Creates a new event_rule set '''

        if 'expire_days' in api2.payload and not isinstance(api2.payload['expire_days'], int):
            ns_event_rule_v2(400, 'expire_days should be an integer.')

        # Computer when the rule should expire
        if 'expire' in api2.payload and api2.payload['expire']:
            if 'expire_days' in api2.payload:
                expire_days = api2.payload.pop('expire_days')

                expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                api2.payload['expire_at'] = expire_at
            else:
                ns_event_rule_v2.abort(400, 'Missing expire_days field.')

        event_rule = EventRule(**api2.payload)
        event_rule.hash_observables()
        event_rule.save()

        return {'message': 'Successfully created event rule.', 'uuid': str(event_rule.uuid)}


@ns_event_rule_v2.route("/<uuid>")
class EventRuleDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, uuid, current_user):
        ''' Gets a event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        if event_rule:
            return event_rule
        else:
            ns_event_rule_v2.abort(404, 'Event rule not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_rule_create)
    @api2.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('update_event_rule')
    def put(self, uuid, current_user):
        ''' Updates the event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        
        if event_rule:

            if 'observables' in api2.payload:
                event_rule.observables = api2.payload.pop('observables')
                event_rule.hash_observables()

            if len(api2.payload) > 0:
                event_rule.update(**api2.payload)

            return event_rule
        else:
            ns_event_rule_v2.abort(404, 'Event rule not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_event_rule')
    def delete(self, uuid, current_user):
        ''' Removes an event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        if event_rule:
            event_rule.delete()
            return {'message': 'Sucessfully deleted the event rule.'}


@ns_input_v2.route("")
class InputList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_input_list, as_list=True)
    @token_required
    @user_has('view_inputs')
    def get(self, current_user):
        ''' Returns a list of inputs '''
        inputs = Input.search().execute()
        if inputs:
            return [i for i in inputs]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_input_create)
    @api2.response('409', 'Input already exists.')
    @api2.response('200', 'Successfully create the input.')
    @token_required
    @user_has('add_input')
    def post(self, current_user):
        ''' Creates a new input '''
        _tags = []
        inp = Input.get_by_name(name=api2.payload['name'])

        if not inp:

            if 'credential' in api2.payload:
                cred_uuid = api2.payload.pop('credential')
                api2.payload['credential'] = cred_uuid

            if 'config' in api2.payload:
                try:
                    api2.payload['config'] = json.loads(base64.b64decode(
                        api2.payload['config']).decode('ascii').strip())
                except Exception:
                    ns_input_v2.abort(
                        400, 'Invalid JSON configuration, check your syntax')

            if 'field_mapping' in api2.payload:
                try:
                    api2.payload['field_mapping'] = json.loads(base64.b64decode(
                        api2.payload['field_mapping']).decode('ascii').strip())
                except Exception:
                    ns_input_v2.abort(
                        400, 'Invalid JSON in field_mapping, check your syntax')

            inp = Input(**api2.payload)
            inp.save()

            if len(_tags) > 0:
                inp.tags += _tags
                inp.save()
        else:
            ns_input_v2.abort(409, 'Input already exists.')
        return {'message': 'Successfully created the input.'}


@ns_input_v2.route("/<uuid>")
class InputDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_input_list)
    @token_required
    @user_has('view_inputs')
    def get(self, uuid, current_user):
        ''' Returns information about an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            return inp
        else:
            ns_input_v2.abort(404, 'Input not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_input_create)
    @api2.marshal_with(mod_input_list)
    @token_required
    @user_has('update_input')
    def put(self, uuid, current_user):
        ''' Updates information for an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            if 'name' in api2.payload and Input.get_by_name(name=api2.payload['name']):
                ns_input_v2.abort(409, 'Input name already exists.')
            else:
                inp.update(**api2.payload)
                return inp
        else:
            ns_input_v2.abort(404, 'Input not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_input')
    def delete(self, uuid, current_user):
        ''' Deletes an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            inp.delete()
            return {'message': 'Sucessfully deleted input.'}


@ns_agent_v2.route("/pair_token")
class AgentPairToken(Resource):

    @api2.doc(security="Bearer")
    @token_required
    @user_has('pair_agent')
    def get(self, current_user):
        ''' 
        Generates a short lived pairing token used by the agent to get a long running JWT
        '''

        settings = Settings.load()
        return generate_token(None, settings.agent_pairing_token_valid_minutes, 'pairing')


@ns_agent_v2.route("")
class AgentList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_agent_list, as_list=True)
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        ''' Returns a list of Agents '''
        agents = Agent.search().execute()
        if agents:
            return [agent for agent in agents]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_create)
    @api2.response('409', 'Agent already exists.')
    @api2.response('200', "Successfully created the agent.")
    @token_required
    @user_has('add_agent')
    def post(self, current_user):
        ''' Creates a new Agent '''

        agent = Agent.get_by_name(name=api2.payload['name'])
        if not agent:

            agent = Agent(**api2.payload)
            role = Role.get_by_name(name='Agent')
            role.add_user_to_role(agent.uuid)
            agent.save()

            token = generate_token(str(agent.uuid), 86400, token_type='agent')

            return {'message': 'Successfully created the agent.', 'uuid': str(agent.uuid), 'token': token}
        else:
            ns_agent_v2.abort(409, "Agent already exists.")


@ns_agent_v2.route("/heartbeat/<uuid>")
class AgentHeartbeat(Resource):

    @api2.doc(security="Bearer")
    @token_required
    def get(self, uuid, current_user):
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            agent.last_heartbeat = datetime.datetime.utcnow()
            agent.save()
            return {'message': 'Your heart still beats!'}
        else:
            '''
            If the agent can't be found, revoke the agent token
            '''

            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            expired = ExpiredToken(token=access_token)
            expired.save()
            
            ns_agent_v2.abort(400, 'Your heart stopped.')


@ns_agent_v2.route("/<uuid>")
class AgentDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_create)
    @api2.marshal_with(mod_agent_list)
    @token_required
    @user_has('update_agent')
    def put(self, uuid, current_user):
        ''' Updates an Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            agent.update(**api2.payload)
            return agent
        else:
            ns_agent_v2.abort(404, 'Agent not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_agent')
    def delete(self, uuid, current_user):
        ''' Removes a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            agent.delete()
            return {'message': 'Agent successfully delete.'}
        else:
            ns_agent_v2.abort(404, 'Agent not found.')

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_agent_list)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            return agent
        else:
            ns_agent_v2.abort(404, 'Agent not found.')


@ns_credential_v2.route('/encrypt')
class EncryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_create)
    @api2.marshal_with(mod_credential_full)
    @api2.response('400', 'Successfully created credential.')
    @api2.response('409', 'Credential already exists.')
    @token_required
    @user_has('add_credential')
    def post(self, current_user):
        ''' Encrypts the password '''
        credential = Credential.get_by_name(api2.payload['name'])
        if not credential:
            pw = api2.payload.pop('secret')
            print(pw)
            credential = Credential(**api2.payload)
            credential.save()
            credential.encrypt(pw.encode(
            ), current_app.config['MASTER_PASSWORD'])
            
            return credential
        else:
            ns_credential_v2.abort(409, 'Credential already exists.')


@ns_credential_v2.route("")
class CredentialList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_list)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):
        credentials = Credential.search().execute()
        if credentials:
            return [c for c in credentials]
        else:
            return []


@ns_credential_v2.route('/decrypt/<uuid>')
class DecryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_return)
    @api2.response('404', 'Credential not found.')
    @token_required
    @user_has('decrypt_credential')
    def get(self, uuid, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            value = credential.decrypt(current_app.config['MASTER_PASSWORD'])
            if value:
                return {'secret': value}
            else:
                ns_credential_v2.abort(401, 'Invalid master password.')
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


@ns_credential_v2.route('/<uuid>')
class CredentialDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_full)
    @api2.response('404', 'Credential not found.')
    @token_required
    @user_has('view_credentials')
    def get(self, uuid, current_user):
        ''' Gets the full details of a credential '''
        credential = Credential.get_by_uuid(uuid)
        if credential:
            return credential
        else:
            ns_credential_v2.abort(409, 'Credential not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_update, validate=True)
    @api2.marshal_with(mod_credential_full)
    @api2.response('404', 'Credential not found.')
    @api2.response('409', 'Credential name already exists.')
    @token_required
    @user_has('update_credential')
    def put(self, uuid, current_user):
        ''' Updates a credential '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            if 'name' in api2.payload:
                cred = Credential.get_by_name(api2.payload['name'])
                if cred:
                    if cred.uuid != uuid:
                        ns_credential_v2.abort(409, 'Credential name already exists.')
            
            if 'secret' in api2.payload:
                credential.encrypt(api2.payload.pop('secret').encode(
                                    ), current_app.config['MASTER_PASSWORD'])
            if len(api2.payload) > 0:
                credential.update(**api2.payload)
            return credential
        else:
            ns_credential_v2.abort(404, 'Credential not found.')

    @api2.doc(security="Bearer")
    @api2.response('404', 'Credential not found.')
    @api2.response('200', "Credential sucessfully deleted.")
    @token_required
    @user_has('delete_credential')
    def delete(self, uuid, current_user):
        ''' Deletes a credential '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            credential.delete()
            return {'message': 'Credential successfully deleted.'}
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


@ns_list_v2.route("")
class ThreatListList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_list_list, as_list=True)
    @token_required
    @user_has('view_lists')
    def get(self, current_user):
        ''' Returns a list of ThreatLists '''
        lists = ThreatList.search().execute()
        if lists:
            return [l for l in lists]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_list_create)
    @api2.marshal_with(mod_list_list)
    @api2.response('409', 'ThreatList already exists.')
    @api2.response('200', "Successfully created the list.")
    @token_required
    @user_has('add_list')
    def post(self, current_user):
        '''
        Creates a new ThreatList 
        
        Supported list types: `values|pattern`
        
        '''

        if api2.payload['list_type'] not in ['values', 'pattern']:
            ns_list_v2.abort(400, "Invalid list type.")

        if 'values' in api2.payload:
            _values = api2.payload.pop('values')
            if not isinstance(_values, list):
                _values = _values.split('\n')
            values = []
            for value in _values:
                if value == '':
                    continue
                values.append(value)

            api2.payload['values'] = values

        if api2.payload['data_type'] not in Settings.load().data_types:
            ns_list_v2.abort(409, "Data type not found.")

        value_list = ThreatList.get_by_name(name=api2.payload['name'])

        if not value_list:
            value_list = ThreatList(**api2.payload)
            value_list.save()
            return value_list
        else:
            ns_list_v2.abort(409, "ThreatList already exists.")


@ns_list_v2.route("/<uuid>")
class ThreatListDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_list_create)
    @api2.marshal_with(mod_list_list)
    @token_required
    @user_has('update_list')
    def put(self, uuid, current_user):
        ''' Updates a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            
            if 'name' in api2.payload:
                l =  ThreatList.get_by_name(name=api2.payload['name'])
                if l and l.uuid != uuid:
                    ns_list_v2.abort(409, 'ThreatList with that name already exists.')

            if 'values' in api2.payload:

                # Get the current values in the list
                current_values = [v for v in value_list.values]

                # Determine what the new values should be, current, new or removed
                _values = api2.payload.pop('values')

                # Detect if the user sent it as a list or a \n delimited string
                if not isinstance(_values, list):
                    _values = _values.split('\n')

                removed_values = [v for v in current_values if v not in _values and v != '']
                new_values = [v for v in _values if v not in current_values and v != '']

                # For all values not in the new list
                # delete them from the database and disassociate them 
                # from the list
                for v in removed_values:
                    value_list.values.remove(v)

                for v in new_values:
                    if value_list.values:
                        value_list.values.append(v)
                    else:
                        value_list.values = [v]
                
                value_list.save()

            # Update the list with all other fields
            if len(api2.payload) > 0:
                value_list.update(**api2.payload)

            return value_list
        else:
            ns_list_v2.abort(404, 'ThreatList not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_list')
    def delete(self, uuid, current_user):
        ''' Removes a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            value_list.delete()
            return {'message': 'ThreatList successfully delete.'}
        else:
            ns_list_v2.abort(404, 'ThreatList not found.')

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_list_list)
    @token_required
    @user_has('view_lists')
    def get(self, uuid, current_user):
        ''' Gets the details of a ThreatList '''

        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            return value_list
        else:
            ns_list_v2.abort(404, 'ThreatList not found.')


@ns_settings_v2.route("")
class GlobalSettings(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_settings)
    @token_required
    @user_has('view_settings')    
    def get(self, current_user):
        ''' Retrieves the global settings for the system '''
        settings = Settings.load()
        return settings

    @api2.doc(security="Bearer")
    @api2.expect(mod_settings)
    @token_required    
    @user_has('update_settings')
    def put(self, current_user):

        if 'agent_pairing_token_valid_minutes' in api2.payload:
            if int(api2.payload['agent_pairing_token_valid_minutes']) > 365:
                ns_settings_v2.abort(400, 'agent_pairing_token_valid_minutes can not be greated than 365 days.')

        settings = Settings.load()
        settings.update(**api2.payload)

        return {'message': 'Succesfully updated settings'}


@ns_settings_v2.route("/generate_persistent_pairing_token")
class PersistentPairingToken(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_persistent_pairing_token)
    @token_required
    @user_has('create_persistent_pairing_token')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        settings = Settings.load()
        return settings.generate_persistent_pairing_token()
