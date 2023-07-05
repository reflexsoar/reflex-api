from flask_restx import Resource, Namespace, fields

from ..model import DetectionRepository, Detection, DetectionRepositoryToken, Organization, UpdateByQuery, DetectionRepositorySubscription
from ..model.detection import VALID_REPO_SHARE_MODES, VALID_REPO_TYPES
from ..utils import token_required, user_has, default_org
from .shared import mod_pagination, mod_user_list, ISO8601, ValueCount

api = Namespace('DetectionRepository', description='Detection Repository', path='/detection_repository')

mod_detection_repo = api.model('DetectionRepository', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'organization': fields.String,
    'tags': fields.List(fields.String),
    'active': fields.Boolean(default=False),
    'detections': fields.List(fields.String, help='A list of detection_ids NOT uuids of the detections in this repository'),
    'detection_count': ValueCount(attribute='detections'),
    'share_type': fields.String,
    'repo_type': fields.String,
    'subscribed': fields.Boolean,
    'read_only': fields.Boolean,
    'url': fields.String,
    'refresh_interval': fields.Integer,
    'external_tokens': fields.List(fields.String),
    'created_at': ISO8601(),
    'updated_at': ISO8601(),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'access_scope': fields.List(fields.String),
}, strict=True)

mod_detection_repo_create = api.model('DetectionRepositoryCreate', {
    'name': fields.String(required=True),
    'organization': fields.String(required=False),
    'description': fields.String,
    'tags': fields.List(fields.String),
    'active': fields.Boolean(default=False),
    'detections': fields.List(fields.String, help='A list of detection_ids NOT uuids of the detections in this repository'),
    'share_type': fields.String(requried=True, enum=VALID_REPO_SHARE_MODES),
    'repo_type': fields.String(required=True, enum=VALID_REPO_TYPES),
    'access_scope': fields.List(fields.String, required=False),
    'url': fields.String,
    'access_token': fields.String,
    'refresh_interval': fields.Integer
}, strict=True)

mod_detection_repo_list = api.model('DetectionRepositoryList', {
    'repositories': fields.List(fields.Nested(mod_detection_repo)),
    'pagination': fields.Nested(mod_pagination)
})

mod_repo_subscription_sync_settings = api.model('DetectionRepositorySubscriptionSyncSettings', {
    'risk_score': fields.Boolean(default=True),
    'severity': fields.Boolean(default=True),
    'interval': fields.Boolean(default=True),
    'lookbehind': fields.Boolean(default=True),
    'mute_period': fields.Boolean(default=True),
    'threshold_config': fields.Boolean(default=True),
    'metric_change_config': fields.Boolean(default=True),
    'field_mismatch_config': fields.Boolean(default=True),
    'new_terms_config': fields.Boolean(default=True),
    'field_templates': fields.Boolean(default=True),
    'signature_fields': fields.Boolean(default=True),
    'observable_fields': fields.Boolean(default=True),
    'guide': fields.Boolean(default=True),
    'setup_guide': fields.Boolean(default=True),
    'testing_guide': fields.Boolean(default=True),
    'false_positives': fields.Boolean(default=True)
})

mod_repo_subscribe = api.model('DetectionRepositorySubscribe', {
    'sync_interval': fields.Integer,
    'sync_settings': fields.Nested(mod_repo_subscription_sync_settings),
    'default_input': fields.String() ,
    'default_field_template': fields.String(),
})

mod_detection_add = api.model('DetectionRepositoryAddDetections', {
    'detections': fields.List(fields.String, help='A list of detection_ids NOT uuids of the detections in this repository'),
})


# PERMISSIONS
# create_detection_repository
# view_detection_repository
# update_detection_repository
# share_detection_repository
# delete_detection_repository


# POST /detection_repository - Create
# GET /detection_repository - List
# GET /detection_repository/{id} - Get
# PUT /detection_repository/{id} - Update
# PUT /detection_repository/{id}/add_detections - Add Detections
# PUT /detection_repository/{id}/remove_detections - Remove Detections
# PUT /detection_repository/{id}/add_access_token - Add Access Token
# PUT /detection_repository/{id}/remove_access_token - Remove Access Token
# PUT /detection_repository/{id}/activate - Activate the repository
# PUT /detection_repository/{id}/deactivate - Deactivate the repository
# GET /detection_repository/{id}/sync - Sync the repository
# POST /detection_repository/{id}/subscribe - Subscribe to the repository
# POST /detection_repository/{id}/unsubscribe - Unsubscribe from the repository
# DELETE /detection_repository/{id} - Delete


@api.route('/<string:uuid>')
class DetectionRepositoryDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_detection_repo_create)
    @api.marshal_with(mod_detection_repo)
    @token_required
    @default_org
    @user_has('update_detection_repository')
    def put(self, user_in_default_org, current_user, uuid):

        # Locate the detection if it doesn't exist return a 404
        repository = DetectionRepository.get_by_uuid(uuid)
        if not repository:
            api.abort(404, 'Detection Repository not found')

        # If the user is not a member of the default_org don't allow them
        # to change access_scope or the organization of the repository
        if not user_in_default_org:
            if 'organization' in api.payload:
                api.abort(403, 'You do not have permission to change the organization of this repository')
            if 'access_scope' in api.payload:
                api.abort(403, 'You do not have permission to change the access scope of this repository')

        # If the name is changing make sure it doesn't already exist and return a 409 if it does
        if 'name' in api.payload:
            existing_repo = DetectionRepository.get_by_name(api.payload['name'])
            if existing_repo and existing_repo.uuid != uuid:
                api.abort(409, 'A repository with that name already exists')

        if 'access_scope' in api.payload:

            # Determine if any uuids in access_scope have been removed, and for the ones that
            # have been removed, set the from_repo_sync flag to False for any detections
            # that were synced from this repository where the detections organization is the UUID

            # Get the current access_scope
            current_access_scope = repository.access_scope

            # Get the new access_scope
            new_access_scope = api.payload['access_scope']

            # Get the list of uuids that have been removed from the access_scope
            if current_access_scope and new_access_scope:
                removed_uuids = list(set(current_access_scope) - set(new_access_scope))

                if removed_uuids:

                    # Get the list of detections that were synced from this repository
                    # and are in the removed_uuids list
                    detections = Detection.search()
                    detections = detections.filter(
                        'term', from_repo_sync=True)
                    detections = detections.filter('terms', organization=removed_uuids)
                    detections = [d for d in detections.scan()]

                    # Set the from_repo_sync flag to False for all detections that were synced from this repository
                    # and are in the removed_uuids list
                    # TODO: Make this a bulk update - remember to refresh the index
                    for detection in detections:
                        detection.from_repo_sync = False
                        detection.save()


                    # Delete any active subscriptions for the removed_uuids and this repository
                    subscriptions = DetectionRepositorySubscription.search()
                    subscriptions = subscriptions.filter('term', repository=repository.uuid)
                    subscriptions = subscriptions.filter('terms', organization=removed_uuids)
                    subscriptions = [s for s in subscriptions.scan()]

                    for subscription in subscriptions:
                        subscription.delete()

        # Save the changes to the repository
        repository.update(**api.payload)

        repository.check_subscription(organization=current_user.organization)

        # Return the new repo data
        return repository, 200
    
    @api.doc(security="Bearer")
    @token_required
    @default_org
    @user_has('delete_detection_repository')
    def delete(self, user_in_default_org, current_user, uuid):
        '''Delete a repository'''
        repository = DetectionRepository.get_by_uuid(uuid)

        if not repository:
            api.abort(404, 'Detection Repository not found')

        # If the user deleting this repository is not in the same organization 
        # of a default_org member of the repository don't allow them to delete it
        if current_user.organization != repository.organization:
            if not user_in_default_org:
                api.abort(403, 'You do not have permission to delete this repository')

        # Find all detections synchronized from this repo
        update_query = UpdateByQuery(index=Detection._index._name)

        # Find any detection with a detection_id that matches repository.detections
        update_query = update_query.filter('terms', detection_id=repository.detections)

        # Filter for detections that are from_repo_sync
        update_query = update_query.filter('term', from_repo_sync=True)

        # Filter out any detections that are in the same organization as the repository
        # using a bool not match
        update_query = update_query.filter('bool', must_not={'match': {'organization': repository.organization}})

        # Painless script to set from_repo_sync to false
        update_query = update_query.script(source='ctx._source.from_repo_sync = false')

        # Execute the update
        update_query.execute()
        
        # Delete the repository
        repository.delete()

        return {'message': 'Repository deleted'}, 200


@api.route('/<string:uuid>/sync_local_subscribers')
class DetectionRepositorySyncLocalSubscribers(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('sync_local_subscribers')
    def post(self, current_user, uuid):
        '''
        Forces a sync of the repository for all local subscribers.  The user
        must have the sync_local_subscribers permission to perform this action
        and must be a member of the default organization.
        '''

        if not current_user.is_default_org:
            api.abort(403, 'You do not have permission to sync local subscribers')

        # Get the repository
        repository = DetectionRepository.get_by_uuid(uuid)

        # Locate all the local subscriptions for this repository
        subscriptions = DetectionRepositorySubscription.get_by_repository(uuid=uuid)

        # Sync the repository for each local subscriber
        for subscription in subscriptions:
            repository.sync(organization=subscription.organization,
                            subscription=subscription)
            
        return {'message': 'Syncing repository'}, 200


@api.route('/<string:uuid>/sync')
class DetectionRepositorySync(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('subscribe_detection_repository')
    def post(self, current_user, uuid):
        '''Forces a sync of the repository'''
        repository = DetectionRepository.get_by_uuid(uuid)

        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not repository.check_access_scope(organization=current_user.organization):
            api.abort(403, 'You do not have permission to sync this repository')

        repository.check_subscription(organization=current_user.organization)
        if not repository.subscribed:
            api.abort(403, 'You do not have permission to sync this repository')

        repository.sync(organization=current_user.organization)

        return {'message': 'Syncing repository'}, 200


@api.route('/<string:uuid>/subscription')
class DetectionRepositorySubscription(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_repo_subscribe)
    @token_required
    @user_has('subscribe_detection_repository')
    def get(self, current_user, uuid):
        '''Gets the subscription for the repository'''
        repository = DetectionRepository.get_by_uuid(uuid)

        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not repository.check_access_scope(organization=current_user.organization):
            api.abort(403, 'You do not have permission to get the subscription for this repository')

        subscription = repository.get_subscription(organization=current_user.organization)

        if not subscription:
            api.abort(404, 'Subscription not found')

        return subscription, 200
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_repo_subscribe)
    @api.expect(mod_repo_subscribe)
    @token_required
    @user_has('subscribe_detection_repository')
    def put(self, current_user, uuid):
        '''Updates the subscription for the repository'''
        repository = DetectionRepository.get_by_uuid(uuid)

        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not repository.check_access_scope(organization=current_user.organization):
            api.abort(403, 'You do not have permission to update the subscription for this repository')

        subscription = repository.get_subscription(organization=current_user.organization)

        if not subscription:
            api.abort(404, 'Subscription not found')

        subscription.update(**api.payload)

        return subscription, 200

@api.route('/<string:uuid>/subscribe')
class DetectionRepositorySubscribe(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_repo)
    @api.expect(mod_repo_subscribe)
    @token_required
    @user_has('subscribe_detection_repository')
    def post(self, current_user, uuid):
        '''Subscribes to a detection repository
        Permission Required `subscribe_detection_repository`
        '''

        repository = DetectionRepository.get_by_uuid(uuid)
        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not repository.check_access_scope(organization=current_user.organization):
            api.abort(403, 'You do not have permission to subscribe to this repository')
        
        subscription = None

        data = api.payload

        try:
            sync_interval = data['sync_interval']
            sync_settings = data['sync_settings']
            default_input = None
            default_field_template = None
            if 'default_input' in data:
                default_input = data['default_input']

            if 'default_field_template' in data:
                default_field_template = data['default_field_template']
            
            subscription = repository.subscribe(sync_interval=sync_interval,
                                                sync_settings=sync_settings,
                                                default_input=default_input,
                                                default_field_template=default_field_template)
        except ValueError as e:
            api.abort(400, str(e))

        # Sync the repository
        if subscription:
            repository.sync(organization=subscription.organization)

        repository.check_subscription(organization=current_user.organization)

        return repository
    

@api.route('/<string:uuid>/remove_detections')
class DetectionRepositoryRemoveDetections(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_detection_add)
    @token_required
    @default_org
    @user_has('update_detection_repository')
    def post(self, user_in_default_org, current_user, uuid):
        '''Removes detections from a detection repository'''

        repository = DetectionRepository.get_by_uuid(uuid)
        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not user_in_default_org and current_user.organization != repository.organization:
            api.abort(403, 'You do not have permission to remove detections from this repository')

        repository.check_subscription(organization=current_user.organization)

        if repository.read_only:
            api.abort(403, 'You do not have permission to remove detections from this repository')

        data = api.payload

        if not data.get('detections'):
            api.abort(400, 'No detections provided')

        detections = Detection.get_by_uuid(data.get('detections'), organization=repository.organization)
        if detections:
            repository.remove_detections(detections)

        return {'message': 'Detections removed from repository'}, 200


@api.route('/<string:uuid>/add_detections')
class DetectionRepositoryAddDetections(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_detection_add)
    @token_required
    @default_org
    @user_has('update_detection_repository')
    def post(self, user_in_default_org, current_user, uuid):
        '''Adds detections to a detection repository
        Permission Required `update_detection_repository`
        '''

        repository = DetectionRepository.get_by_uuid(uuid)
        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not user_in_default_org and current_user.organization != repository.organization:
            api.abort(403, 'You do not have permission to add detections to this repository')

        repository.check_subscription(organization=current_user.organization)

        if repository.read_only:
            api.abort(403, 'This repository is read only')

        data = api.payload

        if not data.get('detections'):
            api.abort(400, 'No detections provided')

        detections = Detection.get_by_uuid(data.get('detections'), organization=repository.organization, all_results=True)
        if detections:
            repository.add_detections(detections=detections)
        else:
            api.abort(400, 'No detections found')

        return {'message': 'Detections added to repository'}, 200

@api.route('/<string:uuid>/unsubscribe')
class DetectionRepositoryUnsubscribe(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_repo)
    @token_required
    @user_has('subscribe_detection_repository')
    def post(self, current_user, uuid):
        '''Unsubscribes from a detection repository
        Permission Required `subscribe_detection_repository`
        '''

        repository = DetectionRepository.get_by_uuid(uuid)
        if not repository:
            api.abort(404, 'Detection Repository not found')

        if not repository.check_access_scope(organization=current_user.organization):
            api.abort(403, 'You do not have permission to unsubscribe from this repository')
        
        subscription = None

        try:
            subscription = repository.unsubscribe(organization=current_user.organization)
        except ValueError as e:
            api.abort(400, str(e))

        if not subscription:
            # Remove all the rules from the organizations detections library
            repository.remove_rules(organization=current_user.organization)

        repository.check_subscription(organization=current_user.organization)

        return repository   


@api.route('')
class DetectionRepositoryList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_repo_list)
    @token_required
    @user_has('view_detection_repositories')
    def get(self, current_user):
        '''Returns a list of detection repositories
        Permission Required `view_detection_repositories`
        '''

        repositories = DetectionRepository.search()
        repositories = [repo for repo in repositories.scan()]

        # Filter by repositories that this organization owns or has access to
        # via the access scope field, if the access_scope field is empty then
        # the user has access to the repository
        repositories = [repo for repo in repositories if repo.check_access_scope(current_user.organization)]

        # Get subscription status for each repository
        [repo.check_subscription(organization=current_user.organization) for repo in repositories]

        return {
            'repositories': repositories,
            'pagination': {
                'total': len(repositories),
                'page': 1,
                'page_size': 25,
                'pages': 1
            }
        }
    
    @api.doc(security="Bearer")
    @api.expect(mod_detection_repo_create)
    @api.marshal_with(mod_detection_repo)
    @token_required
    @user_has('create_detection_repository')
    def post(self, current_user):
        '''Creates a detection repository
        Permission Required `create_detection_repository`
        Valid Share Types: `private`, `local-shared`, `external-private`, `external-public`
        Valid Repository Types: `local`, `remote`
        '''

        data = api.payload

        # Do not allow the user to set the UUID
        if 'uuid' in data:
            del data['uuid']

        if 'organization' in data:
            if data['organization'] != current_user.organization and not current_user.default_org:
                api.abort(403, 'You do not have permission to create a repository in this organization')
        else:
            data['organization'] = current_user.organization

        organization = Organization.get_by_uuid(data['organization'])
        if not organization:
            api.abort(404, 'Target Organization not found')

        if data['share_type'] not in VALID_REPO_SHARE_MODES:
            api.abort(400, 'Invalid share type')

        if data['repo_type'] not in VALID_REPO_TYPES:
            api.abort(400, 'Invalid repository type')

        if not current_user.has_right('share_detection_repository') and data['share_type'] != 'private':
            api.abort(403, 'You do not have permission to create a repository of this type')

        # Depending on the repository type, override certain field values
        if data['repo_type'] == 'local':
            data['url'] = None # Local repositories cannot have a URL
            data['access_token'] = None # Local repositories cannot have access tokens
            data['refresh_interval'] = None 

        if data['repo_type'] == 'remote':
            data['share_type'] = None # Remote repositories cannot be shared
            data['detections'] = [] # Remote repositories cannot have detections
            data['refresh_interval'] = 60 # Default to 60 minutes

        # Check to make sure any detections being added to the repository exist
        # if they don't, remove them from the list
        if 'detections' in data and data['detections']:
            detections = Detection.get_by_detection_id(detection_id=data['detections'], organization=data['organization'])

            # If the detection is from a repository sync, remove it from the list as sharing
            # detections from a repo in another repo is not supported
            data['detections'] = [d.detection_id for d in detections if d.from_repo_sync is not True]

        # Set the default risk score if one is not provided
        if 'risk_score' not in data:
            data['risk_score'] = 50

        existing_repo = DetectionRepository.get_by_name(name=data['name'], organization=data['organization'])
        if existing_repo:
            api.abort(409, 'A repository with this name already exists')

        repo = DetectionRepository(**data)
        repo.save()

        return repo
    