from flask_restx import Resource, Namespace, fields

from ..model import DetectionRepository, Detection, DetectionRepositoryToken, Organization
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
    'updated_by': fields.Nested(mod_user_list)
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

mod_repo_subscribe = api.model('DetectionRepositorySubscribe', {
    'sync_interval': fields.Integer,
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

        # Save the changes to the repository
        repository.update(**api.payload)

        repository.check_subscription(organization=current_user.organization)

        # Return the new repo data
        return repository, 200


@api.route('/<string:uuid>/sync')
class DetectionRepositorySync(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('subscribe_detection_repository')
    def post    (self, current_user, uuid):
        '''Forces a sync of the repository'''
        repository = DetectionRepository.get_by_uuid(uuid)

        if not repository:
            api.abort(404, 'Detection Repository not found')

        if current_user.organization not in repository.access_scope:
            api.abort(403, 'You do not have permission to sync this repository')

        repository.check_subscription(organization=current_user.organization)
        if not repository.subscribed:
            api.abort(403, 'You do not have permission to sync this repository')

        repository.sync(organization=current_user.organization)

        return {'message': 'Syncing repository'}, 200


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

        if current_user.organization not in repository.access_scope:
            api.abort(403, 'You do not have permission to subscribe to this repository')
        
        subscription = None

        try:
            subscription = repository.subscribe()
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

        detections = Detection.get_by_uuid(data.get('detections'), organization=repository.organization)
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

        if current_user.organization not in repository.access_scope:
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

        # Filter by repositories that this organization owns or has access to
        # via the access scope field
        repositories = repositories.filter('bool', should=[
            {'term': {'organization': current_user.organization}},
            {'bool': {
                'must': [
                    {'term': {'share_type': 'local-shared'}},
                    {'term': {'access_scope': current_user.organization}}
                ]
            }}
        ])

        # TODO: Fetch only the repositories that the user has access to which includes
        # repositories in their organization, remote repositories their organization
        # owns and local-shared repositories from the default organization
        repositories = [repo for repo in repositories.scan()]

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
            print(data['detections'])

        existing_repo = DetectionRepository.get_by_name(name=data['name'], organization=data['organization'])
        if existing_repo:
            api.abort(409, 'A repository with this name already exists')

        repo = DetectionRepository(**data)
        repo.save()

        return repo
    