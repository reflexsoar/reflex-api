from flask_restx import Resource, Namespace, fields

from ..model import DetectionRepository, Detection, DetectionRepositoryToken, Organization
from ..model.detection import VALID_REPO_SHARE_MODES, VALID_REPO_TYPES
from ..utils import token_required, user_has
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
    'url': fields.String,
    'access_token': fields.String,
    'refresh_interval': fields.Integer
}, strict=True)

mod_detection_repo_list = api.model('DetectionRepositoryList', {
    'repositories': fields.List(fields.Nested(mod_detection_repo)),
    'pagination': fields.Nested(mod_pagination)
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
# DELETE /detection_repository/{id} - Delete


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
        if data['detections']:
            detections = Detection.get_by_detection_id(detection_id=data['detections'], organization=data['organization'])

            # If the detection is from a repository sync, remove it from the list as sharing
            # detections from a repo in another repo is not supported
            data['detections'] = [d.uuid for d in detections if d.from_repo_sync is False]

        existing_repo = DetectionRepository.get_by_name(name=data['name'], organization=data['organization'])
        if existing_repo:
            api.abort(409, 'A repository with this name already exists')

        repo = DetectionRepository(**data)
        repo.save()

        return repo
    