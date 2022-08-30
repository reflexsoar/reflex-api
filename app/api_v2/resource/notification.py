from ..model.user import Organization
from ..utils import page_results, strip_meta_fields, token_required, user_has, ip_approved, check_org, default_org, strip_meta_fields
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from flask import current_app
from .shared import mod_pagination, ISO8601, JSONField, mod_user_list
from app.api_v2.model import (
    NotificationChannel, Notification, NOTIFICATION_CHANNEL_TYPES, Credential, notification
)

api = Namespace('Notification', description='Notification Channels and Notifications',
                path='/notification', strict=True)

'''
Permissions:
    - create_notification_channel
    - view_notification_channels
    - update_notification_channel
    - delete_notification_channel
    - view_notifications
'''

mod_notification = api.model('NotificationDetails', {
    'created_at': ISO8601,
    'organization': fields.String,
    'sent': fields.Boolean,
    'success': fields.Boolean,
    'partial_success': fields.Boolean,
    'time_sent': ISO8601,
    'error_message': fields.List(fields.String),
    'channel': fields.String,
    'viewed': fields.Boolean,
    'source_object_type': fields.String,
    'source_object_uuid': fields.String,
    'message': fields.String,
    'title': fields.String,
})

mod_email_configuration = api.model('EmailConfiguration', {
    'credential': fields.String,
    'smtp_server': fields.String,
    'smtp_port': fields.Integer,
    'use_tls': fields.Boolean,
    'mail_from': fields.String,
    'subject': fields.String,
    'mail_to': fields.List(fields.String),
    'message_template': fields.String
})

mod_slack_configuration = api.model('SlackWebhook', {
    'webhook_url': fields.String,
    'message_template': fields.String
})

mod_teams_configuration = api.model('TeamsWebhook', {
    'webhook_url': fields.String,
    'message_template': fields.String
})

mod_pagerduty_configuration = api.model('PagerDutyWebhook', {
    'webhook_url': fields.String,
    'message_template': fields.String
})

mod_api_header = api.model('CustomerAPIHeader', {
    'key': fields.String,
    'value': fields.String
})

mod_custom_api_configuration = api.model('CustomAPI', {
    'api_url': fields.String,
    'headers': fields.List(fields.Nested(mod_api_header)),
    'body': fields.String,
    'tls_insecure': fields.Boolean
})

mod_create_notification_channel = api.model('CreateNotificationChannel', {
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'channel_type': fields.String,
    'email_configuration': fields.Nested(mod_email_configuration),
    'slack_configuration': fields.Nested(mod_slack_configuration),
    'teams_configuration': fields.Nested(mod_teams_configuration),
    'pagerduty_configuration': fields.Nested(mod_pagerduty_configuration),
    'rest_api_configuration': fields.Nested(mod_custom_api_configuration),
    'max_messages': fields.Integer,
    'backoff': fields.Integer,
    'enabled': fields.Boolean
}, strict=True)

mod_notification_channel = api.clone('NotificationChannelDetails', mod_create_notification_channel, {
    'uuid': fields.String,
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_at': ISO8601,
    'updated_by': fields.Nested(mod_user_list)
})

mod_notification_channel_paged_list = api.model('NotificationChannelPagedList', {
    'channels': fields.List(fields.Nested(mod_notification_channel)),
    'pagination': fields.Nested(mod_pagination)
})

mod_notification_paged_list = api.model('NotificationPagedList', {
    'notifications': fields.List(fields.Nested(mod_notification)),
    'pagination': fields.Nested(mod_pagination)
})




@api.route("/test")
class TestNotification(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        notification = Notification(
            sent=False,
            channel='ff0bb016-173a-4241-a17c-99821d3d696a',
            source_object_type='event',
            source_object_uuid='87bd454a-01bd-409b-889a-14cd90ba30ec'
        )
        notification.save()

@api.route("/channel/<uuid>")
class NotificationChannelDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_notification_channel)
    @api.expect(mod_create_notification_channel, skip_none=True)
    @token_required
    @strip_meta_fields
    @check_org
    @user_has('update_notification_channel')
    def put(self, current_user, uuid):

        if api.payload['channel_type'] not in NOTIFICATION_CHANNEL_TYPES:
            api.abort(
                400, f'Invalid channel type {api.payload["channel_type"]}.  Must be one of {NOTIFICATION_CHANNEL_TYPES}')

        channel = None
        if 'organization' in api.payload:
            org = Organization.get_by_uuid(api.payload['organization'])

            if not org:
                api.abort(
                    400, f'Invalid organization "{api.payload["organization"]}"')

            channel = NotificationChannel.get_by_uuid(
                organization=api.payload['organization'], uuid=uuid)
            existing_channel = NotificationChannel.get_by_name(
                organization=api.payload['organization'], name=api.payload['name'])
        else:
            channel = NotificationChannel.get_by_uuid(uuid=uuid)
            existing_channel = NotificationChannel.get_by_name(name=api.payload['name'])

        if not channel:
            api.abort(404, f'Notification channel "{uuid}" not found')

        if channel and existing_channel:
            if channel.name == existing_channel.name and channel.uuid != existing_channel.uuid:
                api.abort(409, f'Channel for the name "{api.payload["name"]}" already exists')

        channel.update(**api.payload)
        return channel


channel_parser = api.parser()
channel_parser.add_argument(
    'organization', type=str, help='The organization to filter by', location='args', required=False)
channel_parser.add_argument('enabled', type=xinputs.boolean,
                            help='Is the channel enabled', location='args', required=False)
channel_parser.add_argument('name__like', type=str, help='The name to filter by', location='args', required=False)
channel_parser.add_argument(
    'page', type=int, help='The page number', location='args', required=False, default=1)
channel_parser.add_argument('page_size', type=int, help='The number of items per page',
                            location='args', required=False, default=25)
@api.route("/channel")
class NotificationChannelList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_notification_channel_paged_list)
    @api.expect(channel_parser)
    @token_required
    @default_org
    @user_has('view_notification_channels')
    def get(self, current_user, user_in_default_org):
        '''
        Get a list of all notification channels
        '''

        pages = 0
        total_results = 0

        args = channel_parser.parse_args()

        channels = NotificationChannel.search()

        # Filter by active or inactive channels
        if args.enabled:
            channels = channels.filter('term', enabled=args.active)

        # Wildcard search on a name __like
        if args.name__like:
            channels = channels.query('wildcard', name=f'*{args.name__like}*')

        if user_in_default_org:
            if args.organization:
                channels = channels.filter('term', organization=args.organization)

        channels, total_results, pages = page_results(
            channels, args.page, args.page_size)
        channels = channels.execute()

        return {
            'channels': channels,
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_notification_channel)
    @api.expect(mod_create_notification_channel)
    @token_required
    @check_org
    @user_has('create_notification_channel')
    def post(self, current_user):

        if api.payload['channel_type'] not in NOTIFICATION_CHANNEL_TYPES:
            api.abort(
                400, f'Invalid channel type {api.payload["channel_type"]}.  Must be one of {NOTIFICATION_CHANNEL_TYPES}')

        channel = None
        if 'organization' in api.payload:
            org = Organization.get_by_uuid(api.payload['organization'])

            if not org:
                api.abort(
                    400, f'Invalid organization "{api.payload["organization"]}"')

            channel = NotificationChannel.get_by_name(
                organization=api.payload['organization'], name=api.payload['name'])
        else:
            channel = NotificationChannel.get_by_name(name=api.payload['name'])

        if channel:
            api.abort(
                409, f'Channel for the name "{api.payload["name"]}" already exists')
        else:

            if api.payload['channel_type'] == 'email':
                if 'credential' in api.payload['email_configuration']:
                    credential = Credential.get_by_uuid(api.payload['email_configuration']['credential'])
                    if not credential:
                        cred = api.payload['email_configuration']['credential']
                        api.abort(400, f'Credential "{cred}" not found')
                else:
                    api.abort(400, 'Credential is required for email channels')

            channel = NotificationChannel(**api.payload)
            channel.save(refresh=True)

        return channel
