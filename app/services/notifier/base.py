from datetime import datetime
import logging
import time
import pymsteams
import chevron
from app.api_v2.model import Notification, NotificationChannel, NOTIFICATION_CHANNEL_TYPES, SOURCE_OBJECT_TYPE, Event, Case


class Notifier(object):
    '''
    Notifier handles all sorts of notification activity
    Can send webhooks, emails, etc on behalf of the 
    Reflex system.
    Example: E-mail the user when a case is assigned to them
    '''

    def __init__(self, app=None, log_level="DEBUG", *args, **defaults):

        if app:
            self.init_app(app, **defaults)

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(f"ThreatPoller")
        self.logger.addHandler(ch)
        self.logger.setLevel(log_levels[log_level])

        self.notification_type_mapping = {}

        for notification_type in NOTIFICATION_CHANNEL_TYPES:
            if notification_type == 'teams_webhook':
                self.notification_type_mapping[notification_type] = self.send_teams_webhook
                #self.notification_type_mapping[notification_type] = self.send_webhook
            if notification_type == 'email':
                self.notification_type_mapping[notification_type] = self.send_email
            if notification_type == 'reflex':
                self.notification_type_mapping[notification_type] = self.send_reflex

    def set_log_level(self, log_level):
        '''Allows for changing the log level after initialization'''

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        self.logger.setLevel(log_levels[log_level])
        self.log_level = log_level

    def init_app(self, app, **defaults):
        ''' Initialize the Notifier from within an application factory '''
        self.app = app
        config = self.app.config.get('NOTIFIER', {
            'LOG_LEVEL': 'DEBUG',
            'MAX_THREADS': 1,
            'POLL_INTERVAL': 30
        })
        self.config = config
        self.set_log_level(config['LOG_LEVEL'])

        self.logger.info('Notifier Started')


    def check_notifications(self):
        '''
        Checks the notification queue to see if there are any to send
        '''

        self.logger.info('Checking for new notifications')

        notifications = Notification.search()
        notifications = notifications.filter(
            'term', sent=False)  # Only send unsent notifications
        notifications = notifications.filter('exists', field='sent')
        notifications = notifications.filter('match', sent=False)
        notifications = notifications.scan()

        if notifications:
            for notification in notifications:
                channels = self.get_channels(notification)
                for channel in channels:
                    self.notification_type_mapping[channel.channel_type](channel,notification)


    def send_email(self, sender: str, users: list, subject: str, recipients: list = []):
        '''
        Sends an email to a target user
        '''

        """

        # Find all the users emails and add them to the recipient list
        uuids = [u.uuid for u in users]
        users = User.get_by_uuid(uuid=uuids)
        [recipients.append(u.email) for u in users]
        """
        raise NotImplementedError


    def get_channels(self, notification):
        '''
        Fetches the configured channels for the notification in question
        and also performs some permission checks on the channel before allowing
        it to be used.  Returns a list of channels.
        '''
        # Attempt to find the configured notification channel
        channel = NotificationChannel.search()
        channel = channel.filter('term', uuid=notification.channel)
        channel = channel.filter('term', enabled=True)
        channels = channel.execute()

        errors = []
        _channels = []

        if channels:

            # If only one channel is configured turn it in to a list anyway so that code
            # does not have to be re-used
            if not isinstance(channels, list):
                channels = [c for c in channels]

            for channel in channels:

                # If the notification attemps to use a channel that is across the organizational bounds
                # reject the notification
                if notification.organization != channel.organization:
                    error_message = f"No channel found for notification {notification.uuid}"
                    errors.append(error_message)
                    self.logger.error(error_message)
                else:
                    _channels.append(channel)

        else:
            notification.send_failed(message=['No channels available for notification'])
        
        if len(errors) > 0 and len(_channels) > 0:
            notification.error_message = errors
            notification.partial_success = True
            notification.save()
        
        if len(errors) > 0 and len(_channels) == 0:
            notification.send_failed(message=errors)

        return _channels


    def use_template(self, template, source_object_type, source_object_uuid, **kwargs):
        '''
        Uses a template to generate a message
        '''
        OBJECT_MAP = {
            'event': Event,
            'case': Case
        }

        message = ""

        if source_object_type in SOURCE_OBJECT_TYPE:
            source_object = None
            source_object = OBJECT_MAP[source_object_type].get_by_uuid(uuid=source_object_uuid)
            if source_object:
                message = chevron.render(template, source_object.to_dict())
                return message

        return template       

    
    def send_teams_webhook(self, channel, notification):
        '''
        Sends a message to a Microsoft Teams webhook
        '''
        channel_config = channel.teams_configuration
        webhook_url = channel_config['webhook_url']
        message_template = channel_config['message_template']
        teams_message = pymsteams.connectorcard(webhook_url)

        if hasattr(notification, 'title') and notification.title:
            teams_message.title(notification.title)
        else:
            teams_message.title('ReflexSOAR Notification')
       
        if hasattr(notification, 'source_object_type') and hasattr(notification, 'source_object_uuid'):
            if notification.source_object_type not in ['', None] and notification.source_object_uuid not in ['', None]:
                notification.message = self.use_template(message_template, notification.source_object_type, notification.source_object_uuid)

        teams_message.text(notification.message)

        result = teams_message.send()
        if result:
            notification.sent = True
            notification.time_sent = datetime.utcnow()
            notification.success = True
            notification.save()


    def send_webhook(self, channel, notification):
        '''
        Sends a message to a webhook destination
        '''

        print(f"Webhook URL: {channel.to_dict()}")


        return False

    def send_reflex(self):
        '''
        Sends the notification to a users specific notification queue
        '''
        raise NotImplementedError
