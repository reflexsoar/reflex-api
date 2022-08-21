import logging
import time
from app.api_v2.model import Notification, NotificationChannel, NOTIFICATION_CHANNEL_TYPES


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
            if notification_type.endswith('_webhook'):
                self.notification_type_mapping[notification_type] = self.send_webhook
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
            'MAX_THREADS': 1
        })
        self.config = config
        self.set_log_level(config['LOG_LEVEL'])

        self.logger.info('Notifier Started')

    def check_notifications(self):
        '''
        Checks the notification queue to see if there are any to send
        '''

        while True:
            notifications = Notification.search()
            notifications = notifications.filter(
                'term', sent=False)  # Only send unsent notifications
            notifications = notifications.filter('match', closed=False)
            notifications = notifications.scan()
            notifications = notifications.execute()

            if notifications:
                for notification in notifications:

                    # If an incorrect notification type is assigned reject the notification
                    if notification.channel_type not in NOTIFICATION_CHANNEL_TYPES:
                        notification.send_failed(
                            message='Invalid channel type')

                    # If the notification type is not mapped to a function reject the notification
                    if notification.channel_type not in self.notification_type_mapping:
                        notification.send_failed(
                            message='Channel type not mapped to a notifier function')
                    else:
                        self.notification_type_mapping[notification.channel_type](
                            notification)

            time.sleep(self.config['POLL_INTERVAL'])

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
        channels = channel.execute()

        errors = []
        _channels = []

        if channels:

            # If only one channel is configured turn it in to a list anyway so that code
            # does not have to be re-used
            if not isinstance(channels, list):
                channels = [channels]

            for channel in channels:

                # If the notification attemps to use a channel that is across the organizational bounds
                # reject the notification
                if notification.organization != channel.organization:
                    error_message = f"No channel found for notification {notification.uuid}"
                    errors.append(error_message)
                    self.logger.error(error_message)
                else:
                    _channels.append(channel)
        
        if len(errors) > 0 and len(_channels) > 0:
            notification.error_message = errors
            notification.partial_success = True
            notification.save()
        
        if len(errors) > 0 and len(_channels) == 0:
            notification.send_failed(message=errors)

        return _channels 


    def send_webhook(self, notification):
        '''
        Sends a message to a webhook destination
        '''

        # Get and filter the channels for the notification
        channels = self.get_channels(notification)

        return False

    def send_reflex(self):
        '''
        Sends the notification to a users specific notification queue
        '''
        raise NotImplementedError
