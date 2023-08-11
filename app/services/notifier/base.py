from datetime import datetime
import logging
import json
import time
import pymsteams
import chevron
import requests
import smtplib
import ssl
import markdown
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment
from jinja2.exceptions import UndefinedError as JinjaUndefinedError
from pdpyras import EventsAPISession
from requests.exceptions import ConnectionError
from app.api_v2.model import Notification, NotificationChannel, NOTIFICATION_CHANNEL_TYPES, SOURCE_OBJECT_TYPE, Event, Case, Settings, Credential, Detection


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

        self.logger = logging.getLogger("Notifier")
        self.logger.addHandler(ch)
        self.logger.setLevel(log_levels[log_level])

        self.notification_type_mapping = {}

        for notification_type in NOTIFICATION_CHANNEL_TYPES:
            if notification_type == 'teams_webhook':
                self.notification_type_mapping[notification_type] = self.send_teams_webhook
            if notification_type == 'slack_webhook':
                self.notification_type_mapping[notification_type] = self.send_slack_webhook
            if notification_type == 'email':
                self.notification_type_mapping[notification_type] = self.send_email
            if notification_type == 'reflex':
                self.notification_type_mapping[notification_type] = self.send_reflex
            if notification_type == 'pagerduty_api':
                self.notification_type_mapping[notification_type] = self.send_pagerduty_api
            if notification_type == 'rest_api':
                self.notification_type_mapping[notification_type] = self.send_rest_api_call

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
                if not notification.is_native:
                    channels = self.get_channels(notification)
                    for channel in channels:
                        try:
                            self.notification_type_mapping[channel.channel_type](channel,notification)
                        except KeyError:
                            self.logger.error(f"Channel type {channel.channel_type} is not supported")
                else:
                    # Send the notification via the organizations configured SMTP server
                    # if the user has subscribed to events via SMTP
                    pass


    def send_email(self, channel, notification):
        '''
        Sends an email to a target user
        '''

        """

        # Find all the users emails and add them to the recipient list
        uuids = [u.uuid for u in users]
        users = User.get_by_uuid(uuid=uuids)
        [recipients.append(u.email) for u in users]
        """

        channel_config = channel.email_configuration
        message_template = channel_config['message_template']
        credential = Credential.get_by_uuid(channel_config['credential'])
        if credential:
            try:
                secret = credential.decrypt(secret=self.app.config['MASTER_PASSWORD'])
            except:
                self.logger.error(f"Unable to decrypt credential {credential.uuid}")
                notification.send_failed(message=f"Unable to decrypt credential {credential.uuid}")

            if hasattr(notification, 'source_object_type') and hasattr(notification, 'source_object_uuid'):
                if notification.source_object_type not in ['', None] and notification.source_object_uuid not in ['', None]:
                    notification.message = self.use_template(message_template, notification.source_object_type, notification.source_object_uuid)

        subject = self.use_template(channel_config['subject'], notification.source_object_type, notification.source_object_uuid, skip_detection=True)

        # Create the base message
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = channel_config['mail_from']
            message["To"] = ','.join(channel_config['mail_to'])

            # Create the plain-text and HTML version of your message
            text = notification.message

            part1 = MIMEText(text, "plain")
            part2 = MIMEText(markdown.markdown(text), "html")

            message.attach(part1)
            message.attach(part2)

            connection = smtplib.SMTP(channel_config['smtp_server'], channel_config['smtp_port'])

            # If the mail server requires TLS
            if 'use_tls' in channel_config and channel_config['use_tls']:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)

                connection.ehlo()
                connection.starttls(context=context)
                connection.ehlo()
                
                if 'credential' in channel_config:
                    connection.login(credential.username, secret)

                connection.sendmail(channel_config['mail_from'], channel_config['mail_to'], message.as_string())
            else:
                
                
                if 'credential' in channel_config:
                    connection.login(credential.username, secret)
                connection.sendmail(channel_config['mail_from'], channel_config['mail_to'], message.as_string())
        except Exception as e:
            notification.send_failed(message=f"Unable to send email: {e}")
        
        notification.send_success()


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
        channels = [c for c in channel.scan()]

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
                if notification.organization != channel.organization and not channel.is_global:
                    error_message = f"No channel found for notification {notification.uuid}"
                    errors.append(error_message)
                    self.logger.error(error_message)
                elif channel.muted:
                    error_message = f"Channel {channel.uuid} is muted"
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
        environment = Environment()

        if source_object_type in SOURCE_OBJECT_TYPE:
            source_object = None
            source_object = OBJECT_MAP[source_object_type].get_by_uuid(uuid=source_object_uuid)

            if 'skip_detection' in kwargs and kwargs['skip_detection']:
                pass

            else:
                if hasattr(source_object, 'detection_id'):
                    detection = Detection.get_by_uuid(uuid=source_object.detection_id)
                    if detection:
                        if hasattr(detection, 'email_template') and detection.email_template != "":
                            template = detection.email_template

            jinja_template = environment.from_string(template)
                            
            if source_object:                

                source_dict = source_object.to_dict()
                if 'raw_log' in source_dict:
                    source_dict['raw_log'] = json.loads(source_dict['raw_log'])
                try:
                    message = jinja_template.render(source_dict)
                except JinjaUndefinedError as e:
                    message = template + "\n\n" + f"Error parsing source object: {str(e)}"

                #message = chevron.render(template, source_object.to_dict())
                return message

        return template

    
    def send_pagerduty_api(self, channel, notification):
        '''
        Sends a notification to PagerDuty via the API
        '''
        channel_config = channel.pagerduty_configuration
        message_template = channel_config['message_template']
        credential = Credential.get_by_uuid(uuid=channel_config.credential)
        if credential:
            try:
                secret = credential.decrypt(secret=self.app.config['MASTER_PASSWORD'])
            except:
                self.logger.error(f"Unable to decrypt credential {credential.uuid}")
                notification.send_failed(message=f"Unable to decrypt credential {credential.uuid}")
            session = EventsAPISession(secret)

            if hasattr(notification, 'source_object_type') and hasattr(notification, 'source_object_uuid'):
                if notification.source_object_type not in ['', None] and notification.source_object_uuid not in ['', None]:
                    notification.message = self.use_template(message_template, notification.source_object_type, notification.source_object_uuid)

            if notification.source_object_type == 'event':
                event = Event.get_by_uuid(notification.source_object_uuid)
                dedup_key = event.signature
            else:
                dedup_key = session.trigger(notification.message, "ReflexSOAR Notifications")
                
            if dedup_key:
                notification.send_success()
        else:
            notification.send_failed(message=[f'Could not connect locate Credential.  Please check the configuration for channel {channel.uuid}']) 


    def send_teams_webhook(self, channel, notification):
        '''
        Sends a message to a Microsoft Teams webhook
        '''
        
        channel_config = channel.teams_configuration
        webhook_url = channel_config['webhook_url']
        message_template = channel_config['message_template']
        teams_message = pymsteams.connectorcard(webhook_url)

        settings = Settings.load(organization=channel.organization)

        if hasattr(notification, 'title') and notification.title:
            teams_message.title(notification.title)
        else:
            teams_message.title('ReflexSOAR Notification')
       
        if hasattr(notification, 'source_object_type') and hasattr(notification, 'source_object_uuid'):
            if notification.source_object_type not in ['', None] and notification.source_object_uuid not in ['', None]:
                notification.message = self.use_template(message_template, notification.source_object_type, notification.source_object_uuid)

                # Add a View Event button if this was sourced from an event
                if notification.source_object_type == 'event':
                    teams_message.addLinkButton("View Event", f"{settings.base_url}/#/alerts/{notification.source_object_uuid}")

                # Add a View Case button if this was sourced from an event
                if notification.source_object_type == 'case':
                    teams_message.addLinkButton("View Case", f"{settings.base_url}/#/cases/{notification.source_object_uuid}")               

        teams_message.text(notification.message)

        try:
            result = teams_message.send()
            if result:
                notification.send_success()
        except ConnectionError as e:
            notification.send_failed(message=[f'Could not connect to Microsoft Teams. {e}'])       

    def send_slack_webhook(self, channel, notification):
        '''
        Sends a webhook to Slack
        '''
        message = notification.message
        channel_config = channel.slack_configuration
        webhook_url = channel_config['webhook_url']
        message_template = channel_config['message_template']

        if hasattr(notification, 'source_object_type') and hasattr(notification, 'source_object_uuid'):
            if notification.source_object_type not in ['', None] and notification.source_object_uuid not in ['', None]:
                notification.message = self.use_template(message_template, notification.source_object_type, notification.source_object_uuid)

        try:
            data = {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": notification.message
                        }
                    }
                ]
            }
            headers = {
                'Content-Type': 'application/json'
            }
            request = requests.post(webhook_url, headers=headers, json=data)
            if request.status_code == 200:
                notification.send_success()
            else:
                notification.send_failed(message=[f'Could not connect to Slack. {request.status_code} - {request.text}'])
        except Exception as e:
            notification.send_failed(message=[f'Could not connect to Slack. {e}'])


    def send_webhook(self, channel, notification):
        '''
        Sends a message to a webhook destination
        '''

        print(f"Webhook URL: {channel.to_dict()}")
        


        return False

    def send_rest_api_call(self, channel, notification): 
        '''
        Sends a REST API call to the defined destination
        '''
        
        channel_config = channel.rest_api_configuration
        session = requests.Session()
        session.headers.update(channel_config.headers)
        print(channel_config.headers)
        print(session.headers)
        
        if hasattr(notification, 'source_object_type') and hasattr(notification, 'source_object_uuid'):
            if notification.source_object_type not in ['', None] and notification.source_object_uuid not in ['', None]:
                channel_config.body = self.use_template(channel_config.body, notification.source_object_type, notification.source_object_uuid)

        try:
            response = session.post(channel_config.api_url, data=channel_config.body)
            if response.status_code == 200:
                notification.send_success()
            else:
                notification.send_failed(message=[f'Could not send notification to REST API. {response.status_code} - {response.text}'])
        except ConnectionError as e:
            notification.send_failed(message=[f'Could not connect to REST API. {e}'])       
         

    def send_reflex(self):
        '''
        Sends the notification to a users specific notification queue
        '''
        raise NotImplementedError
