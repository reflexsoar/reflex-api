"""app/api_v2/model/notification.py

Contains all the logic for Notification interaction with the API
"""

import datetime
from multiprocessing.sharedctypes import Value
from xmlrpc.client import DateTime
from . import (
    Keyword,
    Boolean,
    Integer,
    Text,
    base,
    Nested,
    InnerDoc
)


NOTIFICATION_CHANNEL_TYPES = [
    'email', 'slack_webhook', 'pagerduty_api', 'teams_webhook', 'reflex', 'generic_webhook', 'rest_api'
]

SOURCE_OBJECT_TYPE = [
    'event', 'case'
]

NATIVE_TYPES = [
    'case_assigned',
    'case_severity_changed',
    'case_closed',
    'user_mentioned',
    'case_comment_added'
]

class PagerDutyAPI(InnerDoc):
    '''
    A simple configuration for creating incidents via PagerDuty
    '''

    message_template = Keyword()  # The message template to use when creating an incident
    credential = Keyword() # The PD API key to use when creating an incident
    default_from = Keyword() # The dummy user to send the incident from


class EmailNotificationTemplate(base.BaseDocument):
    '''
    A Notification Template is a template that can be used to create a notification
    '''

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-email-notification-templates'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword(fields={'Text': Text()})
    description = Keyword(fields={'Text': Text()})
    subject = Keyword(fields={'Text': Text()})
    template = Keyword() # The template to use when creating a notification
    enabled = Boolean() # Whether the template is enabled or not
    internal_id = Keyword() # The internal ID of the template, system reserved


class EmailNotification(InnerDoc):
    '''
    Stores the configuration for an e-mail based notification channel
    '''

    credential = Keyword()  # The credential to use when sending the e-mail
    mail_from = Keyword() # The e-mail address to send the e-mail from
    subject = Keyword() # The subject of the e-mail
    mail_to = Keyword() # The e-mail address to send the e-mail to
    smtp_server = Keyword() # The SMTP server to use when sending the e-mail
    smtp_port = Keyword() # The SMTP port to use when sending the e-mail
    use_tls = Boolean() # Whether to use TLS when sending the e-mail
    message_template = Keyword() # The message template to use when sending the e-mail


class TeamsWebhook(InnerDoc):
    '''
    A simple configuration for a Teams notification channel
    '''

    webook_url = Keyword()  # The URL to send the Teams webhook to
    message_template = Keyword()  # The message template to use when creating a message


class SlackWebhook(InnerDoc):
    '''
    A simple configuration for a Slack notification channel
    '''

    webhook_url = Keyword()  # The URL to send the Slack webhook to
    message_template = Keyword()  # The message template to use when creating a message


class APIHeader(InnerDoc):
    '''
    An API header
    '''
    key = Keyword() # The key of the header
    value = Keyword() # The value of the header


class CustomAPI(InnerDoc):
    '''
    A simple configuration for a custom API call
    '''
    api_url = Keyword() # The URL to send the API call to
    headers = Nested(APIHeader) # The headers to use when making the API call
    body = Keyword() # The body to use when making the API call
    tls_insecure = Boolean() # Whether to use TLS when making the API call


class NotificationChannel(base.BaseDocument):

    '''
    A Notification Channel is a target destination for configured notifications.
    It can be anything from e-mail, to slack/teams, twitter, case management
    etc.
    '''

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-notification-channels'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword(fields={'Text': Text()})
    enabled = Boolean()
    description = Keyword(fields={'Text': Text()})
    channel_type = Keyword()
    email_configuration = Nested(EmailNotification)
    slack_configuration = Nested(SlackWebhook)
    teams_configuration = Nested(TeamsWebhook)
    pagerduty_configuration = Nested(PagerDutyAPI)
    rest_api_configuration = Nested(CustomAPI)
    max_messages = Integer()  # The max number of notifications to send per minute
    # How long the notifier should back off on this channel if max_messages is exceeded
    backoff = Integer()
    muted = Boolean() # If the max_messages is achieved then the notification channel will be disabled until the backoff is reset
    muted_until = DateTime() # When the channel should be unmuted

    def mute(self):
        '''
        Sets the channel to be disabled for the backoff period
        '''
        self.muted = True
        self.muted_until = datetime.datetime.now() + datetime.timedelta(seconds=self.backoff)
        self.save()

    def unmute(self):
        '''
        Resets the channel to be unmuted
        '''
        self.muted = False
        self.muted_until = None
        self.save()

    def save(self, skip_update_by=False, **kwargs):
        '''
        Overrides the BaseDocument save() function and adds some checking on
        the channel_types
        '''

        if self.channel_type not in NOTIFICATION_CHANNEL_TYPES:
            raise ValueError('Invalid channel type')

        if not self.enabled:
            self.enabled = True

        super().save(skip_update_by=skip_update_by, **kwargs)


    def update(self, skip_update_by=False, **kwargs):
        '''
        Overrides the BaseDocument update() function and adds some checking on
        the channel_types
        '''

        if 'channel_type' in kwargs:
            if kwargs['channel_type'] not in NOTIFICATION_CHANNEL_TYPES:
                raise ValueError('Invalid channel type')
        elif self.channel_type not in NOTIFICATION_CHANNEL_TYPES:
            raise ValueError('Invalid channel type')

        if not self.enabled:
            self.enabled = True

        super().update(skip_update_by=skip_update_by, **kwargs)


    @classmethod
    def get_by_name(cls, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = cls.search()
        response = response.filter('term', name=name)
        
        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if response:
            response = response[0]
            return response
        return response


    @classmethod
    def get_by_organization(cls, organization):
        '''
        Fetches a document by the organization field
        '''
        response = cls.search()
        response = response.filter('term', organization=organization)
        response = list(response.scan())

        if len(response) > 0:
            return response
        return []


class Notification(base.BaseDocument):
    '''
    A Notification object tracks the actual notification, when it was sent
    if it failed for any reason, etc.
    '''

    class Index:  # pylint: disable=too-few-public-methods
        name = 'reflex-notifications'
        settings = {
            'refresh_interval': '1s'
        }

    sent = Boolean()  # Whether the notification was sent
    success = Boolean() # Whether the notification was sent successfully
    partial_success = Boolean() # Did the message send on only one of multiple channels
    time_sent = DateTime()  # The time the notification was sent
    error = Boolean()  # True if there was an error sending the notification
    error_message = Keyword()  # The error message if there was an error
    title = Keyword()
    message = Keyword()
    channel = Keyword()  # What channel was used to send the notification
    viewed = Boolean()  # Was the notification viewed (used by Reflex internal notifications)
    source_object_type = Keyword()
    source_object_uuid = Keyword()
    audience = Keyword() # The user this notification is intended for
    is_native = Boolean() # If this is a native notification don't allow it to be sent via channels
    use_org_smtp = Boolean() # If this is a native notification use the tenant SMTP server
    native_type = Keyword() # case, event, mention, etc.

    def send_failed(self, message):
        '''
        Sets the notification to failed and sets the error message
        '''
        self.error = True
        self.error_message = message
        self.sent = True
        self.time_sent = datetime.datetime.utcnow()
        self.save()

    def send_success(self):
        self.sent = True
        self.success = True
        self.time_sent = datetime.datetime.utcnow()
        self.save()


    @classmethod
    def get_by_organization(cls, organization):
        '''
        Fetches a document by the organization field
        '''
        response = cls.search()
        response = response.filter('term', organization=organization)
        response = list(response.scan())

        if len(response) > 0:
            return response
        return []

    
    def update(self, skip_update_by=False, **kwargs):
        '''
        Overrides the BaseDocument update() function and adds some checking on
        the source_item_type
        '''

        if self.source_object_type not in SOURCE_OBJECT_TYPE:
            raise ValueError('Invalid source object type')

        if self.is_native and self.native_type not in NATIVE_TYPES:
            raise ValueError('Invalid native type')

        if not self.sent:
            self.sent = False

        if not self.is_native:
            self.is_native = False

        if self.is_native:
            self.use_org_smtp = True

        super().update(skip_update_by=skip_update_by, **kwargs)


    def save(self, skip_update_by=False, **kwargs):
        '''
        Overrides the BaseDocument save() function and adds some checking on
        the source_item_type
        '''

        if self.source_object_type not in SOURCE_OBJECT_TYPE:
            raise ValueError('Invalid source object type')

        if self.is_native and self.native_type not in NATIVE_TYPES:
            raise ValueError('Invalid native type')

        if not self.sent:
            self.sent = False

        if not self.is_native:
            self.is_native = False

        if self.is_native:
            self.use_org_smtp = True

        super().save(skip_update_by=skip_update_by, **kwargs)
