"""app/api_v2/model/notification.py

Contains all the logic for Notification interaction with the API
"""

import datetime
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
    'email', 'slack_webhook', 'pagerduty_webhook', 'teams_webhook', 'reflex', 'generic_webhook'
]


class PagerDutyWebhook(InnerDoc):
    '''
    A simple configuration for creating incidents via PagerDuty
    '''

    webhook_url = Keyword()  # The URL to send the PagerDuty webhook to
    message_template = Keyword()  # The message template to use when creating an incident


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
    pagerduty_configuration = Nested(PagerDutyWebhook)
    max_messages = Integer()  # The max number of notifications to send per minute
    # How long the notifier should back off on this channel if max_messages is exceeded
    backoff = Integer()

    def save(self, skip_update_by=False, **kwargs):
        '''
        Overrides the BaseDocument save() function and adds some checking on
        the channel_types
        '''

        if self.channel_type not in NOTIFICATION_CHANNEL_TYPES:
            raise ValueError('Invalid channel type')

        super().save(skip_update_by=skip_update_by, **kwargs)


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
    channel = Keyword()  # What channel was used to send the notification
    viewed = Boolean()  # Was the notification viewed (used by Reflex internal notifications)

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


