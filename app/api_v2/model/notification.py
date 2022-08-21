"""app/api_v2/model/notification.py

Contains all the logic for Notification interaction with the API
"""

from xmlrpc.client import DateTime
from . import (
    Keyword,
    Ip,
    Date,
    Boolean,
    Integer,
    Text,
    user,
    base,
    inout,
    InnerDoc,
    Nested
)


channel_types = [
    'email', 'slack_webhook', 'pagerduty_webhook', 'teams_webhook', 'reflex', 'generic_webhook'
]

class PagerDutyWebhook(base.BaseDocument):
    '''
    A simple configuration for creating incidents via PagerDuty
    '''

    webhook_url = Keyword() # The URL to send the PagerDuty webhook to
    message_template = Keyword() # The message template to use when creating an incident


class EmailNotification(base.BaseDocument):
    '''
    Stores the configuration for an e-mail based notification channel
    '''

    username = Keyword()
    password = Keyword()
    smtp_server = Keyword()
    smtp_port = Keyword()
    use_tls = Boolean()
    message_template = Keyword()

    def set_password(self, password):
        '''
        Encrypts the password for the Email
        '''
        raise NotImplementedError


class TeamsWebhook(base.BaseDocument):
    '''
    A simple configuration for a Teams notification channel
    '''

    webook_url = Keyword() # The URL to send the Teams webhook to
    message_template = Keyword() # The message template to use when creating a message


class SlackWebhook(base.BaseDocument):
    '''
    A simple configuration for a Slack notification channel
    '''

    webhook_url = Keyword() # The URL to send the Slack webhook to
    message_template = Keyword() # The message template to use when creating a message


class NotificationChannel(base.BaseDocument):

    '''
    A Notification Channel is a target destination for configured notifications.
    It can be anything from e-mail, to slack/teams, twitter, case management
    etc.
    '''

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-notification-channels'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword(fields={'Text': Text()})
    enabled = Boolean()
    description = Keyword(fields={'Text': Text()})
    channel_type = Keyword()
    configuration = Nested(dynamic=True)

    def save(self, skip_update_by=False, **kwargs):
        '''
        Overrides the BaseDocument save() function and adds some checking on
        the channel_types
        '''

        if self.channel_type not in channel_types:
            raise ValueError('Invalid channel type')

        super().save(skip_update_by=skip_update_by, **kwargs)


class Notification(base.BaseDocument):
    '''
    A Notification object tracks the actual notification, when it was sent
    if it failed for any reason, etc.
    '''

    class Index: # pylint: disable=too-few-public-methods
        name = 'reflex-notifications'
        settings = {
            'refresh_interval': '1s'
        }

    sent = Boolean() # Whether the notification was sent
    time_sent = DateTime() # The time the notification was sent
    error = Boolean() # True if there was an error sending the notification
    error_message = Keyword() # The error message if there was an error
    channel = Keyword() # What channel was used to send the notification