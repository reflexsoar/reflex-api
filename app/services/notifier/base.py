# from ...api_v2.models import Notification, User

class Notifier(object):
    '''
    Notifier handles all sorts of notification activity
    Can send webhooks, emails, etc on behalf of the 
    Reflex system.
    Example: E-mail the user when a case is assigned to them
    '''

    def __init__(self, app):

        self.app = app

    def check_notifications(self):
        '''
        Checks the notification queue to see if there are any to send
        '''

        """
        s = Notification.search()
        s = s.filter('exists', field='closed')
        s = s.filter('match', closed=False)
        s = s[0:s.count()]
        notifications = s.execute()

        for notification in result:

            if action == 'email':
                # Send an email message
            elif action == 'webhook':
                # Send the webhook
            else:
                raise NotImplementedError
        """
        raise NotImplementedError

    def send_email(self, sender: str, users:list, subject: str, recipients: list = []):
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

    def send_webhook(self, url: str, message: str):
        '''
        Sends a message to a webhook destination
        '''
        raise NotImplementedError

