from datetime import datetime
from ...api_v2.model import Case, Settings, Event

class SLAMonitor(object):
    '''
    SLAMonitor checks open cases and tasks to see if
    the SLA has been missed and will trigger notifications
    if configured to do so, or mark the case as SLA missed
    '''

    def __init__(self, app):
        self.app = app

    def check_case_slas(self):
        raise NotImplementedError

    def check_event_slas(self):
        '''
        Queries the database for Events in a New status
        Checks the sla_breach_time on each event to see if it is in the past
        If in the past, the sla_violated flag will be set on the event
        '''

        now = datetime.datetime.utcnow()

        events = Event.get_by_status(status='New')
        print(events)
        raise NotImplementedError
    