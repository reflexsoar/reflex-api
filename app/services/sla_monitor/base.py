from ...api_v2.model import Case, Settings

class SLAMonitor(object):
    '''
    SLAMonitor checks open cases and tasks to see if
    the SLA has been missed and will trigger notifications
    if configured to do so, or mark the case as SLA missed
    '''

    def __init__(self, app):
        self.app = app

    def check_slas(self):
        raise NotImplementedError

    