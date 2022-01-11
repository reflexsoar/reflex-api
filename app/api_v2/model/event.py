import datetime
import hashlib
from fnmatch import fnmatch
from app.api_v2.model.exceptions import EventRuleFailure

from app.api_v2.rql.parser import QueryParser
from . import case as c
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Object,
    Date,
    system,
    utils
)

class EventStatus(base.BaseDocument):
    '''
    The status of an Event
    '''

    name = Keyword()
    description = Text()
    closed = Boolean()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-event-statuses'

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            status = response[0]
            return status
        return response


class Event(base.BaseDocument):
    '''
    An event in reflex is anything sourced by an agent input that
    is actionable in the system by an analyst.
    '''

    uuid = Keyword()
    title = Keyword()
    description = Text()
    reference = Keyword()
    case = Keyword()
    source = Text(fields={'keyword':Keyword()})
    source_uuid = Keyword()
    tlp = Integer()
    severity = Integer()
    tags = Keyword()
    #event_observables = Nested(Observable)
    status = Object()
    signature = Keyword()
    dismissed = Boolean()
    dismiss_reason = Text()
    dismiss_comment = Text()
    dismissed_by = Object()
    event_rules = Keyword()
    raw_log = Text()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-events'

    @property
    def observables(self):
        '''
        Event observables
        '''
        observables = system.Observable.get_by_event_uuid(self.uuid)
        return [r for r in observables]

    @observables.setter
    def observables(self, value):
        '''
        Event observables
        '''
        self.event_observables = value
        self.save

    def append_event_rule_uuid(self, uuid):
        '''
        Adds the UUID of an event rule to the event so that metrics and troubleshooting
        can be performed on the event
        '''
        if self.event_rules and isinstance(self.event_rules, list):
            self.event_rules += [uuid]
        else:
            self.event_rules = [uuid]
        self.save()

    def add_observable(self, content):
        '''
        Adds an observable to the event and also checks it
        against threatlists that are defined in the system
        '''

        added_observables = []
        for o in content:

            observable = system.Observable(**o)

            observable.add_event_uuid(self.uuid)
            observable.auto_data_type()
            observable.check_threat_list()
            observable.enrich()
            observable.save()
            added_observables.append(observable)

        return added_observables

    def set_open(self):
        '''
        Sets an event as open, this is a working state
        where the event is actively being worked by an
        analyst in a case
        '''
        self.status = EventStatus.get_by_name(name='Open')
        self.save()

    def set_new(self):
        '''
        Sets the event as new
        '''
        self.status = EventStatus.get_by_name(name='New')
        self.save()

    def set_dismissed(self, reason, comment=None):
        '''
        Sets the event as dismissed
        '''
        self.status = EventStatus.get_by_name(name='Dismissed')
        if comment:
            self.dismiss_comment = comment
            self.dismiss_reason = reason.title
            self.dismissed_by = utils._current_user_id_or_none()
        self.save()

    def set_closed(self):
        '''
        Sets the event as closed
        '''
        self.status = EventStatus.get_by_name(name='Closed')
        self.save()

    def set_case(self, uuid):
        '''
        Assigns a case to the event
        '''
        self.case = uuid
        self.save()

    def hash_event(self, data_types=['host', 'user', 'ip'], observables=[]):
        '''
        Generates an md5 signature of the event by combining the Events title
        and the observables attached to the event.  The Event signature is used
        for correlating multiple instances of an event
        '''

        _observables = []
        obs = []

        hasher = hashlib.md5()
        hasher.update(self.title.encode())

        for observable in observables:
            if observable.data_type in sorted(data_types):
                obs.append({'data_type': observable.data_type.lower(),
                            'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.signature = hasher.hexdigest()
        return

    def check_event_rule_signature(self, signature, observables=[]):
        '''
        Checks to see if the Event matches an event rules signature
        '''
        hasher = hashlib.md5()
        obs = []

        for observable in observables:
            obs.append({'data_type': observable.data_type.lower(),
                        'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        if signature == hasher.hexdigest():
            return True
        return False

    @classmethod
    def get_by_reference(self, reference):
        '''
        Fetches an event by its source reference value
        '''
        response = self.search().query('match', reference=reference).execute()
        if response:
            document = response[0]
            return document
        return response

    @classmethod
    def get_by_signature(self, signature, all_events=False):
        '''
        Fetches an event by its calculated signature
        '''
        response = self.search()
        response = response.filter('match', signature=signature)
        if all_events:
            response = response[0:response.count()]
            
        response = response.execute()
        if len(response) >= 1:
            return [d for d in response]
        else:
            return [response]

    @classmethod
    def get_by_signature_and_status(self, signature, status, all_events=False):
        '''
        Fetches an event by its calculated signature and status
        '''
        response = self.search()
        response = response.filter('match', signature=signature)
        response = response.filter('match', **{'status.name':status})
        if all_events:
            response = response[0:response.count()]
            
        response = response.execute()
        if len(response) >= 1:
            return list(response)
        else:
            return [response]

    @classmethod
    def get_by_case(self, case):
        """
        Returns any event that has a case uuid associated with it that
        matches the :case: variable
        """
        response = self.search().query('term', case=case).execute()
        if len(response) >= 1:
            return [d for d in response]
        else:
            return [response]

    @property
    def related_events_count(self):
        ''' 
        Returns an numeric representation of how many related events there 
        are with this event based on the given filter and the events 
        signature
        '''

        filters = []
        
        search = self.search()
        if self.signature:
            search = search.filter('term', **{'signature': self.signature})
        else:
            return 0
        if hasattr(self, 'related_event_filters'):
            filters = self.related_event_filters
            if len(filters) > 0:
                for _filter in filters:
                    search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})
        return search.count()


    def set_filters(self, filters=[], skip_related_events=False):
        '''
        Sets search filters that are used when calling related_events()
        '''

        if not hasattr(self, 'skip_related_events'):
            self.__dict__['skip_related_events'] = skip_related_events
        else:
            self.skip_related_events = skip_related_events

        if not hasattr(self, 'related_event_filters'):
            self.__dict__['related_event_filters'] = filters
        else:
            self.related_event_filters = filters


class EventRule(base.BaseDocument):
    '''
    An Event Rule is created so that when new events come in they can
    be automatically handled based on how the analyst sees fit without the
    analyst actually having to do anything.
    '''

    name = Keyword()
    description = Text()
    event_signature = Keyword()  # The title of the event that this was created from
    rule_signature = Keyword()  # A hash of the title + user customized observable values
    target_case_uuid = Keyword() # The target case to merge this into if merge into case is selected
    merge_into_case = Boolean()
    query = Text() # The RQL query to run against events
    dismiss = Boolean()
    expire = Boolean()  # If not set the rule will never expire, Default: True
    expire_at = Date()  # Computed from the created_at date of the event + a timedelta in days
    active = Boolean()  # Users can override the alarm and disable it out-right
    hit_count = Integer() # How many times the event rule has triggered
    last_matched_date = Date() # When the rule last matched on an event
    order = Integer() # What order to process events in, 1 being first

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-event-rules'


    @classmethod
    def update_order(self, order):
        '''
        Updates the order in which this rule will be processed
        '''

        self.order = order
        self.save()
    
    def process_rql(self, event):
        '''
        Checks an event against an RQL query to see if it matches.  If an event 
        matches the rule, apply the rules conditions to the event
        '''

        if self.expire and self.expire_at < datetime.datetime.utcnow():
            self.active = False
            self.save()
        else:

            try:
                qp = QueryParser()

                if self.query:
                    
                    parsed_query = qp.parser.parse(self.query)
                else:
                    parsed_query = qp.parser.parse(self.query)

                results = [r for r in qp.run_search(event, parsed_query)]
                
                # Process the event
                if len(results) > 0:
                    self.last_matched_date = datetime.datetime.utcnow()
                    self.save()
                    return True
            except Exception as e:
                raise EventRuleFailure(e)
        return False


    def process_event(self, event) -> bool:
        """
        Process the event based on the settings in the rule
        """
        # Check if the should be expired, disable the rule if it expired
        
        if self.hit_count:
            self.hit_count += 1
        else:
            self.hit_count = 1
        self.save()

        event_acted_on = False

        if self.dismiss:
            reason = c.CloseReason.get_by_name(title='Other')
            event.set_dismissed(reason=reason)
            event_acted_on = True

        if self.merge_into_case:

            # Add the event to the case
            case = c.Case.get_by_uuid(self.target_case_uuid)                                
            case.add_event(event)
            event_acted_on = True

        # If the event was acted on by the signature, watermark the event
        if event_acted_on:
            event.append_event_rule_uuid(self.uuid)
        
        return event_acted_on


    @classmethod
    def get_by_title(self, title):
        """
        Returns an event rule by its event_signature (event title)
        By default only returns active rules
        """

        query = self.search()
        query = query.filter('term', event_signature=title)

        response = query.execute()
        if len(response) >= 1:
            rule = [r for r in response if hasattr(r, 'active') and r.active]
        else:
            if hasattr(response, 'active') and response.active:
                rule = [response]
            else:
                rule = None

        return rule

    @classmethod
    def get_all(self):
        """
        Returns all the event rules
        """

        query = self.search()
        query = query[0:query.count()]
        response = query.execute()
        if response:
            return list(response)

        return []

class MutedEvents(base.BaseDocument):
    '''
    An Event Rule can be set to mute (dismiss) alarms for a certain period
    and then temporarily allow an event to come in after that period expires, resetting
    the clock and once again muting events
    '''

    event_rule = Keyword()
    last_event_processed = Date()
    event_uuid = Keyword()

    def mute_expired(self, time_interval: int):
        '''
        Returns if the timespan has expired between the current date
        and the last time an event was allowed in to the event queue
        
        Parameters:
            time_interval: int - The time in minutes to mute for
            
        Return:
            boolean
        '''
        now = datetime.datetime.utcnow()
        
        time_difference = (now - self.last_event_processed)
        minutes_since = time_difference.total_seconds/60
        return minutes_since > time_interval
