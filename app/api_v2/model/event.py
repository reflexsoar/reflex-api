import datetime
import hashlib
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
    source = Text()
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

    def add_observable(self, content):
        '''
        Adds an observable to the event and also checks it
        against threatlists that are defined in the system
        '''

        added_observables = []
        for o in content:

            observable = system.Observable(**o)

            observable.add_event_uuid(self.uuid)
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

    def hash_event(self, data_types=['host', 'user', 'ip', 'string'], observables=[]):
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

    """
    @property
    def related_events(self):
        '''
        Returns a list of uuids for all related events that match the given
        filter
        '''

        filters = []
        skip_related_events = True
        search = self.search()
        search = search.filter('term', **{'signature': self.signature})

        if hasattr(self, 'related_event_filters'):
            filters = self.related_event_filters

        if hasattr(self, 'skip_related_events'):
            skip_related_events = self.skip_related_events

        if not skip_related_events:
            print(filters)
            if len(filters) > 0:
                for _filter in filters:
                    search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})
            search = search[0:search.count()]
            import json
            print(json.dumps(search.to_dict(), indent=2))
            results = search.execute()
            if len(results) >= 1:
                return [e.uuid for e in results if e.uuid != self.uuid]
        return []
    """



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
    # The target case to merge this into if merge into case is selected
    target_case_uuid = Keyword()
    #observables = Nested(Observable)
    merge_into_case = Boolean()
    dismiss = Boolean()
    expire = Boolean()  # If not set the rule will never expire, Default: True
    expire_at = Date()  # Computed from the created_at date of the event + a timedelta in days
    active = Boolean()  # Users can override the alarm and disable it out-right
    hit_count = Integer()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-event-rules'

    def add_observable(self, content):
        '''
        Adds an observable to the event and also checks it
        against threatlists that are defined in the system
        '''

        added_observables = []
        for _ in content:

            observable = system.Observable(**_)

            observable.set_rule(self.uuid)
            observable.save()
            added_observables.append(observable)

        return added_observables

    def hash_observables(self, observables: list):
        '''
        Creates an MD5 hash of all the observables on an event
        so that they can be compared to the events signature set
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
        self.rule_signature = hasher.hexdigest()
        self.save()

    def hash_target_observables(self, target_observables):
        '''
        Creates an MD5 hash of all the observables on an event
        so that they can be compared to the events signature set
        '''
        hasher = hashlib.md5()
        obs = []
        expected_observables = [{'data_type': obs.data_type.lower(
        ), 'value': obs.value.lower()} for obs in self.observables]
        for observable in target_observables:
            obs_dict = {'data_type': observable.data_type.name.lower(
            ), 'value': observable.value.lower()}
            if obs_dict in expected_observables:
                obs.append(obs_dict)
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        return hasher.hexdigest()

    def process(self, event) -> bool:
        """
        Process the event based on the settings in the rule
        """
        # Check if the should be expired, disable the rule if it expired
        if self.expire and self.expire_at < datetime.datetime.utcnow():
            self.active = False
            self.save()
            return False

        else:

            # Increment the hit count
            if self.hit_count:
                self.hit_count += 1
            else:
                self.hit_count = 1
            self.save()

            if self.dismiss:
                reason = c.CloseReason.get_by_name(title='Other')
                event.set_dismissed(reason=reason)
                return True
            elif self.merge_into_case:

                # Add the event to the case
                case = c.Case.get_by_uuid(self.target_case_uuid)                                
                case.add_event(event)
                return True

        return False


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
