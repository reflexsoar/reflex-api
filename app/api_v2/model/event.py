import datetime
import hashlib
import json
from app.api_v2.model.exceptions import EventRuleFailure
from app.api_v2.model.notification import Notification
from app.api_v2.model.system import Observable
from app.api_v2.model.user import User
from app.api_v2.model.inout import Input

from app.api_v2.rql.parser import QueryParser
from . import case as c
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Float,
    Integer,
    Object,
    Date,
    system,
    utils,
    Nested,
    InnerDoc
)

from .utils import IndexedDict

class EventComment(base.BaseInnerDoc):
    '''
    A comment that can be applied to an Event
    '''
    
    comment = Keyword(fields={'text': Text()})


class EventStatus(base.BaseDocument):
    '''
    The status of an Event
    '''

    name = Keyword()
    description = Text(fields={'keyword':Keyword()})
    closed = Boolean()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-event-statuses'

    @classmethod
    def get_by_name(self, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search()
        
        response = response.filter('term', name=name)

        if organization:
            response = response.filter('term', organization=organization)
            
        response = response.execute()
        if response:
            status = response[0]
            return status
        return response


class EventView(base.BaseDocument):
    '''
    An EventView is a saved filter that can be used on the Event Queue page
    to quickly change between filters
    '''

    class Index:
        ''' Defines the index to use '''
        name = 'reflex-event-views'

    name = Keyword(fields={'text':Text()})
    shared = Boolean() # Is the filter public or private
    filter_string = Text() # The JSON string of the filter

    @classmethod
    def get_by_name(cls, name):
        '''
        Fetches a document by the name field
        '''
        response = cls.search()
        response = response.filter('term', name=name)
        response = response.execute()
        if response:
            view = response[0]
            return view
        return response


class EventObservable(InnerDoc):
    '''
    A list of observables associated with an Event
    '''
    tags = Keyword()
    data_type = Text(fields={'keyword':Keyword()})
    value = Text(fields={'keyword':Keyword()})
    spotted = Boolean()
    ioc = Boolean()
    safe = Boolean()
    tlp = Integer()
    source_field = Keyword() # The source field or alias being used
    original_source_field = Keyword() # The source field where the observable was extracted from

    def __hash__(self):
        return hash(tuple(self))


class EventMetrics(InnerDoc):
    '''
    Meta information about an event
    '''

    agent_uuid = Keyword()
    agent_pickup_time = Date()
    agent_bulk_start = Date()
    event_processing_dequeue = Date()
    event_processing_start = Date()
    event_processing_end = Date()
    event_bulked = Date()
    event_rule_start = Date()
    event_rule_end = Date()
    event_enrichment_start = Date()
    event_enrichment_end = Date()
    total_duration = Float()
    total_duration_with_agent = Float()
    auto_data_type_start = Date()
    auto_data_type_end = Date()
    threat_list_check_start = Date()
    threat_list_check_end = Date()
    threat_list_check_duration = Float()
    auto_data_type_duration = Float()
    event_processing_duration = Float()
    agent_duration = Float()
    enrichment_duration = Float()
    event_rule_duration = Float()
    auto_data_type_extraction = Boolean()
    first_touch = Date()
    total_abandons = Integer()
    total_touches = Integer()


class Event(base.BaseDocument):
    '''
    An event in reflex is anything sourced by an agent input that
    is actionable in the system by an analyst.
    '''

    uuid = Keyword()
    title = Keyword(fields={'text':Text()})
    description = Text(fields={'keyword':Keyword()})
    reference = Keyword()
    case = Keyword()
    source = Text(fields={'keyword':Keyword()})
    source_uuid = Keyword()
    tlp = Integer()
    severity = Integer()
    tags = Keyword()
    event_observables = Nested(EventObservable)
    status = Object()
    signature = Keyword()
    dismissed = Boolean()
    dismiss_reason = Text(fields={'keyword':Keyword()})
    dismiss_comment = Text(fields={'keyword': Keyword()})
    tuning_advice = Keyword(fields={'text':Text()}) # Used to supply tuning advice back to the customer
    dismissed_by = Object()
    dismissed_at = Date()
    dismissed_by_rule = Boolean()
    closed_at = Date()
    time_to_act = Float()
    time_to_close = Float()
    time_to_dismiss = Float()
    time_to_detection = Float()
    event_rules = Keyword()
    raw_log = Text()
    sla_breach_time = Date() # The time the SLA was breached
    sla_violated = Boolean() # Has the SLA been violated
    detection_id = Keyword() # The UUID of the Detection rule that generated this event
    risk_score = Integer() # The risk score if this originated from a detection rule
    original_date = Date() # The date the original log was generated (not when it was created in Reflex)
    comments = Nested()
    metrics = Object(EventMetrics)
    response_phase = Keyword() # The response phase that the event is in
    acknowledged = Boolean() # Has the event been acknowledged by an analyst
    acknowledged_by = Object() # The analyst that acknowledged the event
    integration_attributes = Object() # Attributes used by integrations
    integration_output = Object() # The output of the integration

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-events'
        settings = {
            'refresh_interval': '1s',
            'max_inner_result_window': 10000
        }

    @property
    def observables(self):
        '''
        Event observables
        '''
        if self.event_observables:
            return list(self.event_observables)
        else:
            return []

    @observables.setter
    def observables(self, value):
        '''
        Event observables
        '''
        self.event_observables = value
        self.save()

    def add_integration_attribute(self, key, value):
        '''
        Adds an integration attribute to the event, e.g.
        pagerduty.incident_id = 1234
        pagerduty.integration_config = 1234
        '''
        if not self.integration_attributes:
            self.integration_attributes = {}

        self.integration_attributes[key] = value
        self.save()

    def append_event_rule_uuid(self, uuid):
        '''
        Adds the UUID of an event rule to the event so that metrics and troubleshooting
        can be performed on the event
        '''
        if self.event_rules:
            self.event_rules.append(uuid)
        else:
            self.event_rules = [uuid]

    def add_comment(self, comment, skip_save=False):
        '''
        Adds a comment to the event
        '''
        if not self.comments:
            self.comments = [comment]
        else:
            self.comments.append(comment)

        if not skip_save:
            self.save()

    def remove_comment(self, uuid, skip_save=False):
        '''
        Removes a comment from the event
        '''

        if not self.comments:
            return

        for comment in self.comments:
            if comment['uuid'] == uuid:
                self.comments.remove(comment)
                break

        if not skip_save:
            self.save()

    def add_observable(self, content):
        '''
        Adds an observable to the event and also checks it
        against threatlists that are defined in the system
        '''

        added_observables = []
        for o in content:

            # FIX: Don't create observables with empty or placeholder values
            if o['value'] not in [None,'','-']:

                # Cast all the values to strings
                if not isinstance(o['value'], str):
                    o['value'] = str(o['value'])

                observable = system.Observable(**o, organization=self.organization)

                observable.add_event_uuid(self.uuid)
                observable.auto_data_type()
                observable.check_threat_list()

                observables_fields = ['uuid','data_type','value','tags','safe','tlp','spotted',
                                      'ioc','source_field','original_source_field']

                observable_dict = {key: getattr(observable, key) for key in observables_fields}
                if not self.event_observables:
                    self.event_observables = [observable_dict]
                else:
                    self.event_observables.append(observable_dict)

        self.save()

        return added_observables

    def set_open(self):
        '''
        Sets an event as open, this is a working state
        where the event is actively being worked by an
        analyst in a case
        '''
        self.status = EventStatus.get_by_name(name='Open')
        self.time_to_act = (datetime.datetime.utcnow() - self.created_at).seconds
        self.save()

    def set_new(self):
        '''
        Sets the event as new
        '''
        self.status = EventStatus.get_by_name(name='New')
        self.save()

    def set_dismissed(self, reason, by_rule=False, comment=None, advice=None):
        '''
        Sets the event as dismissed
        '''
        self.status = EventStatus.get_by_name(name='Dismissed')
        if comment:
            self.dismiss_comment = comment
        if advice:
            self.tuning_advice = advice
        self.dismiss_reason = reason.title
        self.dismissed_by = utils._current_user_id_or_none()
        self.dismissed_at = datetime.datetime.utcnow()
        self.time_to_dismiss = (self.dismissed_at - self.created_at).seconds
        self.dismissed_by_rule = by_rule
        self.save()

    def set_closed(self):
        '''
        Sets the event as closed
        '''
        self.status = EventStatus.get_by_name(name='Closed')
        self.closed_at = datetime.datetime.utcnow()
        self.time_to_close = (self.closed_at - self.created_at).seconds
        self.save()

    def set_case(self, uuid):
        '''
        Assigns a case to the event
        '''
        self.case = uuid
        self.save()

    def acknowledge(self, user):
        '''
        Acknowledges the event and sets the user that acknowledged it
        '''
        self.acknowledged = True
        self.acknowledged_by = user.username
        self.set_open()
        self.save()

    def unacknowledge(self):
        '''
        Unacknowledges the event
        '''
        self.acknowledged = False
        self.acknowledged_by = None

        # Set the initial value of total abandons if it doesn't exist
        if not hasattr(self, 'total_abandons'):
            self.total_abandons = 0

        self.total_abandons += 1
        self.set_new()
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
    def count_by_case(self, case, organization=None):
        '''
        Fetches the count of events by the case
        '''

        response = self.search()
        if organization:
            response = response.filter('term', organization=organization)
        response = response.filter('term', case=case).count()
        return response
    
    @classmethod
    def get_by_reference(self, reference, organization=None):
        '''
        Fetches an event by its source reference value
        '''
        response = self.search()

        if organization:
            response = response.filter('term', organization=organization)
        
        response = response.query('match', reference=reference).execute()
        if response:
            document = response[0]
            return document
        return response

    @classmethod
    def get_by_status(self, status):
        '''
        Fetches an event based on the string representation of it's status
        '''
        search = self.search()
        search = search.filter('term', **{"status.name__keyword": status})
        results = search.scan()
        return results
        

    @classmethod
    def get_by_signature(self, signature, all_events=False):
        '''
        Fetches an event by its calculated signature
        '''
        response = self.search()
        response = response.filter('match', signature=signature)
        if all_events:
            response = response[0:response.count()]
            response = response.scan()
        else:    
            response = response.execute()

        response = list(response)

        return response
        

    @classmethod
    def get_by_signature_and_status(self, signature, status, all_events=False):
        '''
        Fetches an event by its calculated signature and status
        '''
        response = self.search()
        if isinstance(signature, list):
            response = response.filter('terms', signature=signature)
        else:
            response = response.filter('match', signature=signature)
        response = response.filter('match', **{'status.name':status})
        if all_events:
            response = response[0:response.count()]
            
        response = list(response.scan())
        return response


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

    def as_indexed_dict(self):
        '''
        Returns the event as an IndexedDict object
        '''
        event_as_dict = self.to_dict()
        if 'event_observables' in event_as_dict:
            observables = event_as_dict.pop('event_observables')
            event_as_dict['observables'] = {}
            for i in range(0, len(observables)):
                event_as_dict['observables'][i] = observables[i]
        if 'raw_log' in event_as_dict:
            event_as_dict['raw_log'] = json.loads(event_as_dict['raw_log'])
        indexed_event = IndexedDict(event_as_dict)
        return indexed_event
    
    def remap_observables(self):
        ''' Attempts to extract observables again using an updated
        field template/field mapping
        '''
        if hasattr(self, 'input_uuid'):
            _input = Input.get_by_uuid(self.input_uuid)
            if _input:
                fields = _input.get_field_settings()
                print(fields)


class EventRule(base.BaseDocument):
    '''
    An Event Rule is created so that when new events come in they can
    be automatically handled based on how the analyst sees fit without the
    analyst actually having to do anything.
    '''

    name = Keyword()
    description = Text(fields={'keyword':Keyword()})
    event_signature = Keyword()  # The title of the event that this was created from
    rule_signature = Keyword()  # A hash of the title + user customized observable values
    target_case_uuid = Keyword() # The target case to merge this into if merge into case is selected
    merge_into_case = Boolean()
    create_new_case = Boolean() # If true, a new case will be created for the matching events
    set_organization = Boolean() # If true, the Event Rule will change the organization of the matching events
    target_organization = Keyword()
    case_template = Keyword() # The template to use when creating a new case
    query = Text(fields={'keyword':Keyword()}) # The RQL query to run against events
    deleted = Boolean() # A soft delete flag
    version = Integer() # A version tracking integer
    dismiss = Boolean()
    dismiss_reason = Text(fields={'keyword':Keyword()}) # The text description for why this was dismissed
    dismiss_comment = Text(fields={'keyword':Keyword()}) # A custom reason for why this was dismissed
    expire = Boolean()  # If not set the rule will never expire, Default: True
    expire_days = Integer() # The number of days before the rule expires
    expire_at = Date()  # Computed from the created_at date of the event + a timedelta in days
    active = Boolean()  # Users can override the alarm and disable it out-right
    add_tags = Boolean() # When the event rule matches should it add tags
    tags_to_add = Keyword() # What tags to add when add_tags is True
    remove_tags = Boolean() # When the event rule matches should it remove tags
    tags_to_remove = Keyword() # What tags to remove when remove_tags is True
    update_severity = Boolean() # When the event rule matches update the severity
    target_severity = Keyword() # What severity to use when update_severity is True
    mute_event = Boolean() # If True, any new events with a signature matching won't get into the system
    mute_period = Integer() # Hour many minutes to mute the event for
    mute_start_date = Date() # When did the mute period start
    hit_count = Integer() # How many times the event rule has triggered
    last_matched_date = Date() # When the rule last matched on an event
    order = Integer() # What order to process events in, 1 being first
    global_rule = Boolean() # Is it a global rule that should be processed on everything
    disable_reason = Keyword() # The reason why a rule was disabled (internally set by the system)
    priority = Integer() # The priority of the event rule, lower is more important
    notification_channels = Keyword() # The channels to send notifications to
    agent_uuid = Keyword() # The agent that created this event rule
    agent_type = Keyword() # The type of agent that created this event rule
    high_volume_rule = Boolean() # This flags true if the Event rule is too noisy
    tags = Keyword() # Descriptive tags for the event rule
    protected = Boolean() # If true, the event rule can only be modified by its creator
    integration_actions = Nested() # The integration actions to run when the event rule matches

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-event-rules'
        settings = {
            'refresh_interval': '1s'
        }
        version = "0.1.5"

    
    def create_notification(self, source_object_uuid, organization, source_object_type='event'):
        '''
        Creates a notification for the event rule
        '''
        if self.notification_channels and len(self.notification_channels) > 0:

            # TODO: Add a security check here to make sure only event rules that belong to the organization
            #       can create notifications on the organization.  A global channel just means it can
            #       be used to relay any organizations events, not that any organization can use it freely

            for channel in self.notification_channels:
                    
                notification = Notification(
                    sent=False,
                    channel=channel,
                    source_object_type=source_object_type,
                    source_object_uuid=source_object_uuid,
                    organization=organization
                )
                notification.save()

    def update_order(self, order):
        '''
        Updates the order in which this rule will be processed
        '''

        self.order = order
        self.save()

    
    def parse_rule(self):
        '''
        Parses the RQL query and converts it from a string to a 
        chain of comparisons to check the event
        '''
        qp = QueryParser(organization=self.organization)
        self.parsed_rule = qp.parser.parse(self.query)
    
    def expired(self):
        '''
        Checks to see if the rule has expired and disables it if it has expired
        return True if expired
        return False if not expired
        '''
        if hasattr(self, 'expire_at') and hasattr(self, 'expire'):
            if self.expire and self.expire_at < datetime.datetime.utcnow():
                self.active = False
                return True
        return False

    def check_rule(self, event):
        '''
        Checks an event against the rule to see if it matches
        '''
        
        qp = QueryParser(organization=self.organization)
        parse_start_time = datetime.datetime.utcnow()

        # Convert raw log back into a dictionary if the rule calls for checking against raw_log
        if 'raw_log' in event and isinstance(event['raw_log'], str) and 'raw_log' in self.query:
            event['raw_log'] = json.loads(event['raw_log'])

        results = list(qp.run_search(event, self.parsed_rule))
        parse_end_time = datetime.datetime.utcnow()

        # Convert raw log back into a string if the rule calls for checking against raw_log
        if 'raw_log' in event and isinstance(event['raw_log'], dict) and 'raw_log' in self.query:
            event['raw_log'] = json.dumps(event['raw_log'])

        # FUTURE: Warn on poor performing event rules if they parse slowly
        time_taken_seconds = (parse_end_time - parse_start_time).total_seconds()
        
        if len(results) > 0:
            self.last_matched_date = datetime.datetime.utcnow()
            return True

        return False
    
    def process_rql(self, event):
        '''
        Checks an event against an RQL query to see if it matches.  If an event 
        matches the rule, apply the rules conditions to the event
        '''

        print(f"DEBUG: Expire: {self.expire} - Expire At: {self.expire_at} - Active: {self.active}")
        if self.expire and self.expire_at < datetime.datetime.utcnow():
            
            self.active = False
            self.save()
        else:

            try:
                qp = QueryParser(organization=self.organization)

                if self.query:
                    
                    parsed_query = qp.parser.parse(self.query)
                else:
                    parsed_query = qp.parser.parse(self.query)

                results = list(qp.run_search(event, parsed_query))
                
                # Process the event
                if len(results) > 0:
                    self.last_matched_date = datetime.datetime.utcnow()
                    
                    return True
            except Exception as e:
                raise EventRuleFailure(e)
        return False


    def process_event(self, event) -> bool:
        """
        Process the event based on the settings in the rule
        """
        # Check if the should be expired, disable the rule if it expired
        
        event_acted_on = False

        # Dismiss the event
        if self.dismiss:
            reason = c.CloseReason.get_by_uuid(uuid=self.dismiss_reason)
            event.set_dismissed(reason=reason, by_rule=True)
            event_acted_on = True

        # Add the event to the case
        if self.merge_into_case:            
            case = c.Case.get_by_uuid(self.target_case_uuid)                                
            case.add_event(event)
            event_acted_on = True

        # Add tags to the event
        if self.add_tags:

            if self.tags_to_add:
                if event.tags is None:
                    event.tags = self.tags_to_add
                else:
                    [event.tags.append(t) for t in self.tags_to_add]

            event_acted_on = True
        
        # Update the severity of the Event Rule calls for it to be updated
        if self.update_severity:
            if isinstance(self.target_severity, int):
                event.severity = self.target_severity
            event_acted_on = True

        # Set a mute period for the Event and dismiss it
        if self.mute_event:

            # If this is the first time a matching event is being muted, set the mute_start_date
            if not self.mute_start_date:
                self.mute_start_date = datetime.datetime.utcnow()

            # If the mute period has not expired, dismiss the event
            if not (datetime.datetime.utcnow()-self.mute_start_date).seconds/60 > self.mute_period:
                event.set_dismissed(reason=reason, by_rule=True)
                event_acted_on = True

        # If the event was acted on by the signature, watermark the event
        if event_acted_on:
            event.append_event_rule_uuid(self.uuid)
        
        return event_acted_on

    @classmethod
    def get_by_name(self, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search()
        
        response = response.filter('term', name=name)
        if organization:
            response = response.filter('term', organization=organization)
            
        response = response.execute()
        if response:
            user = response[0]
            return user
        return response

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
    def get_all(self, organization=None):
        """
        Returns all the event rules
        """

        query = self.search()

        if organization:
            query = query.query('bool', should=[{'match': {'organization': organization}},{'match': {'global_rule': True}}])
        else:
            query = query.query('bool', should=[{'match': {'global_rule': True}}])

        query = query.filter('term', active=True)
        query = query.sort('global_rule','-created_at')

        query = query[0:query.count()]
        response = query.execute()
        if response:
            return list(response)

        return []
