"""app/api_v2/model/detection.py

Contains all the logic for the Detection engine
"""

import re
import json
from concurrent.futures import ThreadPoolExecutor
import math
import datetime
from pytz import timezone

from app.api_v2.model.utils import _current_user_id_or_none
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Long,
    Float,
    Date,
    Nested,
    system,
    Object,
    FieldMappingTemplate,
    AttrList,
    UpdateByQuery,
    Input,
    Agent,
    Organization,
    Q,
    bulk
)

from .inout import FieldMap


VALID_REPO_SHARE_MODES = ['private', 'local-shared',
                          'external-private', 'external-public']
VALID_REPO_TYPES = ['local', 'remote']
VALID_DETECTION_STATUS = ['Experimental', 'Draft', 'Superceded',
                          'Beta',
                          'Stable',
                          'Test',
                          'Deprecated',
                          'Production']


class MITRETacticTechnique(base.InnerDoc):
    '''
    A MITRE Tactic or Technique
    '''
    mitre_id = Keyword(fields={'text': Text()})
    external_id = Keyword(fields={'text': Text()})
    name = Keyword(fields={'text': Text()})
    shortname = Keyword(fields={'text': Text()})


class DetectionExceptionIntelList(base.BaseInnerDoc):

    name = Keyword(fields={'text': Text()})


class GlobalDetectionException(base.BaseDocument):
    '''
    Defines a global exclusion that can be used in any Detection Rule
    '''

    class Index:
        name = 'reflex-global-detection-exceptions'
        settings = {
            "refresh_interval": "1s"
        }

    description = Text()
    condition = Keyword()
    values = Keyword(fields={'text': Text()})
    field = Keyword()
    list = Nested(DetectionExceptionIntelList)


class DetectionException(base.BaseInnerDoc):
    '''
    A DetectionException tells a detection to filter out specific criteria
    '''

    description = Text()
    condition = Keyword()
    values = Keyword(fields={'text': Text()})
    field = Keyword()
    is_global = Boolean()
    rule_bound = Boolean()
    list = Nested(DetectionExceptionIntelList)


class IndicatorMatchConfig(base.InnerDoc):
    '''
    An indicator match rule compares the value of a field to a value contained 
    in an intel list
    '''
    intel_list = Object()
    key_field = Keyword()


class MetricChangeConfig(base.InnerDoc):
    '''
    The configuration for a Metric Changes
    '''

    avg_period = Integer()  # How far back to look to find average logs
    threshold = Integer()  # The threshold e.g. 10 which is 10 items or 10%
    threshold_format = Integer()  # 1 = Value, 2 = Percent
    increase = Boolean()  # True = increase, False = Decrease


class ThresholdConfig(base.InnerDoc):
    '''
    The configuration for ThresholdHold
    '''

    threshold = Integer()  # The number of items where the threshold is crossed
    operator = Keyword()  # The operator to use e.g. >, <, >=, <=, ==, !=
    dynamic = Boolean()  # True = dynamic, False = static
    key_field = Keyword()  # Optional key to count against (count of records in this field)
    discovery_period = Integer()  # How far back to look to find average logs
    recalculation_period = Integer()  # How often to recompute the dynamic threshold
    per_field = Boolean()  # True = per field, False = per item
    threshold_last_discovered = Date()  # The last time the threshold was discovered
    max_events = Integer()  # The number of events to return when a threshold is crossed


class NewTermsConfig(base.InnerDoc):
    '''
    The configuration for NewTerms
    '''

    key_field = Keyword()  # The field to pull terms from
    max_terms = Integer()  # How many terms to look for in the baseline period
    window_size = Integer()  # How far back to look for the initial set of terms


class FieldMismatchConfig(base.InnerDoc):
    '''
    A Field Mismatch rule will fire when two fields of an item returned by 
    the intial query do not match
    '''

    source_field = Keyword()
    target_field = Keyword()
    operator = Keyword()  # eq or ne


class QueryConfig(base.InnerDoc):
    '''
    '''

    language = Keyword()  # kql, lucene, spl, eql, qradar
    query = Keyword()


class SourceConfig(base.InnerDoc):
    '''
    '''

    language = Keyword()
    name = Keyword()
    uuid = Keyword()


class SourceMonitorConfig(base.InnerDoc):
    '''
    Defines settings for a SourceMonitor detection type
    '''
    data_sources = Keyword()
    source_lists = Nested()
    excluded_sources = Keyword()
    excluded_source_lists = Nested()
    autodiscover_data_streams = Boolean()
    ignore_data_streams_older_than_days = Integer() # If a data stream is older than this number of days ignore it
    delta_change = Boolean()  # True = delta change, False = absolute change
    delta_window = Integer()  # How far back to look for the delta
    operator = Keyword()  # The operator to use e.g. >, <, >=, <=, ==, !=
    threshold = Integer()  # The threshold e.g. 10 which is 10 items or 10%
    # True = threshold is a percent, False = threshold is a value
    threshold_as_percent = Boolean()


class RepositorySyncLog(base.BaseDocument):
    '''
    A log entry showing what happened during a repository sync
    '''

    repository_uuid = Keyword()  # the ID of the repository that was synced
    level = Keyword()  # info, error, warning
    detection_uuid = Keyword()  # the ID of the detection that was synced
    subscription = Keyword()  # The subscription that was synced
    message = Keyword(fields={'text': Text()})  # Any message related to the log
    status = Keyword()  # success, failure, warning

    class Index:
        name = "reflex-repository-sync-log"
        settings = {
            "refresh_interval": "1s"
        }


class DetectionLog(base.BaseDocument):
    '''
    A log entry for the detection for troubleshooting and history tracking
    '''

    detection_uuid = Keyword()  # the ID of the detection create the log entry
    level = Keyword()  # info, error, warning
    hits = Long()  # How many hits this detection matched on this run
    time_taken = Integer()  # How long this run took
    start_time = Date()  # When the run started
    end_time = Date()  # When the run finished
    # Any message related to the log
    message = Keyword(fields={'text': Text()})

    class Index:
        name = "reflex-detections-log"
        settings = {
            "refresh_interval": "1s"
        }


class DetectionSchedulHourRange(base.InnerDoc):
    '''
    A range of hours for a day
    '''
    start = Integer()
    end = Integer()


class DetectionScheduleDay(base.InnerDoc):
    '''
    A day of the week with a list of hours
    '''
    custom = Boolean()
    hours = Nested(DetectionSchedulHourRange)


class DetectionSchedule(base.InnerDoc):
    '''Defines what days and the hours of the day a detection should run'''
    monday = Object(DetectionScheduleDay)
    tuesday = Object(DetectionScheduleDay)
    wednesday = Object(DetectionScheduleDay)
    thursday = Object(DetectionScheduleDay)
    friday = Object(DetectionScheduleDay)
    saturday = Object(DetectionScheduleDay)
    sunday = Object(DetectionScheduleDay)


class AgentDetectionState(base.InnerDoc):
    '''
    Contains details about the agent
    '''

    agent = Keyword()
    detections = Keyword()
    assessments = Keyword()


class DetectionState(base.BaseDocument):
    '''
    A state tracking table for detections.  Determines what work each 
    detection agent should perform.  Is updated periodically by the detection
    workload scheduler.  When the DetectionState table has a status of 'PROCESSING'
    no detections are available to agents. When the status is 'BALANCED' detections
    are available to agents.
    '''

    status = Keyword()  # PROCESSING, BALANCED
    last_updated = Date()  # The last time the status was updated
    agents = Nested(AgentDetectionState)  # The agents assigned to detections

    class Index:
        name = "reflex-detections-state"
        settings = {
            "refresh_interval": "1s"
        }

    def _agent_has_work(self, agent_uuid):
        '''
        Returns true if the agent_uuid has any work assigned to it
        '''

        agent = next(
            (agent for agent in self.agents if agent.agent == agent_uuid), None)

        if agent is None:
            return False

        if not agent.detections or len(agent.detections) == 0:
            return False

        return True
    
    def _agent_has_assessments(self, agent_uuid):
        '''
        Returns true if the agent_uuid has any assessments assigned to it
        '''

        agent = next(
            (agent for agent in self.agents if agent.agent == agent_uuid), None)
        
        if agent is None:
            return False
        
        if not agent.assessments or len(agent.assessments) == 0:
            return False
        
        return True

    def _detection_assigned(self, detection_uuid):
        '''
        Returns true if the detection_uuid is assigned to any agent
        '''
        for agent in self.agents:
            if agent.detections and detection_uuid in agent.detections:
                return True

        return False

    def _needs_rebalance(self, detections, agents):
        '''
        Returns True if certain conditions are met
        '''

        rebalance = False

        # If a rule has been enabled since the last rebalance
        # detections = Detection.get_by_organization(self.organization)
        for detection in detections:

            # If the detection is enabled and not assigned to an agent
            if detection.active and not self._detection_assigned(detection.uuid):
                rebalance = True
                break

            if not detection.active and self._detection_assigned(detection.uuid):
                rebalance = True
                break

        active_rules = True if len(
            [detection for detection in detections if detection.active]) > 0 else False

        rules_needing_assessment = True if len(
            [detection for detection in detections if detection.assess_rule]) > 0 else False

        # Filter agents down to those that are detection agents
        # agents = Agent.get_by_organization(self.organization)

        # If an agent currently has assignments or detections but is not
        # a detection agent
        for agent in agents:
            if self._agent_has_work(agent.uuid) and 'detector' not in agent.merged_roles:
                rebalance = True
                break

        agents = [agent for agent in agents if 'detector' in agent.merged_roles]

        for agent in agents:

            # If an agent is unhealthy and has work assigned to it
            if not agent.healthy and self._agent_has_work(agent.uuid):
                rebalance = True
                break

            # If an agent is unhealthy and has assessments assigned to it
            if not agent.healthy and self._agent_has_assessments(agent.uuid):
                rebalance = True
                break

            # If an agent is healthy and has no work assigned to it
            if agent.healthy and not self._agent_has_work(agent.uuid) and active_rules:
                rebalance = True
                break

            # If an agent is healthy and has no assessments assigned to it
            if agent.healthy and not self._agent_has_assessments(agent.uuid) and rules_needing_assessment:
                rebalance = True
                break

        agent_inventory = [a.uuid for a in Agent.get_by_organization(self.organization)]
        # If the agent no longer exists
        for agent in self.agents:
            if agent.agent not in agent_inventory:
                rebalance = True
                break

        return rebalance

    @classmethod
    def _init_state(cls, organization: str):
        '''
        Initializes the state table
        '''

        state = cls(organization=organization,
                    status='BALANCED',
                    last_updated=None)
        state.save(refresh=True)
        return state

    @classmethod
    def get_by_organization(cls, organization: str):
        '''
        Returns the state for the organization
        '''

        state = cls.search().filter('term', organization=organization).execute()
        if state and len(state) > 0:
            return state[0]

        return None
    
    def get_agent_assessments(self, agent_uuid: str):
        '''
        Returns the assessment UUIDs assigned to the agent
        '''
        if self.agents and len(self.agents) > 0:

            agent = next(
                (agent for agent in self.agents if agent.agent == agent_uuid), None)

            if agent:
                return agent.assessments

        return []

    def get_agent_detections(self, agent_uuid: str):
        '''
        Returns the detection UUIDs assigned to the agent
        '''
        if self.agents and len(self.agents) > 0:

            agent = next(
                (agent for agent in self.agents if agent.agent == agent_uuid), None)

            if agent:
                return agent.detections

        return []

    @classmethod
    def check_state(cls):
        '''
        Checks the state for each organization in the system
        '''

        organizations = [org.uuid for org in Organization.search().scan()]

        for organization in organizations:

            state = cls.search().filter('term', organization=organization).execute()

            if len(state) > 0:
                state = state[0]

            if not state:
                state = cls._init_state(organization)

            # Retrieve all detections
            detections = Detection.get_by_organization(state.organization)

            # Retrieve all agents
            agents = Agent.get_by_organization(state.organization)

            if state._needs_rebalance(detections=detections, agents=agents):

                state.rebalance_detections(detections=detections, agents=agents)

            state.assign_assessments(detections, agents)

    def assign_assessments(self, detections, agents):
        '''
        Distributes any rules that are currently flagged as assess_rule equally
        across all agents
        '''

        if detections:
            assessments = [d.uuid for d in detections if d.assess_rule]

            if len(agents) > 0 and len(assessments) > 0:

                # Split the detections up into chunks based on the number of agents
                chunk_size = math.ceil(len(assessments) / len(agents))

                for i, agent in enumerate(agents):
                    for a in self.agents:
                        if a.agent == agent.uuid:
                            a.assessments = assessments[i*chunk_size:(i+1)*chunk_size]
                
                self.save()

    def rebalance_detections(self, detections, agents, force=False):
        '''
        Redistributes the detection workload to agents
        '''

        # Do not rebalance if the status is PROCESSING, a rebalance is already in progress
        if self.status == 'PROCESSING' and not force:
            return

        if detections:

            # Filter down to active detections
            detections = [d for d in detections if d.active]

            # Set the status to PROCESSING
            self.status = 'PROCESSING'
            self.save(refresh="wait_for")

            # Retrieve all the agents
            agents = Agent.get_by_organization(self.organization)

            # Filter agents down to healthy detection agents
            agents = [
                agent for agent in agents if 'detector' in agent.merged_roles and agent.healthy]

            _agents = []

            if len(agents) > 0:

                # Split the detections up into chunks based on the number of agents
                chunk_size = math.ceil(len(detections) / len(agents))

                # Split up the detections evenly across the agents
                for i, agent in enumerate(agents):
                    _agents.append({
                        'agent': agent.uuid,
                        'detections': [detection.uuid for detection in detections[i * chunk_size:(i + 1) * chunk_size]]
                    })

            # Update the state table
            self.agents = _agents
        self.last_updated = datetime.datetime.utcnow()
        self.status = 'BALANCED'
        self.save(refresh="wait_for")


class Detection(base.BaseDocument):
    '''
    A Detection is a rule defined by a security team to look for suspicious or malicious
    activity in a source of data
    '''

    name = Keyword(fields={'text': Text()})
    # The UUID of the original detection this detection was created from
    original_uuid = Keyword()
    from_repo_sync = Boolean()  # Tells you if the rule was created from a repo sync
    repository = Keyword()  # The UUID of the repository this rule was created from
    query = Object(QueryConfig)  # The query to run against the log source
    # A persistent UUID that follows the rule and is associated to events
    detection_id = Keyword()
    from_sigma = Boolean()  # Tells you if the rule was converted from a Sigma rule
    sigma_rule = Keyword(fields={'text': Text()})  # The raw sigma rule
    sigma_rule_id = Keyword()  # The ID of the Sigma rule
    description = Text()
    guide = Text()  # A descriptive process for how to triage/investigate this detection
    setup_guide = Text()  # A guide for how to setup this detection
    testing_guide = Text()  # A guide for how to test this detection
    email_template = Text()  # A template for the email notification
    test_script = Text()  # A script to test the detection
    test_script_language = Keyword()  # Is the script safe to run?
    test_script_safe = Boolean()  # Is the script safe to run?
    tags = Keyword()  # A list of tags used to categorize this repository
    tactics = Nested(MITRETacticTechnique)  # T1085.1
    techniques = Nested(MITRETacticTechnique)  # T1085
    # A list of URLs that detail in greater depth why this detection exists
    references = Keyword()
    false_positives = Keyword()  # A list of false positives
    kill_chain_phase = Keyword()  # Singular text based phase definition
    rule_type = Integer()  # 0 - Match 1 - Frequency 2 - Metric
    version = Integer()  # Version number
    active = Boolean()  # Is the rule active or disabled
    # A list of warnings for this alert e.g. slow, volume, field_missing, import_fail
    warnings = Keyword()
    # The UUID of the input/source this detection should run against
    source = Object(SourceConfig)
    # The UUID of the case_template to apply when an alert created by this detection is ultimately turned in to a case
    case_template = Keyword()
    risk_score = Integer()  # 0 - 100
    severity = Integer()  # 1-4 (1: Low, 2: Medium, 3: High, 4: Critical)
    # Calculate a unique signature for this rule based on fields on the source event
    signature_fields = Keyword()
    field_templates = Keyword()  # A list of field templates to apply to the alert
    # Configures which fields should show up as observables in the alert
    observable_fields = Nested(FieldMap)
    time_taken = Integer()  # How long the rule took to run in milliseconds
    query_time_taken = Long()  # How long the query took to run in milliseconds
    interval = Integer()  # How often should the rule run in minutes
    lookbehind = Integer()  # How far back should the rule look when it runs
    # How far back in minutes the rule should hunt for missed detections if a rule run is missed
    catchup_period = Integer()
    # Skip Event Rules when this detection generates an Event
    skip_event_rules = Boolean()
    run_start = Date()  # When the run started
    run_finished = Date()  # When the run finished
    next_run = Date()  # When the rule should run again
    last_run = Date()  # When was the last time the rule was run
    last_hit = Date()  # The last time this rule matched anything
    total_hits = Long()
    exceptions = Nested(DetectionException)  # InnerDoc
    # How long to prevent the detection from refiring in minutes. If 0 send all
    mute_period = Integer()
    threshold_config = Object(ThresholdConfig)
    metric_change_config = Object(MetricChangeConfig)
    field_mismatch_config = Object(FieldMismatchConfig)
    new_terms_config = Object(NewTermsConfig)
    indicator_match_config = Object(IndicatorMatchConfig)
    source_monitor_config = Object(SourceMonitorConfig)
    assigned_agent = Keyword()  # The UUID of the agent that should run this alarm
    # If true the detection will include the meta data from the source event in the alert
    include_source_meta_data = Boolean()
    status = Keyword()  # Experimental, Beta, Stable, Test, Deprecated, Production
    repository = Keyword()  # The UUID of the repositories this rule is associated to
    daily_schedule = Boolean()  # If false the detection will always run
    schedule = Nested(DetectionSchedule)
    schedule_timezone = Keyword()  # The timezone offset in hours
    assess_rule = Boolean()  # If true the rule will be assessed for quality
    last_assessed = Date()  # When the rule was last assessed
    average_query_time = Long()  # The average query time in milliseconds
    hits_over_time = Keyword()  # A JSON string of the hits over time
    average_hits_per_day = Integer()  # The average hits per day
    is_hunting_rule = Boolean()  # If true the rule is a hunting rule
    # The maximum number of events to create per run
    suppression_max_events = Integer()
    required_fields = Keyword()  # A list of fields that must be present on the source event
    author = Keyword() # A list of authors
    field_metrics = Object(enabled=False) # A list of field metrics
    field_settings = Object(properties={
        'fields': Nested(FieldMap),
        'signature_fields': Keyword(),
        'tag_fields': Keyword(),
    })

    class Index:
        name = "reflex-detections"
        settings = {
            "refresh_interval": "1s"
        }
        version = '0.1.6'

    def save(self, **kwargs):
        ''' Override save to set some defaults '''
        if not self.from_repo_sync:
            self.from_repo_sync = False

        if not self.status:
            self.status = 'Draft'

        if not self.daily_schedule:
            self.daily_schedule = False

        if not self.schedule:
            self.schedule = {
                'monday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                },
                'tuesday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                },
                'wednesday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                },
                'thursday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                },
                'friday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                },
                'saturday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                },
                'sunday': {
                    'custom': False,
                    'hours': [{
                        'from': '00:00',
                        'to': '23:59'
                    }]
                }

            }

        super(Detection, self).save(**kwargs)

    def should_run(self, catchup_period=1440):
        '''
        Determines if the last_run + the interval is greater than now
        '''

        schedule_allows = False

        if hasattr(self, 'schedule'):
            # Adjust for the timezone if it is set
            if hasattr(self, 'schedule_timezone') and self.schedule_timezone is not None:
                now = datetime.datetime.now(timezone(self.schedule_timezone))
            else:
                now = datetime.datetime.utcnow()
                
            for day_of_week in self.schedule:
                day_config = self.schedule[day_of_week]
                if 'active' in day_config and day_config['active']:
                    if day_of_week == now.strftime("%A").lower():

                        # For each define from to in hours check if the 
                        # current hours and minutes is within the range
                        for time_range in day_config['hours']:
                            
                            # Get the current hours and minutes in 24 hour format
                            now_time = f"{now.hour:02d}{now.minute:02d}"
                            now_time = int(now_time)

                            # Get the from and to hours and minutes in 24 hour format
                            from_time = int(time_range["from"].replace(":", ""))
                            to_time = int(time_range["to"].replace(":", ""))

                            # If the current time is within the range, allow the run
                            if now_time >= from_time and now_time <= to_time:
                                schedule_allows = True
                                break
                else:
                    schedule_allows = True
                    break

        # If the schedule doesn't allow us to run, return False
        if not schedule_allows:
            return False

        if hasattr(self, 'last_run'):

            # Convert the last_run ISO8601 UTC timestamp back to a datetime object
            last_run = self.last_run

            # Determine the next time the rule should run
            next_run = last_run + datetime.timedelta(minutes=self.interval)
            next_run = next_run.replace(tzinfo=None)

            # Determine the current time in UTC
            current_time = datetime.datetime.utcnow()

            # Compute the mute period based on the last_hit property
            if hasattr(self, 'mute_period') and self.mute_period != None and self.mute_period > 0 and hasattr(self, 'last_hit') and self.last_hit:
                last_hit = self.last_hit
                mute_time = last_hit + \
                    datetime.timedelta(seconds=self.mute_period*60)
                mute_time = mute_time.replace(tzinfo=None)
            else:
                mute_time = current_time

            # If the current_time is greater than the when the detection rule should run again
            if current_time > next_run and current_time >= mute_time:
                return True
            
        return False

    def extract_fields_from_query(self, query=None):
        '''
        Extracts the fields from a query and returns them as a list. Fields
        are expected to be written like field_name: value or field_name:value
        or field_name : value
        '''
        fields = []
        pattern = r'\b([\w\.]+):'

        pattern = re.compile(pattern)

        if not query:
            query = self.query.query
        
        matches = pattern.findall(query)
        if matches:
            fields = [m for m in matches]

        fields = list(set(fields))

        EXCLUDED_FIELDS = ['_exists_']

        self.required_fields = [f.lstrip("-") for f in fields if f not in EXCLUDED_FIELDS and len(f) > 1]
            
        return fields
    
    @classmethod
    def get_by_detection_id(cls, detection_id, repository=None, organization=None):
        '''
        Fetches a document by the detection_id field  which is a persistent UUID
        that follows the rule across any installation of the API
        '''
        response = cls.search(skip_org_check=True)

        if isinstance(detection_id, AttrList):
            detection_id = [d for d in detection_id]

        if isinstance(detection_id, list):
            response = response.filter('terms', detection_id=detection_id)
        else:
            response = response.filter('term', detection_id=detection_id)

        if repository:
            response = response.filter('term', repository=repository)

        if organization:
            response = response.filter('term', organization=organization)

        response = [r for r in response.scan()]
        return response

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
    def get_by_organization(cls, organization, active=None):
        '''
        Fetches a document by the organization field
        '''
        response = cls.search()
        response = response.filter('term', organization=organization)

        if active in [True, False]:
            response = response.filter('term', active=active)

        response = list(response.scan())

        if len(response) > 0:
            return response
        return []
    
    def update_field_settings(self):
        '''
        Updates the field settings for this detection
        '''
        self.field_settings = self.final_fields

    @classmethod
    def bulk_update_field_settings(cls, field_template: str):
        '''
        Updates the field settings for a list of detections
        '''

        detections = [d for d in cls.search().filter('term', field_templates=field_template).scan()]

        for detection in detections:
            detection.update_field_settings()

        cls.bulk(detections)

    @classmethod
    def bulk(cls, items: list):
        '''
        Bulk adds application inventory data
        '''

        _items = []
        for item in items:
            if isinstance(item, dict):
                _items.append(cls(**item).to_dict(True))
            else:
                _items.append(item.to_dict(True))

        bulk(cls._get_connection(), (i for i in _items))
    
    @property
    def final_fields(self):

        if hasattr(self, 'ignore_final_fields') and self.ignore_final_fields:
            return {}
        
        final_fields = self.get_field_settings()

        source_input = None

        final_fields = []
        observable_fields = []
        signature_fields = []
        tag_fields = []

        # If the detection specifies its own signature fields, use those as a base
        if self.signature_fields:
            signature_fields = self.signature_fields

        # If the final_fields has any signature_fields, add them to the signature_fields list
        # then deduplicate the list and sort it alphabetically
        if any('signature_field' in field and field['signature_field'] is True for field in final_fields):
            signature_fields.extend([field['field'] for field in final_fields if 'signature_field' in field and field['signature_field'] is True])

        # Sort the signature fields alphabetically
        signature_fields = sorted(signature_fields)

        # Determine which fields are tag fields
        tag_fields.extend([field['field'] for field in final_fields if 'tag_field' in field and field['tag_field'] is True])

        # Include only fields that are marked as observable fields
        """ DEPRECATION WARNING: The inclusion of fields missing the observable_field flag will
            be removed in a future release.  We maintain backwards compatibility for now but
            this will be removed in a future release. """
        observable_fields = [field for field in final_fields if ('observable_field' in field and field['observable_field'] is True) or 'observable_field' not in field]

        # If the detection rule has no field settings or signature fields
        # or tag fields, fetch the settings from the source input            
        if not observable_fields or not signature_fields or not tag_fields:
            source_input = Input.get_by_uuid(self.source.uuid)

            _input_fields = source_input.get_field_settings()

            # If no final_fields were determined, default to the source input field mapping
            if not observable_fields:
                observable_fields = _input_fields

            # If no signature fields were determined, default to the source input signature fields
            if not signature_fields:
                if hasattr(source_input.config, 'signature_fields'):
                    signature_fields = [field['field'] for field in _input_fields if 'signature_field' in field and field['signature_field'] is True]
                else:
                    signature_fields = []

            # If no tag_fields were determined, default to the source input tag fields
            if not tag_fields:
                # Get any tag fields from the input
                if hasattr(source_input.config, 'tag_fields'):
                    tag_fields.extend([field['field'] for field in _input_fields if 'tag_field' in field and field['tag_field'] is True])
                else:
                    tag_fields = []

        response = {
            "fields": observable_fields,
            "signature_fields": signature_fields,
            "tag_fields": tag_fields
        }
        return response
    

    def get_field_settings(self):
        '''Provides a list of field settings for this detection'''

        final_fields = []
        # If the detection is using templates, merge the fields from all the
        # templates into a single list.  Templates with a higher priority will
        # override templates with a lower priority in the event of a field name
        # collision
        if self.field_templates:
            templates = FieldMappingTemplate.search(skip_org_check=True)

            # The templates assigned to this detection but only if they belong to the same org
            # or are flagged as global
            templates = templates.filter(
                'bool',
                should=[
                    Q('bool', must=[Q('term', is_global=True), Q('terms', uuid=self.field_templates)]),
                    Q('bool', must=[Q('term', organization=self.organization), Q('terms', uuid=self.field_templates)])
                ]
            )

            templates = [t for t in templates.scan()]

            templates.sort(key=lambda x: x.priority, reverse=True)
            for template in templates:
                for template_field in template.field_mapping:
                    replaced = False
                    for field in final_fields:
                        if field['field'] == template_field['field']:
                            # If the field is currently a signature field make sure it stays that way
                            if 'signature_field' in field and field['signature_field'] is True:
                                template_field['signature_field'] = True

                            final_fields[final_fields.index(
                                field)] = template_field
                            
                            replaced = True
                            break

                    if not replaced:
                        final_fields.append(template_field)

        # Add additional field settings from the detection rule, these will override
        # any field settings from the templates in the event of a field name collision
        if self.observable_fields:
            for detection_field in self.observable_fields:
                replaced = False
                for field in final_fields:
                    if field['field'] == detection_field['field']:
                        final_fields[final_fields.index(
                            field)] = detection_field
                        replaced = True
                        break

                if not replaced:
                    final_fields.append(detection_field)

        return final_fields

    @classmethod
    def create_from_json(cls, data, preserve_uuid=False, preserve_organization=False, from_repo=False, repository_uuid=None):
        ''' Creates a detection from a json object '''

        current_user = _current_user_id_or_none()

        if isinstance(data, str):
            data = json.loads(data)

        # Don't preserve the UUID by default
        if not preserve_uuid:
            data.pop('uuid', None)

        # Don't preserve the organization by default
        if not preserve_organization:
            data['organization'] = current_user['organization']

        # If the detection is being created from a repository, set the from_repo_sync flag and
        # set the repository UUID
        if from_repo:
            if not repository_uuid:
                raise ValueError(
                    "Repository ID is required when creating a detection from a repository")
            
            data['from_repo_sync'] = True
            data['repository'] = repository_uuid

        # If preserving the UUID the detection should be updated instead of created
        if preserve_uuid:
            detection = cls.get_by_uuid(data['uuid'])
            if detection:
                detection.update(**data)
                return detection
            else:
                raise ValueError(
                    "Detection with UUID {} does not exist".format(data['uuid']))

        existing_name = cls.get_by_name(
            data['name'], organization=data['organization'])
        if existing_name:
            data['name'] = f"[IMPORTED] - {data['name']}"

        detection = cls(**data)
        detection.last_run = datetime.datetime.utcnow()
        detection.save()
        return detection


class DetectionPerformanceMetric(base.BaseDocument):
    '''
    Used to show Detection performance over time
    '''

    detection_id = Keyword()  # The detection ID for this metric
    rule_type = Integer()  # The rule type
    query_time = Integer()  # How long the query took

    class Index:
        name = "reflex-detections-perf-metrics"
        settings = {
            "refresh_interval": "1s"
        }


class DetectionRepositoryToken(base.BaseDocument):
    '''
    An access token is generated for external parties to subscribe to a detection repository
    '''

    repository = Keyword()  # The UUID of the repository this token belongs to
    ip_addresses = Keyword()  # The IP addresses allowed to use this token
    last_used = Date()  # The last time the token was used

    class Index:
        name = 'reflex-detection-access-tokens'
        settings = {
            "refresh_interval": "1s"
        }

    def validate(self):
        '''
        Validates the token to ensure it is still valid
        '''
        raise NotImplementedError

    def revoke(self):
        '''
        Revoke the token as it is no longer needed or has been abused
        '''
        raise NotImplementedError

    @classmethod
    def generate(cls):
        '''
        Generates a new access token for a given repository
        '''
        raise NotImplementedError


class DetectionRepositorySubscriptionSyncSettings(base.InnerDoc):
    '''
    Configures what fields to synchronize when syncing a repository
    '''
    risk_score = Boolean()
    severity = Boolean()
    interval = Boolean()
    lookbehind = Boolean()
    mute_period = Boolean()
    threshold_config = Boolean()
    metric_change_config = Boolean()
    field_mismatch_config = Boolean()
    new_terms_config = Boolean()
    field_templates = Boolean()
    signature_fields = Boolean()
    observable_fields = Boolean()
    guide = Boolean()
    setup_guide = Boolean()
    testing_guide = Boolean()
    false_positives = Boolean()


class DetectionRepositorySubscription(base.BaseDocument):
    '''
    A subscription is created when clicking enable on an internal-shared repository or adding
    an external-private or external-public repository
    '''

    repository = Keyword()  # The UUID of the repository this subscription belongs to
    # Whether or not the repository is currently being synchronized
    synchronizing = Boolean()
    sync_interval = Integer()  # The sync interval for this subscription, in minutes
    last_sync = Date()  # The last time this repository was synced
    next_sync = Date()  # The next time this repository will be synced
    last_sync_status = Keyword()  # The status of the last sync
    active = Boolean()  # Whether or not this subscription is active
    # The sync settings for this subscription
    sync_settings = Object(DetectionRepositorySubscriptionSyncSettings)
    # The UUID of the default input for any detections created from this
    # repository subscription
    default_input = Keyword()
    default_field_template = Keyword()  # The UUID of the default field template

    class Index:
        name = "reflex-detection-repository-subscriptions"
        settings = {
            "refresh_interval": "1s"
        }

    @classmethod
    def get_by_repository(cls, repository, organization=None):
        '''
        Fetches a document by the repository field
        '''
        response = cls.search()
        response = response.filter('term', repository=repository)

        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()

        if len(response) > 0:
            return response[0]
        return []

    def set_default_sync_settings(self):
        '''Sets the default sync settings on the subscription'''
        self.sync_settings.risk_score = True
        self.sync_settings.severity = True
        self.sync_settings.interval = True
        self.sync_settings.lookbehind = True
        self.sync_settings.mute_period = True
        self.sync_settings.threshold_config = True
        self.sync_settings.metric_change_config = True
        self.sync_settings.field_mismatch_config = True
        self.sync_settings.new_terms_config = True
        self.sync_settings.field_templates = True
        self.sync_settings.signature_fields = True
        self.sync_settings.observable_fields = True
        self.sync_settings.guide = True
        self.sync_settings.setup_guide = True
        self.sync_settings.testing_guide = True
        self.sync_settings.false_positives = True

    def should_sync(self):
        '''
        Determines if it is time to sync the repository based on the 
        last_sync and sync_interval fields
        '''

        if not self.last_sync:
            return True
        
        now = datetime.datetime.utcnow()
        
        # If the time (in minutes) between now and the last sync is greater than the sync interval
        # then it is time to sync
        if (now - self.last_sync).total_seconds() / 60 > self.sync_interval:
            return True
        
        return False

    def save(self, *args, **kwargs):
        '''Override save to set the defaults on sync_settings if the field
        does not already exist with a value
        '''
        if not self.sync_settings:
            self.set_default_sync_settings()

        super().save(*args, **kwargs)


class DetectionRepository(base.BaseDocument):
    '''
    A Detection Repository is a collection of detection rules that can be shared throughout the
    Reflex community and is also consumed by Reflex Agents with the detector role to run
    the detections against a source
    '''

    name = Keyword(fields={'text': Text()})
    description = Text()
    tags = Keyword()  # A list of tags used to categorize this repository
    active = Boolean()
    share_type = Keyword()  # private, local-shared, external-private, external-public
    repo_type = Keyword()  # internal, remote, git
    detections = Keyword()  # A list of all the detections in this repository
    url = Keyword()  # The URL to fetch detections from if this an external repository
    # The number of minutes that should pass before fetching new rules
    refresh_interval = Integer()
    # The access token used to fetch detections from an external repository if this is a repo_type 'remote'
    access_token = Keyword()
    # A list of external tokens that can be used to subscribe to this repository if it is a `external-private` share type
    external_tokens = Keyword()
    # Organizations in this list will have access to this repository if it is `local-shared`
    access_scope = Keyword()
    # Whether or not to delete rules that are no longer in the repository
    delete_rules_on_sync = Boolean()

    class Index:
        name = "reflex-detection-repositories"
        settings = {
            "refresh_interval": "1s"
        }

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

    def get_subscription(self, organization = None):
        '''
        Returns the subscription for this repository
        '''
        return DetectionRepositorySubscription.get_by_repository(self.uuid, organization=organization)

    def subscribe(self, sync_settings, sync_interval=60, default_input=None,
                  default_field_template=None):
        '''
        Creates a subscription for this repository
        '''
        subscription = DetectionRepositorySubscription.get_by_repository(
            self.uuid)
        if not subscription:
            subscription = DetectionRepositorySubscription(
                repository=self.uuid,
                sync_interval=sync_interval,
                sync_settings=sync_settings,
                default_input=default_input,
                default_field_template=default_field_template,
                last_sync=datetime.datetime.utcnow(),
                last_sync_status='pending',
                active=True
            )
            subscription.save(refresh="wait_for")
        else:
            raise ValueError("Repository is already subscribed to")

        return subscription

    def unsubscribe(self, organization):
        '''
        Removes a subscription for this repository
        '''
        subscription = DetectionRepositorySubscription.get_by_repository(
            self.uuid)
        if subscription:
            subscription.delete(refresh="wait_for")
        else:
            raise ValueError("Repository is not subscribed to")

        return None

    def check_access_scope(self, organization):
        '''
        Returns True if the organization has access to this repository
        '''
        access_allowed = False

        # If I am the owner or in the owners organization, I have access
        if self.organization == organization:
            return True

        # If this is shared repository and the access scope is not defined or is empty
        # allow access. If the access scope is defined and the organization is NOT in
        # the access scope, deny access
        if self.share_type == 'local-shared':
            access_allowed = True
            if self.access_scope and len(self.access_scope) > 0:
                if organization not in self.access_scope:
                    access_allowed = False

        return access_allowed

    def check_subscription(self, organization):
        '''
        Returns True if the organization is subscribed to this repository
        '''

        self.__dict__['subscribed'] = False

        if self.organization == organization:
            self.__dict__['subscribed'] = True
        else:
            subscription = DetectionRepositorySubscription.get_by_repository(
                self.uuid, organization=organization)
            if subscription:
                self.__dict__['subscribed'] = True
                self.__dict__['subscription'] = subscription

        # Also perform an ownership check
        self.check_ownership(organization)

        return self.subscribed

    def check_ownership(self, organization):
        '''
        Returns True if the repository is read only
        '''
        if organization != self.organization:
            self.__dict__['read_only'] = True
        else:
            self.__dict__['read_only'] = False

        return self.read_only
    
    @classmethod
    def check_detection_repo_subscription_sync(cls):
        '''
        Checks all active detection repository subscriptions and synchronizes
        them based on the configured sync interval
        '''

        subs = DetectionRepositorySubscription.search()
        subs = subs.filter('term', active=True)

        # The sub must have a repository uuid
        subs = subs.filter('exists', field='repository')

        subs = subs.scan()

        def start_sync(subscription):
            repo = DetectionRepository.get_by_uuid(subscription.repository)
            if repo:
                if sub.should_sync():
                    repo.sync(subscription.organization)
            else:
                subscription.active = False
                subscription.save(refresh=True)

        with ThreadPoolExecutor(max_workers=1) as executor:
            for sub in subs:
                if sub.should_sync():
                    executor.submit(start_sync, sub)

    def sync_rule(self, detection, organization, subscription, input_config, ignore_versions=False):

        log_message_base = {
            'organization': organization,
            'repository_uuid': self.uuid,
            'subscription': subscription.uuid,
        }

        try:
        
            existing_detection = Detection.get_by_detection_id(
                                detection.detection_id, organization=organization)
            if not existing_detection:
                new_detection = Detection(
                    name=detection.name,
                    description=detection.description,
                    tags=detection.tags,
                    active=False,
                    query=detection.query,
                    detection_id=detection.detection_id,
                    organization=organization,
                    tactics=detection.tactics,
                    techniques=detection.techniques,
                    references=detection.references,
                    rule_type=detection.rule_type,
                    version=detection.version,
                    risk_score=detection.risk_score,
                    severity=detection.severity,
                    interval=detection.interval,
                    lookbehind=detection.lookbehind,
                    last_run=datetime.datetime.utcfromtimestamp(
                        40246871),
                    mute_period=detection.mute_period,
                    threshold_config=detection.threshold_config,
                    metric_change_config=detection.metric_change_config,
                    field_mismatch_config=detection.field_mismatch_config,
                    new_terms_config=detection.new_terms_config,
                    indicator_match_config=detection.indicator_match_config,
                    from_repo_sync=True,
                    original_uuid=detection.uuid,
                    signature_fields=detection.signature_fields,
                    observable_fields=detection.observable_fields,
                    guide=detection.guide,
                    setup_guide=detection.setup_guide,
                    testing_guide=detection.testing_guide,
                    test_script=detection.test_script,
                    test_script_language=detection.test_script_language,
                    test_script_safe=detection.test_script_safe,
                    email_template=detection.email_template,
                    status=detection.status,
                    source=input_config,
                    field_templates=subscription.default_field_template,
                    assess_rule=True,
                    required_fields=detection.required_fields,
                    from_sigma=detection.from_sigma,
                    sigma_rule=detection.sigma_rule,
                    sigma_rule_id=detection.sigma_rule_id
                )
                new_detection.save()
                RepositorySyncLog(
                    **log_message_base,
                    detection_uuid=detection.uuid,
                    status='success',
                    message=f"Added new detection {new_detection.name}({new_detection.uuid}) from repository {self.name}, using source detection {detection.uuid}",
                    level='info'
                ).save()
            else:

                existing_detection = existing_detection[0]
                if existing_detection.version < detection.version or ignore_versions:

                    existing_detection.name = detection.name
                    existing_detection.description = detection.description
                    existing_detection.tags = detection.tags

                    if existing_detection.query != detection.query:
                        existing_detection.assess_rule = True
                        existing_detection.query = detection.query

                    existing_detection.tactics = detection.tactics
                    existing_detection.techniques = detection.techniques
                    existing_detection.references = detection.references
                    existing_detection.rule_type = detection.rule_type
                    existing_detection.version = detection.version
                    existing_detection.from_repo_sync = True
                    existing_detection.test_script = detection.test_script
                    existing_detection.test_script_language = detection.test_script_language
                    existing_detection.test_script_safe = detection.test_script_safe
                    existing_detection.email_template = detection.email_template
                    existing_detection.status = detection.status
                    existing_detection.required_fields = detection.required_fields
                    existing_detection.from_sigma = detection.from_sigma
                    existing_detection.sigma_rule = detection.sigma_rule
                    existing_detection.sigma_rule_id = detection.sigma_rule_id

                    # Set all the attributes based on the sync settings
                    sync_settings = subscription.sync_settings.to_dict()
                    for sync_setting in sync_settings:
                        if subscription.sync_settings[sync_setting] == True:
                            if sync_setting == 'field_templates':
                                # If the subscription has a default field template and the existing detection does not, set the default
                                if existing_detection.field_templates == None and subscription.default_field_template != None:
                                    existing_detection.field_templates = subscription.default_field_template
                                elif subscription.default_field_template == None and detection.field_templates != None:
                                    existing_detection.field_templates = detection.field_templates
                            else:
                                setattr(existing_detection,
                                        sync_setting,
                                        getattr(detection, sync_setting)
                                        )

                    existing_detection.save()
                    RepositorySyncLog(
                        **log_message_base,
                        message=f"Updated detection {existing_detection.name} ({existing_detection.uuid}) from repository {self.name}",
                        level="info",
                        status="success"
                    ).save()
                    
        except Exception as e:
            RepositorySyncLog(
                **log_message_base,
                message=f"Error syncing detection {detection.name} ({detection.uuid}) from repository {self.name}: {e}",
                level="error",
                status="failed"
            ).save()
            return False


    def sync(self, organization, subscription=None, ignore_versions=False):
        ''' Synchronizes the repository if it is a local repository '''

        # Get the configuration for the repository sync via the subscription
        if not subscription:
            subscription = DetectionRepositorySubscription.get_by_repository(
                self.uuid, organization=organization)

        if subscription:

            # If the sync settings are not defined, set the defaults
            if not subscription.sync_settings:
                subscription.set_default_sync_settings()
                subscription.save(refresh="wait_for")

            if self.detections and len(self.detections) > 0:

                # Trigger that the sync is starting
                subscription.synchronizing = True
                subscription.save(refresh="wait_for")

                input_config = None

                if subscription.default_input:
                    _input = Input.get_by_uuid(subscription.default_input)

                    if not _input:
                        return False

                    input_config = {
                        'uuid': _input.uuid,
                        'language': '',
                        'name': _input.name,
                    }

                if self.repo_type == 'local':
                    detections_to_sync = Detection.get_by_detection_id(
                        self.detections, repository=self.uuid)
                    
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        for detection in detections_to_sync:
                            executor.submit(self.sync_rule, detection, organization, subscription, input_config, ignore_versions)

                    # Update the subscription with the last sync time
                    subscription.last_sync = datetime.datetime.utcnow()
                    subscription.last_sync_status = 'success'
                    subscription.next_sync = datetime.datetime.utcnow(
                    ) + datetime.timedelta(minutes=subscription.sync_interval)
                    subscription.synchronizing = False
                    subscription.save(refresh="wait_for")

                    # Check to see if any detections exist that are from_repo_sync
                    Detection._index.refresh()

            else:
                subscription.next_sync = datetime.datetime.utcnow(
                ) + datetime.timedelta(minutes=subscription.sync_interval)
                subscription.synchronizing = False
                subscription.last_sync_status = 'success'
                subscription.save(refresh="wait_for")

    def add_detections(self, detections):
        ''' Adds detections to the repository '''

        detections = [d.detection_id for d in detections if d.organization ==
                      self.organization and d.from_repo_sync == False]
        if self.detections is None:
            self.detections = []
        detections = [d for d in detections if d not in self.detections]
        try:
            self.detections.extend(detections)
            self.save()

            # Update the detection with the repository uuid
            ubq = UpdateByQuery(index=Detection._index._name)
            ubq = ubq.query('term', organization=self.organization)
            ubq = ubq.query('terms', detection_id=detections)

            # Painless script if the repository field does not exist or is null set it to a list with the repository uuid
            # if it does exist add the repository uuid to the list
            script = '''
            if (ctx._source.repository == null) {
                ctx._source.repository = [params.repository];
            } else {
                ctx._source.repository.add(params.repository);
            }
            '''
            ubq = ubq.script(source=script, params={'repository': self.uuid})
            ubq.execute()

        except Exception as e:
            print(e)

    def remove_detections(self, detections):
        ''' Removes detections from the repository, rules that are not in this repository
        will be disassociated from the repository for any tenants that are subscribed to this
        repository
        '''
        detections = [
            d.detection_id for d in detections if d.organization == self.organization]

        if self.detections is None:
            self.detections = []

        detections = [d for d in detections if d in self.detections]
        try:
            self.detections = [
                d for d in self.detections if d not in detections]
            self.save()

            # Update the detection with the repository uuid
            ubq = UpdateByQuery(index=Detection._index._name)
            ubq = ubq.query('term', organization=self.organization)
            ubq = ubq.query('terms', detection_id=detections)

            # Remove the repository uuid from the detections repository list if it exists in the list
            # else do nothing.  If the repository list is empty after the removal remove the repository field
            # set it to an empty list
            script = "if (ctx._source.containsKey('repository')) { ctx._source.repository.remove(ctx._source.repository.indexOf(params.repository)) }"
            ubq = ubq.script(source=script, params={'repository': self.uuid})
            ubq.execute()

            # Set from_repo_sync to False for any detections that were in this repository but are not anymore
            # and have been synced to a tenant
            ubq = UpdateByQuery(index=Detection._index._name)

            # Removed 2023.10.25 by @n3tsurge
            #ubq = ubq.query('term', organization=self.organization)

            ubq = ubq.query('term', from_repo_sync=True)
            ubq = ubq.query('terms', detection_id=detections)
            ubq = ubq.script(source="ctx._source.from_repo_sync = false")
            ubq.execute()

        except Exception as e:
            print(e)

    def remove_rules(self, organization):
        ''' Removes all the rules associated with this repository from the 
        target organizations rule set
        '''
        if self.detections and len(self.detections) > 0:
            if self.repo_type == 'local':

                # Update by query all the detections that were synchronized from this repo to this
                # organization and set from_repo_sync to False
                ubq = UpdateByQuery(index=Detection._index._name)
                ubq = ubq.query('term', organization=organization)
                ubq = ubq.query('term', from_repo_sync=True)
                ubq = ubq.query('terms', detection_id=self.detections)
                ubq = ubq.script(source="ctx._source.from_repo_sync = false")
                ubq.execute()


class DetectionRepositoryBundle(base.BaseDocument):
    '''
    A Repo Bundle contains information about many repositories, it is an easy way to share many
    repositories at one time
    '''

    name = Keyword(fields={'text': Text()})
    description = Text()
    tags = Keyword()  # A list of tags used to categorize this repository
    repos = Keyword()  # A list of all the repos in the bundle

    class Index:
        name = "reflex-detection-repository-bundles"
        settings = {
            "refresh_interval": "1s"
        }
