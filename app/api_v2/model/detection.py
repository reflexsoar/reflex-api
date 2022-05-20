"""app/api_v2/model/detection.py

Contains all the logic for the Detection engine
"""

import re
import datetime
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Float,
    Date,
    Nested,
    system,
    Object
)


class DetectionException(base.BaseInnerDoc):
    '''
    A DetectionException tells a detection to filter out specific criteria
    '''

    description = Text()
    query = Keyword()


class MetricChangeConfig(base.InnerDoc):
    '''
    The configuration for a Metric Changes
    '''

    avg_period = Integer() # How far back to look to find average logs
    threshold = Integer() # The threshold e.g. 10 which is 10 items or 10%
    threshold_format = Integer() # 1 = Value, 2 = Percent
    increase = Boolean() # True = increase, False = Decrease


class ThresholdConfig(base.InnerDoc):
    '''
    The configuration for ThresholdHold
    '''

    threshold = Integer() # The number of items where the threshold is crossed
    key_field = Keyword() # Optional key to count against (count of records in this field)


class FieldMismatchConfig(base.InnerDoc):
    '''
    A Field Mismatch rule will fire when two fields of an item returned by 
    the intial query do not match
    '''

    source_field = Keyword()
    target_field = Keyword()
    operator = Keyword() # eq or ne


class QueryConfig(base.InnerDoc):
    '''
    '''

    language = Keyword() # kql, lucene, spl, eql, qradar
    query = Keyword()


class SourceConfig(base.InnerDoc):
    '''
    '''

    language = Keyword()
    source = Keyword()


class ObservableField(base.InnerDoc):
    '''
    Defines what fields to extract as observables and what their data_types and associated
    meta data should be
    '''

    field = Keyword()
    alias = Keyword()
    data_type = Text(fields={'keyword':Keyword()})
    tlp = Integer()
    tags = Keyword()


class Detection(base.BaseDocument):
    '''
    A Detection is a rule defined by a security team to look for suspicious or malicious
    activity in a source of data
    '''

    name = Keyword(fields={'text':Text()})
    query = Nested(QueryConfig) # The query to run against the log source
    detection_id = Keyword() # A persistent UUID that follows the rule and is associated to events
    from_sigma = Boolean() # Tells you if the rule was converted from a Sigma rule
    sigma_rule = Keyword(fields={'text':Text()}) # The raw sigma rule
    description = Text()
    guide = Text() # A descriptive process for how to triage/investigate this detection
    tags = Keyword() # A list of tags used to categorize this repository
    tactics = Keyword()  # T1085.1
    techniques = Keyword() # T1085
    references = Keyword() # A list of URLs that detail in greater depth why this detection exists
    false_positives = Keyword() # A list of false positives
    kill_chain_phase = Keyword() # Singular text based phase definition
    rule_type = Integer() # 1 - Match 2 - Frequency 3 - Metric
    version = Integer() # Version number 
    active = Boolean() # Is the rule active or disabled
    warnings = Keyword() # A list of warnings for this alert e.g. slow, volume, field_missing, import_fail
    source = Object(SourceConfig) # The UUID of the input/source this detection should run against
    case_template = Keyword() # The UUID of the case_template to apply when an alert created by this detection is ultimately turned in to a case
    risk_score = Integer() # 0 - 100 
    severity = Integer() # 1-4 (1: Low, 2: Medium, 3: High, 4: Critical)
    signature_fields = Keyword() # Calculate a unique signature for this rule based on fields on the source event
    observable_fields = Nested(ObservableField) # Configures which fields should show up as observables in the alert
    query_time = Integer() # How long the rule took to run in seconds
    interval = Integer() # How often should the rule run in minutes
    lookbehind = Integer() # How far back should the rule look when it runs
    skip_event_rules = Boolean() # Skip Event Rules when this detection generates an Event
    run_start = Date() # When the run started
    run_finished = Date() # When the run finished
    next_run = Date() # When the rule should run again
    last_run = Date() # When was the last time the rule was run
    exceptions = Nested(DetectionException) # InnerDoc 
    mute_period = Integer() # How long to prevent the detection from refiring in minutes. If 0 send all
    threshold_config = Object(ThresholdConfig)
    metric_change_config = Object(MetricChangeConfig)
    field_mismatch_config = Object(FieldMismatchConfig)
    assigned_agent = Keyword() # The UUID of the agent that should run this alarm

    class Index:
        name = "reflex-detections"
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


class DetectionPerformanceMetric(base.BaseDocument):
    '''
    Used to show Detection performance over time
    '''

    detection_id = Keyword() # The detection ID for this metric
    rule_type = Integer() # The rule type
    query_time = Integer() # How long the query took

    class Index:
        name = "reflex-detections-perf-metrics"
        settings = {
            "refresh_interval": "1s"
        }


class DetectionRepositoryToken(base.BaseDocument):
    '''
    An access token is generated for external parties to subscribe to a detection repository
    '''

    repository = Keyword() # The UUID of the repository this token belongs to
    ip_addresses = Keyword() # The IP addresses allowed to use this token
    last_used = Date() # The last time the token was used

    class Index:
        name = 'reflex-detection-access-tokens'
        settings = {
            "refresh_interval": "1s"
        }

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


class DetectionRepository(base.BaseDocument):
    '''
    A Detection Repository is a collection of detection rules that can be shared throughout the
    Reflex community and is also consumed by Reflex Agents with the detector role to run
    the detections against a source
    '''

    name = Keyword(fields={'text':Text()})
    description = Text()
    tags = Keyword() # A list of tags used to categorize this repository
    active = Boolean()
    shared_type = Integer() # 0: Private, 1: Shared, 2: Public
    repo_type = Integer() # 0: Internal, 1: Reflex External, 2: GIT
    detections = Keyword() # A list of all the detections in this repository
    url = Keyword() # The URL to fetch detections from if this an external repository
    refresh_interval = Integer() # The number of seconds that should pass before fetching new rules

    class Index:
        name = "reflex-detection-repositories"
        settings = {
            "refresh_interval": "1s"
        }


class DetectionRepositoryBundle(base.BaseDocument):
    '''
    A Repo Bundle contains information about many repositories, it is an easy way to share many
    repositories at one time
    '''

    name = Keyword(fields={'text':Text()})
    description = Text()
    tags = Keyword() # A list of tags used to categorize this repository
    repos = Keyword() # A list of all the repos in the bundle

    class Index:
        name = "reflex-detection-repository-bundles"
        settings = {
            "refresh_interval": "1s"
        }