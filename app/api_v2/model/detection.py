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
    system
)


class Detection(base.BaseDocument):
    '''
    A Detection is a rule defined by a security team to look for suspicious or malicious
    activity in a source of data
    '''

    name = Keyword(fields={'text':Text()})
    detection_id = Keyword() # A persistent UUID that follows the rule and is associated to events
    description = Text()
    guide = Text() # A descriptive process for how to triage/investigate this detection
    tags = Keyword() # A list of tags used to categorize this repository
    tactics = Keyword()
    techniques = Keyword()
    references = Keyword() # A list of URLs that detail in greater depth why this detection exists
    kill_chain_phase = Keyword()
    rule_type = Integer()
    version = Float()
    active = Boolean() # Is the rule active or disabled
    warnings = Keyword() # A list of warnings for this alert e.g. slow, volume, field_missing, import_fail
    source = Keyword() # The UUID of the input/source this detection should run against
    case_template = Keyword() # The UUID of the case_template to apply when an alert created by this detection is ultimately turned in to a case
    risk_score = Integer() # 0 - 100 
    severity = Integer() # 1-4 (1: Low, 2: Medium, 3: High, 4: Critical)
    signature_fields = Keyword() # Calculate a unique signature for this rule based on fields on the source event
    observable_fields = Nested() # Configures which fields should show up as observables in the alert
    query_time = Integer() # How long the query took to run
    interval = Integer() # How often should the rule run in seconds
    lookbehind = Integer() # How far back should the rule look when it runs

    class Index:
        name = "reflex-detections"
        settings = {
            "refresh_interval": "1s"
        }
    

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