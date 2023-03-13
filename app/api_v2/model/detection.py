"""app/api_v2/model/detection.py

Contains all the logic for the Detection engine
"""

import re
import datetime

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
    AttrList
)

from .inout import FieldMap


VALID_REPO_SHARE_MODES = ['private','local-shared', 'external-private', 'external-public']
VALID_REPO_TYPES = ['local', 'remote']


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
    operator = Keyword() # The operator to use e.g. >, <, >=, <=, ==, !=
    dynamic = Boolean() # True = dynamic, False = static
    key_field = Keyword() # Optional key to count against (count of records in this field)
    discovery_period = Integer() # How far back to look to find average logs
    recalculation_period = Integer() # How often to recompute the dynamic threshold
    per_field = Boolean() # True = per field, False = per item
    threshold_last_discovered = Date() # The last time the threshold was discovered
    max_events = Integer() # The number of events to return when a threshold is crossed


class NewTermsConfig(base.InnerDoc):
    '''
    The configuration for NewTerms
    '''

    key_field = Keyword() # The field to pull terms from
    max_terms = Integer() # How many terms to look for in the baseline period
    window_size = Integer() # How far back to look for the initial set of terms


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
    name = Keyword()
    uuid = Keyword()


class DetectionLog(base.BaseDocument):
    '''
    A log entry for the detection for troubleshooting and history tracking
    '''

    detection_uuid = Keyword() # the ID of the detection create the log entry
    level = Keyword() # info, error, warning
    hits = Long() # How many hits this detection matched on this run
    time_taken = Integer() # How long this run took
    start_time = Date() # When the run started
    end_time = Date() # When the run finished
    message = Keyword(fields={'text':Text()}) # Any message related to the log

    class Index:
        name = "reflex-detections-log"
        settings = {
            "refresh_interval": "1s"
        }


class Detection(base.BaseDocument):
    '''
    A Detection is a rule defined by a security team to look for suspicious or malicious
    activity in a source of data
    '''

    name = Keyword(fields={'text':Text()})
    original_uuid = Keyword() # The UUID of the original detection this detection was created from
    from_repo_sync = Boolean() # Tells you if the rule was created from a repo sync
    repository = Keyword() # The UUID of the repository this rule was created from
    query = Object(QueryConfig) # The query to run against the log source
    detection_id = Keyword() # A persistent UUID that follows the rule and is associated to events
    from_sigma = Boolean() # Tells you if the rule was converted from a Sigma rule
    sigma_rule = Keyword(fields={'text':Text()}) # The raw sigma rule
    sigma_rule_id = Keyword() # The ID of the Sigma rule
    description = Text()
    guide = Text() # A descriptive process for how to triage/investigate this detection
    tags = Keyword() # A list of tags used to categorize this repository
    tactics = Nested(MITRETacticTechnique) # T1085.1
    techniques = Nested(MITRETacticTechnique) # T1085
    references = Keyword() # A list of URLs that detail in greater depth why this detection exists
    false_positives = Keyword() # A list of false positives
    kill_chain_phase = Keyword() # Singular text based phase definition
    rule_type = Integer() # 0 - Match 1 - Frequency 2 - Metric
    version = Integer() # Version number 
    active = Boolean() # Is the rule active or disabled
    warnings = Keyword() # A list of warnings for this alert e.g. slow, volume, field_missing, import_fail
    source = Object(SourceConfig) # The UUID of the input/source this detection should run against
    case_template = Keyword() # The UUID of the case_template to apply when an alert created by this detection is ultimately turned in to a case
    risk_score = Integer() # 0 - 100 
    severity = Integer() # 1-4 (1: Low, 2: Medium, 3: High, 4: Critical)
    signature_fields = Keyword() # Calculate a unique signature for this rule based on fields on the source event
    field_templates = Keyword() # A list of field templates to apply to the alert
    observable_fields = Nested(FieldMap) # Configures which fields should show up as observables in the alert
    time_taken = Integer() # How long the rule took to run in milliseconds
    query_time_taken = Long() # How long the query took to run in milliseconds
    interval = Integer() # How often should the rule run in minutes
    lookbehind = Integer() # How far back should the rule look when it runs
    catchup_period = Integer() # How far back in minutes the rule should hunt for missed detections if a rule run is missed
    skip_event_rules = Boolean() # Skip Event Rules when this detection generates an Event
    run_start = Date() # When the run started
    run_finished = Date() # When the run finished
    next_run = Date() # When the rule should run again
    last_run = Date() # When was the last time the rule was run
    last_hit = Date() # The last time this rule matched anything
    total_hits = Long()
    exceptions = Nested(DetectionException) # InnerDoc 
    mute_period = Integer() # How long to prevent the detection from refiring in minutes. If 0 send all
    threshold_config = Object(ThresholdConfig)
    metric_change_config = Object(MetricChangeConfig)
    field_mismatch_config = Object(FieldMismatchConfig)
    new_terms_config = Object(NewTermsConfig)
    assigned_agent = Keyword() # The UUID of the agent that should run this alarm
    include_source_meta_data = Boolean() # If true the detection will include the meta data from the source event in the alert
    status = Keyword() # Experimental, Beta, Stable, Test, Deprecated, Production

    class Index:
        name = "reflex-detections"
        settings = {
            "refresh_interval": "1s"
        }

    @classmethod
    def get_by_detection_id(cls, detection_id, organization=None):
        '''
        Fetches a document by the detection_id field  which is a persistent UUID
        that follows the rule across any installation of the API
        '''
        response = cls.search(skip_org_check=True)

        if isinstance(detection_id, (list,AttrList)):
            response = response.filter('terms', detection_id=detection_id)
        else:
            response = response.filter('term', detection_id=detection_id)

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
    
    def get_field_settings(self):
        '''Provides a list of field settings for this detection'''

        final_fields = []
        # If the detection is using templates, merge the fields from all the 
        # templates into a single list.  Templates with a higher priority will
        # override templates with a lower priority in the event of a field name
        # collision
        if self.field_templates:
            templates = FieldMappingTemplate.get_by_uuid(self.field_templates)
            templates.sort(key=lambda x: x.priority, reverse=True)
            for template in templates:
                for template_field in template.field_mapping:
                    replaced = False
                    for field in final_fields:
                        if field['field'] == template_field['field']:
                            final_fields[final_fields.index(field)] = template_field
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
                        final_fields[final_fields.index(field)] = detection_field
                        replaced = True
                        break

                if not replaced:
                    final_fields.append(detection_field)

        return final_fields

    
    @classmethod
    def create_from_json(cls, data, preserve_uuid=False, preserve_organization=False, from_repo=False, repository_uuid=None):
        ''' Creates a detection from a json object '''

        current_user = _current_user_id_or_none()
        
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
                raise ValueError("Repository ID is required when creating a detection from a repository")
            data['from_repo_sync'] = True
            data['repository'] = repository_uuid
        
        # If preserving the UUID the detection should be updated instead of created
        if preserve_uuid:
            detection = cls.get_by_uuid(data['uuid'])
            if detection:
                detection.update(**data)
                return detection
            else:
                raise ValueError("Detection with UUID {} does not exist".format(data['uuid']))
            
        existing_name = cls.get_by_name(data['name'], organization=data['organization'])
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


class DetectionRepositorySubscription(base.BaseDocument):
    '''
    A subscription is created when clicking enable on an internal-shared repository or adding
    an external-private or external-public repository
    '''

    repository = Keyword() # The UUID of the repository this subscription belongs to
    sync_interval = Integer() # The sync interval for this subscription, in minutes
    last_sync = Date() # The last time this repository was synced
    last_sync_status = Keyword() # The status of the last sync
    active = Boolean() # Whether or not this subscription is active

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
    share_type = Keyword() # private, local-shared, external-private, external-public
    repo_type = Keyword() # internal, remote, git
    detections = Keyword() # A list of all the detections in this repository
    url = Keyword() # The URL to fetch detections from if this an external repository
    refresh_interval = Integer() # The number of minutes that should pass before fetching new rules
    access_token = Keyword() # The access token used to fetch detections from an external repository if this is a repo_type 'remote'
    external_tokens = Keyword() # A list of external tokens that can be used to subscribe to this repository if it is a `external-private` share type
    access_scope = Keyword() # Organizations in this list will have access to this repository if it is `local-shared`

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
    
    def subscribe(self, sync_interval=60):
        '''
        Creates a subscription for this repository
        '''
        subscription = DetectionRepositorySubscription.get_by_repository(self.uuid)
        if not subscription:
            subscription = DetectionRepositorySubscription(
                repository=self.uuid,
                sync_interval=sync_interval,
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
        subscription = DetectionRepositorySubscription.get_by_repository(self.uuid)
        if subscription:
            subscription.delete(refresh="wait_for")
        else:
            raise ValueError("Repository is not subscribed to")
        
        return None
    
    def check_subscription(self, organization):
        '''
        Returns True if the organization is subscribed to this repository
        '''

        self.__dict__['subscribed'] = False

        if self.organization == organization:
            self.__dict__['subscribed'] = True
        else:
            subscription = DetectionRepositorySubscription.get_by_repository(self.uuid, organization=organization)
            if subscription:
                self.__dict__['subscribed'] = True

        # Also perform an owedership check
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
    
    def sync(self, organization):
        ''' Synchronizes the repository if it is a local repository '''
        if self.repo_type == 'local':
            detections_to_sync = Detection.get_by_detection_id(self.detections)
            for detection in detections_to_sync:
                existing_detection = Detection.get_by_detection_id(detection.detection_id, organization=organization)
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
                        rule_type=detection.rule_type,
                        version=detection.version,
                        risk_score=detection.risk_score,
                        severity=detection.severity,
                        interval=detection.interval,
                        lookbehind=detection.lookbehind,
                        last_run=datetime.datetime.utcfromtimestamp(40246871),
                        mute_period=detection.mute_period,
                        threshold_config=detection.threshold_config,
                        metric_change_config=detection.metric_change_config,
                        field_mismatch_config=detection.field_mismatch_config,
                        new_terms_config=detection.new_terms_config,
                        from_repo_sync=True
                    )
                    new_detection.save()
                else:
                    existing_detection = existing_detection[0]
                    existing_detection.name = detection.name
                    existing_detection.description = detection.description
                    existing_detection.tags = detection.tags
                    existing_detection.active = False
                    existing_detection.query = detection.query
                    existing_detection.tactics = detection.tactics
                    existing_detection.techniques = detection.techniques
                    existing_detection.rule_type = detection.rule_type
                    existing_detection.version = detection.version
                    existing_detection.risk_score = detection.risk_score
                    existing_detection.severity = detection.severity
                    existing_detection.interval = detection.interval
                    existing_detection.lookbehind = detection.lookbehind
                    existing_detection.mute_period = detection.mute_period
                    existing_detection.threshold_config = detection.threshold_config
                    existing_detection.metric_change_config = detection.metric_change_config
                    existing_detection.field_mismatch_config = detection.field_mismatch_config
                    existing_detection.new_terms_config = detection.new_terms_config
                    existing_detection.from_repo_sync = True
                    existing_detection.save()
            Detection._index.refresh()


    def remove_rules(self, organization):
        ''' Removes all the rules associated with this repository from the 
        target organizations rule set
        '''
        if self.repo_type == 'local':
            detections_to_unlink = Detection.get_by_detection_id(self.detections, organization=organization)
            print(detections_to_unlink)


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