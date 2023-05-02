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
    AttrList,
    UpdateByQuery,
    Input
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
    list_uuid = Keyword()
    source_field = Keyword()


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
    assigned_agent = Keyword()  # The UUID of the agent that should run this alarm
    # If true the detection will include the meta data from the source event in the alert
    include_source_meta_data = Boolean()
    status = Keyword()  # Experimental, Beta, Stable, Test, Deprecated, Production
    repository = Keyword()  # The UUID of the repositories this rule is associated to
    daily_schedule = Boolean()  # If false the detection will always run
    schedule = Nested(DetectionSchedule)

    class Index:
        name = "reflex-detections"
        settings = {
            "refresh_interval": "1s"
        }

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
    sync_interval = Integer()  # The sync interval for this subscription, in minutes
    last_sync = Date()  # The last time this repository was synced
    last_sync_status = Keyword()  # The status of the last sync
    active = Boolean()  # Whether or not this subscription is active
    # The sync settings for this subscription
    sync_settings = Object(DetectionRepositorySubscriptionSyncSettings)
    # The UUID of the default input for any detections created from this
    # repository subscription
    default_input = Keyword()

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

    def get_subscription(self):
        '''
        Returns the subscription for this repository
        '''
        return DetectionRepositorySubscription.get_by_repository(self.uuid)

    def subscribe(self, sync_settings, sync_interval=60, default_input=None):
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

    def sync(self, organization):
        ''' Synchronizes the repository if it is a local repository '''

        # Get the configuration for the repository sync via the subscription
        subscription = DetectionRepositorySubscription.get_by_repository(
            self.uuid, organization=organization)

        if subscription:

            # If the sync settings are not defined, set the defaults
            if not subscription.sync_settings:
                subscription.set_default_sync_settings()
                subscription.save(refresh="wait_for")

            if self.detections and len(self.detections) > 0:

                input_config = None

                if subscription.default_input:
                    input = Input.get_by_uuid(subscription.default_input)
                    input_config = {
                        'uuid': input.uuid,
                        'language': '',
                        'name': input.name,
                    }

                if self.repo_type == 'local':
                    detections_to_sync = Detection.get_by_detection_id(
                        self.detections, repository=self.uuid)
                    for detection in detections_to_sync:
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
                                from_repo_sync=True,
                                original_uuid=detection.uuid,
                                signature_fields=detection.signature_fields,
                                observable_fields=detection.observable_fields,
                                guide=detection.guide,
                                setup_guide=detection.setup_guide,
                                testing_guide=detection.testing_guide,
                                status=detection.status,
                                source=input_config
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
                            existing_detection.from_repo_sync = True

                            # Set all the attributes based on the sync settings
                            sync_settings = subscription.sync_settings.to_dict()
                            for sync_setting in sync_settings:
                                if subscription.sync_settings[sync_setting] == True:
                                    setattr(existing_detection,
                                            sync_setting,
                                            getattr(detection, sync_setting)
                                            )

                            existing_detection.save()

                    # Update the subscription with the last sync time
                    subscription.last_sync = datetime.datetime.utcnow()
                    subscription.last_sync_status = 'success'
                    subscription.save(refresh="wait_for")

                    Detection._index.refresh()

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
            ubq = ubq.query('term', organization=self.organization)
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
