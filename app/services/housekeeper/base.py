""" /app/services/housekeeper/base.py
HouseKeeper service runs system jobs that attempt to keep the system
in a healthy state, like pruning old jobs or disabling accounts that have
not been used in a long time
"""
from uuid import uuid4
from hashlib import sha1
import json
import time
import datetime
import logging
from app.api_v2.model import (
    Settings,
    Agent,
    Role,
    AgentGroup,
    Task,
    Q,
    Event,
    EventRule,
    DetectionRepositorySubscription,
    DetectionRepository,
    Organization,
    Detection,
    EventStatus
)
from app.api_v2.model.benchmark import (
    BenchmarkResult, BenchmarkResultHistory,
    archive_agent_results
)


def check_lock(f):
    '''
    Sets a lock on the function to prevent multiple instances of the function
    '''
    def wrapper(*args, **kwargs):
        _owner = args[0]
        while _owner.check_lock:
            time.sleep(1)

        _owner.check_lock = True
        f(*args, **kwargs)
        _owner.check_lock = False
        return
    return wrapper


class HouseKeeper(object):
    """ HouseKeeper service runs system jobs that attempt to keep the system
    in a healthy state, like pruning old jobs or disabling accounts that have
    not been used in a long time
    """

    def __init__(self, app, log_level="DEBUG", *args, **kwargs):

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(log_levels[log_level])

        self.app = app

        self.agent_prune_lifetime = self.app.config['AGENT_PRUNE_LIFETIME']
        self.task_prune_lifetime = self.app.config['TASK_PRUNE_LIFETIME']
        self.agent_health_lifetime = self.app.config['AGENT_HEALTH_LIFETIME']
        self.agent_health_input_ttl = self.app.config['AGENT_HEALTH_CHECK_INPUT_TTL']
        self.event_rule_silent_days = self.app.config['EVENT_RULE_SILENT_DAYS']
        self.event_rule_silent_hits = self.app.config['EVENT_RULE_SILENT_HITS']
        self.event_rule_silent_actions = self.app.config['EVENT_RULE_SILENT_ACTIONS']
        self.event_rule_high_volume_days = self.app.config['EVENT_RULE_HIGH_VOLUME_DAYS']
        self.event_rule_high_volume_hits = self.app.config['EVENT_RULE_HIGH_VOLUME_HITS']

        self.logger.info(
            f"Service started.")
        self.logger.info(
            f"Agent Prune Lifetime: {self.agent_prune_lifetime} days")
        self.logger.info(
            f"Task Prune Lifetime: {self.task_prune_lifetime} days")
        self.logger.info(
            f"Agent Health Lifetime: {self.agent_health_lifetime} days")
        self.logger.info(
            f"Agent Health Input TTL: {self.agent_health_input_ttl} days")
        self.logger.info(
            f"Event Rule Silent Days: {self.event_rule_silent_days} days")
        self.logger.info(
            f"Event Rule Silent Hits: {self.event_rule_silent_hits} hits")
        self.logger.info(
            f"Event Rule High Volume Days: {self.event_rule_high_volume_days} days")
        self.logger.info(
            f"Event Rule High Volume Hits: {self.event_rule_high_volume_hits} hits")

        self.check_lock = None
        self.locks = {
            'check_agent_health': False,
            'check_detection_repo_subscription_sync': False,
            'check_agent_input_health': False,
            'check_expired_event_rules': False,
            'check_silent_event_rules': False,
            'check_high_volume_event_rules': False,
            'prune_old_agents': False,
        }

    @check_lock
    def check_agent_health(self):
        ''' Checks the health of all agents if the agent hasn't check in for a set
        period of time, set the agent to unhealthy and remove it from any work it has to do
        '''

        self.logger.info('Checking for unhealthy agents - Heartbeat TTL')
        issue_label = "Heartbeat TTL Expired"

        days_ago = datetime.datetime.utcnow(
        ) - datetime.timedelta(minutes=self.agent_health_lifetime)

        search = Agent.search()
        search = search[0:search.count()]
        search = search.filter('bool', should=[Q('range', last_heartbeat={
                               'lte': days_ago.isoformat()}), Q('bool', must_not=[Q('exists', field='last_heartbeat')])])
        agents = search.scan()
        for agent in agents:
            agent.healthy = False
            if hasattr(agent, 'health_issues') and agent.health_issues:
                if len(agent.health_issues) > 0:
                    if issue_label in agent.health_issues:
                        continue
                    agent.health_issues.append(issue_label)
                else:
                    agent.health_issues = [issue_label]
            else:
                agent.health_issues = [issue_label]

            agent.save(refresh=True)

    @check_lock
    def check_detection_repo_subscription_sync(self):
        '''
        Checks all active detection repository subscriptions and synchronizes
        them based on the configured sync interval
        '''

        self.logger.info('Checking detection repository subscriptions')
        subs = DetectionRepositorySubscription.search()
        subs = subs.filter('term', active=True)

        # Find all subscriptions that have a next_sync value in the past or
        # the next_sync field does not exist
        subs = subs.filter('bool', should=[Q('range', next_sync={
            'lte': datetime.datetime.utcnow().isoformat()}), Q('bool', must_not=[Q('exists', field='next_sync')])])
        
        # The sub must have a repository uuid
        subs = subs.filter('exists', field='repository')

        subs = subs.scan()

        for sub in subs:
            repo = DetectionRepository.get_by_uuid(sub.repository)

            if not repo:
                self.logger.error(f"Unable to find repository {sub.repository} for subscription {sub.uuid}")
                sub.active = False
                sub.save(refresh=True)
                continue

            self.logger.info(f"Syncing detection repository subscription {repo.name}, {repo.uuid}")
            repo.sync(sub.organization)

    @check_lock
    def check_agent_input_health(self):
        ''' Checks to see if agents that are assigned inputs are still sending
        events
        '''
        self.logger.info('Checking for unhealthy agents - Input Health')
        issue_label = "Events Silent"

        search = Agent.search()
        search = search[0:search.count()]
        agents = search.scan()

        agents_with_inputs = []
        for agent in agents:
            # If the agent is directly assigned inputs
            if agent._input_count > 0:
                agents_with_inputs.append(agent)

        event_search = Event.search()
        event_search.params(size=0)
        event_search.aggs.bucket('agent_events', 'filter', range={
            'created_at': {
                'gte': f"now-{self.agent_health_input_ttl}m"
            }})

        event_search.aggs['agent_events'].bucket(
            'agents', 'terms', field='agent_uuid.keyword', size=10000)
        results = event_search.execute()
        for agent in agents_with_inputs:
            uuids_with_events = [
                b.key for b in results.aggregations.agent_events.agents.buckets]
            if agent.uuid not in uuids_with_events:
                agent.healthy = False
                if hasattr(agent, 'health_issues') and agent.health_issues:
                    if len(agent.health_issues) > 0:
                        if issue_label in agent.health_issues:
                            continue
                        agent.health_issues.append(issue_label)
                    else:
                        agent.health_issues = [issue_label]
                else:
                    agent.health_issues = [issue_label]
            else:
                if hasattr(agent, 'health_issues') and agent.health_issues:
                    if issue_label in agent.health_issues:
                        agent.health_issues.remove(issue_label)
                    if len(agent.health_issues) == 0:
                        agent.healthy = True
            agent.save(refresh=True)

    @check_lock
    def check_expired_event_rules(self):
        ''' Checks to see if any event rules have expired and disables them
        '''
        self.logger.info('Checking for expired event rules')
        search = EventRule.search()
        search = search[0:search.count()]
        search = search.filter('bool', should=[Q('range', expires_at={
            'lte': datetime.datetime.utcnow().isoformat()}), Q('bool', must_not=[Q('exists', field='expires_at')])])
        rules = search.scan()
        for rule in rules:
            if rule.expired():
                rule.enabled = False
                rule.save(refresh=True)

    @check_lock
    def check_silent_event_rules(self):
        '''
        Disables event rules without hits in the last N days
        '''

        SUPPORTED_ACTIONS = [
            'dismiss',
            'add_tags',
            'remove_tags',
            'update_severity',
            'mute_event',
            'dismiss',
            'merge_into_case',
            'create_new_case',
            'set_organization'
        ]

        self.logger.info('Checking silent event rules')
        events = Event.search()

        # Filter by time range now-Nd
        events = events.filter('range', created_at={
            'gte': f"now-{self.event_rule_silent_days}d"})

        # Aggregate count of event rule uuids from the events index
        events.aggs.bucket('event_rules', 'terms',
                           field='event_rules', size=10000)

        # Set the size to 0 so we don't get any events back
        events = events[0:0]

        # Run the search
        results = events.execute()

        # Create a list of rules with hits
        rules_with_hits = [
            b.key for b in results.aggregations.event_rules.buckets]

        # Find all rules that don't have hits and are still enabled
        search = EventRule.search()
        search = search[0:search.count()]
        search = search.filter(
            'bool', must_not=[Q('terms', uuid=rules_with_hits)])

        # Filter by certain actions
        if len(self.event_rule_silent_actions) > 0:

            # Create an or filter
            or_filter = Q('bool', should=[])

            # Add each action to the or filter
            for action in self.event_rule_silent_actions:
                if action in SUPPORTED_ACTIONS:
                    or_filter.should.append(Q('term', **{action: True}))

            # Add the or filter to the search
            search = search.filter(or_filter)

        # Exclude protected rules
        search = search.filter('bool', must_not=[Q('term', protected=True)])

        # Only if the rule hasn't been updated in the last N days
        search = search.filter('range', updated_at={
            'lte': f"now-{self.event_rule_silent_days}d"})

        search = search.filter('term', active=True)

        rules = search.scan()

        # Disable the rules
        for rule in rules:
            rule.active = False
            if not hasattr(rule, 'tags'):
                rule.tags = ['Silent Rule']
            else:
                if rule.tags is None:
                    rule.tags = ['Silent Rule']
                else:
                    if 'Silent Rule' not in rule.tags:
                        rule.tags.append('Silent Rule')
            rule.save(refresh=True)

    @check_lock
    def check_high_volume_event_rules(self):
        '''
        Sets the high_volume_rule value to true if a rule exceeds 
        N events in the last N days
        '''
        self.logger.info('Checking high volume event rules')

        # Create the search
        events = Event.search()

        # Filter by time range now-Nd
        events = events.filter('range', created_at={
            'gte': f"now-{self.event_rule_high_volume_days}d"})

        # Aggregate count of event rule uuids from the events index
        events.aggs.bucket('event_rules', 'terms',
                           field='event_rules', size=10000)

        # Set the size to 0 so we don't get any events back
        events = events[0:0]

        # Run the search
        results = events.execute()

        # Create a list of rules with hits > N
        rules_with_high_hits = [
            b.key for b in results.aggregations.event_rules.buckets if b.doc_count > self.event_rule_high_volume_hits]

        # Create a list of rules with hits < N
        rules_withlow_hits = [
            b.key for b in results.aggregations.event_rules.buckets if b.doc_count < self.event_rule_high_volume_hits]

        # Find all rules that have hits > N and are still enabled and set the high_volume_rule flag
        search = EventRule.search()
        search = search[0:search.count()]
        search = search.filter(
            'bool', must=[Q('terms', uuid=rules_with_high_hits)])
        search = search.filter('term', active=True)
        rules = search.scan()

        # Set the high_volume_rule value to true
        for rule in rules:
            rule.update(high_volume_rule=True)

        # Find all teh rules that have hits < N thave also had high_volume_rule set to true
        # and clear the flag as the volume has dropped
        search = EventRule.search()
        search = search[0:search.count()]
        search = search.filter(
            'bool', must=[Q('terms', uuid=rules_withlow_hits)])
        search = search.filter('term', active=True)
        search = search.filter('term', high_volume_rule=True)
        rules = search.scan()

        # Set the high_volume_rule value to false
        for rule in rules:
            rule.update(high_volume_rule=False)

    def prune_old_agents(self):
        ''' Automatically removes any agents that have not actively
        talked to the system in a number of days

        Parameters:
            days_back (int): How long since the agent last communicated
        '''
        self.logger.info('Checking for old agents to prune')

        days_ago = datetime.datetime.utcnow(
        ) - datetime.timedelta(days=self.agent_prune_lifetime)

        search = Agent.search()
        search = search[0:search.count()]
        # search = search.filter('range', last_heartbeat={
        #                    'lte': days_ago.isoformat()
        #                })

        #search = search.filter('bool', should=[Q('wildcard', external_id__keyword=f"{args.external_id__like.upper()}*"), Q('wildcard', name=f"*{args.name__like}*")])
        search = search.filter('bool', should=[Q('range', last_heartbeat={
                               'lte': days_ago.isoformat()}), Q('bool', must_not=[Q('exists', field='last_heartbeat')])])

        agents = [a for a in search.scan()]

        for agent in agents:

            self.logger.info(
                f"Deleting agent {agent.name}, last heartbeat exceeds threshold of {self.agent_prune_lifetime} days")

            # Remove the agent from the Agent Role
            agent_role = Role.get_by_member(agent.uuid)
            if agent_role:
                agent_role.remove_user_from_role(agent.uuid)

            # Remove the agent from the Agent Groups
            agent_group = AgentGroup.get_by_member(agent.uuid)
            if agent_group:
                if isinstance(agent_group, list):
                    for group in agent_group:
                        group.remove_agent(agent.uuid)
                else:
                    agent_group.remove_agent(agent.uuid)

            # Flag the agents benchmark results as archived
            archive_agent_results(BenchmarkResult, agent.uuid)
            archive_agent_results(BenchmarkResultHistory, agent.uuid)

            # Remove the agent from the Agent Group
            agent.delete()

        return True

    def prune_old_tasks(self):
        ''' Automatically prunes tasks that have completed for failed to complete
        in the last N days

        Parameters:
            days_back (int): How long since the task was completed
        '''

        days_ago = datetime.datetime.utcnow(
        ) - datetime.timedelta(days=self.task_prune_lifetime)

        search = Task.search()
        search = search.filter('range', created_at={
            'lte': days_ago.isoformat()
        })
        search.delete()

    def prune_old_benchmark_results(self):
        ''' Removes old benchmark history where the entry is greater than 1 year old'''

        organizations = Organization.search()

        for organization in organizations.scan():

            self.logger.info(f"Removing old benchmarks for {organization.uuid}")

            settings = Settings.load(organization.uuid)

            days_ago = datetime.datetime.utcnow(
            ) - datetime.timedelta(days=settings.benchmark_history_retention)

            search = BenchmarkResult.search()

            search = search.filter('term', organization=organization.uuid)

            search = search.filter('term', archived=True)

            # Find all benchmark results that are older than 1 year
            search = search.filter('range', assessed_at={
                'lte': days_ago.isoformat()
            })

            search.delete()

    def lock_old_users(self, days_back=90):
        ''' Automatically locks users that have not used the system in
        the last N days

        Parameters:
            days_back (int): How long since the user last used the account
        '''
        raise NotImplementedError

    def force_password_change(self, days_since=90):
        ''' Sets the password reset required flag on a user in the system
        if the last time they set their password is greater than days_since

        Parameters:
            days_since (int): How long its been since they set their password
        '''
        raise NotImplementedError

    def check_for_delayed_detections(self):
        ''' Checks if any detections are delayed and creates a new
        event with all the delayed detections'''

        self.logger.info('Checking for delayed detections')

        # Query all active detections
        detections = Detection.search()
        detections = detections.filter('term', active=True)
        detections = detections.filter('range', last_run={
            'lte': datetime.datetime.utcnow().isoformat()
        })

        detections = detections.scan()
        organizations = {}
        for detection in detections:

            # Using the last_run time and the run interval
            # determine if the detection is more than 1 interval
            # behind

            if detection.organization not in organizations:
                organizations[detection.organization] = {
                    'never_run': [],
                    'delayed': []
                }

            # Ignore detections that have never run
            try:
                if detection.last_run is None:
                        organizations[detection.organization]['never_run'].append(
                            {
                            'name': detection.name,
                            'uuid': detection.uuid,
                            'last_run': detection.last_run,
                            'next_run': now,
                            'lag': f'0',
                            'lag_as_seconds': 0,
                        })
            except Exception as e:
                self.logger.error(f"Error processing detection {detection.name}, {detection.uuid}: {e}")
                continue

            
            try:
                now = datetime.datetime.utcnow()
                last_run = detection.last_run
                interval = detection.interval
                _next_run = last_run + datetime.timedelta(minutes=interval)
                _lag = (now - _next_run).total_seconds() / 60
            except Exception as e:
                self.logger.error(f"Failed to compute delay for {detection.name}, {detection.uuid}: {e}")
                continue

            # If the last run is more than 1 hour behind
            # what the next run should be, then we need to
            # create a new event for the delayed detections
            if _lag > 60:
                organizations[detection.organization]['delayed'].append(
                    {
                        'name': detection.name,
                        'uuid': detection.uuid,
                        'last_run': detection.last_run,
                        'next_run': _next_run,
                        'lag': f'{_lag}',
                        'lag_as_seconds': _lag * 60,
                    })
                    
        events = []
        for organization in organizations:
            new_status = EventStatus.get_by_name(name='New', organization=organization)
            for delayed in organizations[organization]['delayed']:
                event = Event(
                    uuid=uuid4(),
                    organization=organization,
                    title=f"Detection Rule Delayed - {delayed['name']}",
                    detection_id=delayed['uuid'],
                    risk_score=80,
                    severity=3,
                    description=f"The detection rule {delayed['name']} is active and is delayed by more than {delayed['lag']} minutes. Should have run at {delayed['next_run']}.",
                    tags=['detection-delayed'],
                    raw_log=json.dumps(delayed, default=str),
                    status=new_status,
                    tlp=1,
                    reference=uuid4(),
                    source='reflex-system',
                    signature=sha1(f"{delayed['name']}.{delayed['uuid']}".encode()).hexdigest(),
                    original_date=datetime.datetime.utcnow(),
                    created_at=datetime.datetime.utcnow(),
                    category='detection-monitor'
                )
                events.append(event)

            for never_run in organizations[organization]['never_run']:
                event = Event(
                    uuid=uuid4(),
                    organization=organization,
                    title=f"Detection Rule Never Run - {never_run['name']}",
                    detection_id=never_run['uuid'],
                    risk_score=80,
                    severity=3,
                    description=f"The detection rule {never_run['name']} is active and has never run.",
                    tags=['detection-never-run'],
                    raw_log=json.dumps(never_run, default=str),
                    status=new_status,
                    tlp=1,
                    reference=uuid4(),
                    source='reflex-system',
                    signature=sha1(f"{never_run['name']}.{never_run['uuid']}".encode()).hexdigest(),
                    original_date=datetime.datetime.utcnow(),
                    created_at=datetime.datetime.utcnow(),
                    category='detection-monitor'
                )
                events.append(event)

        Event.bulk(events)
