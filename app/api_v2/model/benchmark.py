from enum import Enum

from . import (
    InnerDoc,
    Keyword,
    Text,
    Boolean,
    Integer,
    base,
    Object,
    Date,
    Q,
    UpdateByQuery
)

class platform(Enum):
    WINDOWS = 'windows'
    LINUX = 'linux'
    MACOS = 'macos'
    IOS = 'ios'
    ANDROID = 'android'
    CISCO_IOS = 'cisco-ios'
    CISCO_IOS_XR = 'cisco-ios-xr'
    CISCO_NX_OS = 'cisco-nx-os'
    JUNOS = 'junos'
    PAN_OS = 'pan-os'
    F5_BIG_IP = 'f5-big-ip'
    VMWARE_ESXI = 'vmware-esxi'
    FORTINET_FORTIOS = 'fortinet-fortios'


class status(Enum):
    PASSED = 'passed'
    FAILED = 'failed'
    ERROR = 'error'
    SKIPPED = 'skipped'

BENCHMARK_STATUSES = [status.PASSED.value, status.FAILED.value, status.ERROR.value, status.SKIPPED.value]


class BenchmarkAssessScript(InnerDoc):
    '''
    Contains the script to assess a benchmark rule
    '''
    script = Keyword(fields={'text': Text()})  # Prerequisites for the rule
    language = Keyword(fields={'text': Text()})  # The type of script, e.g. powershell, bash, etc.
    args = Keyword(fields={'text': Text()})  # Arguments to pass to the script
    success = Integer()  # The expected success code from the script


class BenchmarkRemediationScript(InnerDoc):
    '''
    Contains the script to remediate a benchmark rule
    '''
    script = Keyword(fields={'text': Text()})  # The remediation script
    language = Keyword(fields={'text': Text()})  # The type of remediation script
    args = Keyword(fields={'text': Text()})  # Arguments to pass to the remediation script
    success = Integer()  # The expected success code from the script

class BenchmarkFrameworkRule(base.BaseDocument):
    '''
    Defines a Framework Control rule for a Benchmark Framework.'''
    benchmark_name = Keyword(fields={'text': Text()})  # The name of the benchmark
    benchmark_version = Keyword(fields={'text': Text()})  # The version of the benchmark
    platform = Keyword(fields={'text': Text()})  # The platforms the rule applies to, e.g. Windows, Linux, etc.
    control_name = Keyword(fields={'text': Text()})  # The name of the control
    control_id = Keyword(fields={'text': Text()})  # The ID of the control
    control_description = Keyword(fields={'text': Text()})  # The description of the control
    control_rationale = Keyword(fields={'text': Text()})  # The rationale of the control
    control_remediation = Keyword(fields={'text': Text()})  # The remediation of the control
    control_impact = Keyword(fields={'text': Text()})  # The impact of the control
    control_references = Keyword(fields={'text': Text()})  # The references of the control
    control_audit = Keyword(fields={'text': Text()})  # The audit of the control
    framework = Keyword(fields={'text': Text()})  # The frameworks the rule applies to, e.g. NIST, CIS, etc.
    is_automated = Boolean()  # Whether or not the rule is automated

    class Index:
        name = 'reflex-benchmark-framework-rules'
        settings = {
            'refresh_interval': '5s',
        }


class BenchmarkRule(base.BaseDocument):
    '''
    Defines a Benchmark Rule.  Benchmark Rules are used for 
    assessing the posture of an agent against a compliance framework
    or single benchmark.'''

    rule_id = Keyword(fields={'text': Text()})  # A persistent unique identifier for the rule
    name = Keyword(fields={'text': Text()})  # The name of the rule
    description = Keyword(fields={'text': Text()})  # A description of the rule
    platform = Keyword(fields={'text': Text()})  # The platforms the rule applies to, e.g. Windows, Linux, etc.
    assess = Object(BenchmarkAssessScript)  # The script to assess the rule
    remediate = Object(BenchmarkRemediationScript)  # The script to remediate the rule
    risk_score = Integer()  # The risk score of the rule
    secure_score = Integer()  # The secure score of the rule from 1 to 10
    severity = Integer() # The severity of the rule
    auto_remediate = Boolean()  # Whether or not the rule should be automatically remediated
    category = Keyword(fields={'text': Text()})  # The category of the rule
    framework = Keyword(fields={'text': Text()})  # The frameworks the rule applies to, e.g. NIST, CIS, etc.
    version = Integer()  # The version of the rule
    system_managed = Boolean()  # Whether or not the rule is managed by the system
    current = Boolean()  # Whether or not the rule is the current version

    class Index:
        name = 'reflex-benchmark-rules'
        settings = {
            'refresh_interval': '5s',
        }

class BenchmarkRuleset(base.BaseDocument):
    '''
    Defines a Benchmark Ruleset.  Benchmark Rulesets are used for grouping
    benchmark rules together for easier management and assignment to agents.
    '''

    name = Keyword(fields={'text': Text()})  # The name of the ruleset
    rules = Keyword(fields={'text': Text()})  # A list of rule_ids that are in the ruleset
    description = Keyword(fields={'text': Text()})  # A description of the ruleset
    system_managed = Boolean()  # Whether or not the ruleset is managed by the system

    class Index:
        name = 'reflex-benchmark-rulesets'
        settings = {
            'refresh_interval': '5s',
        }

class BenchmarkException(base.BaseDocument):
    '''
    Defines a Benchmark Exception.  Benchmark Exceptions are used for 
    excluding agents from being assessed against a benchmark rule.
    '''

    agent = Keyword(fields={'text': Text()})  # A list of agents to exclude from the rule
    rule_id = Keyword(fields={'text': Text()})  # The rule ID the exception is for
    justification = Keyword(fields={'text': Text()})  # The reason for the exception
    additional_notes = Keyword(fields={'text': Text()})  # Additional notes for the exception
    all_assets = Boolean()  # Whether or not the exception applies to all assets
    expires = Boolean()  # Whether or not the exception expires
    expires_at = Date()  # The timestamp the exception expires
    rule_version = Integer()  # The version of the rule

    class Index:
        name = 'reflex-benchmark-exceptions'
        settings = {
            'refresh_interval': '5s',
        }

class BenchmarkResultHistory(base.BaseDocument):
    '''
    Tracks the historical status of a benchmark rule on an agent
    '''

    agent = Keyword(fields={'text': Text()})  # The agent UUID the result is for
    rule_id = Keyword(fields={'text': Text()})  # The rule ID the result is for
    rule_uuid = Keyword(fields={'text': Text()})  # The rule UUID the result is for
    status = Keyword(fields={'text': Text()})  # The status of the rule, e.g. pass, fail, etc.
    output = Keyword(fields={'text': Text()})  # The output of the rule if any
    rule_version = Integer()  # The version of the rule
    assessed_at = Date()  # The timestamp of the result
    archived = Boolean()  # Whether or not the result has been archived

    class Index:
        name = 'reflex-benchmark-results-history'
        settings = {
            'refresh_interval': '5s',
        }
        version = "0.1.5"

    def archive_agent_results(self, agent_uuid):
        '''
        Archives all results for an agent
        '''
        
        update_query = UpdateByQuery(
            index=BenchmarkResultHistory.Index.name,
            conflicts='proceed',
            refresh=True
        ).query(
            'bool',
            must=[
                Q('term', agent=agent_uuid),
                Q('term', archived=False)
            ]
        ).script(
            source='ctx._source.archived = true'
        )

        update_query.execute()

class BenchmarkResult(base.BaseDocument):
    '''
    Tracks the current status of a benchmark rule on an agent
    '''

    agent = Keyword(fields={'text': Text()})  # The agent UUID the result is for
    rule_id = Keyword(fields={'text': Text()})  # The rule ID the result is for (persistent id)
    rule_uuid = Keyword(fields={'text': Text()})  # The rule UUID the result is for (version id)
    status = Keyword(fields={'text': Text()})  # The status of the rule, e.g. pass, fail, etc.
    output = Keyword(fields={'text': Text()})  # The output of the rule if any
    assessed_at = Date()  # The timestamp of the result
    rule_version = Integer()  # The version of the rule
    archived = Boolean()  # Whether or not the result has been archived

    class Index:
        name = 'reflex-benchmark-results'
        settings = {
            'refresh_interval': '1s',
        }

    def create_history_entry(self):
        '''
        Creates an entry for the current result to the history index
        '''
        historical_result = BenchmarkResultHistory(
            agent=self.agent,
            rule_id=self.rule_id,
            rule_uuid=self.rule_uuid,
            status=self.status,
            output=self.output,
            assessed_at=self.assessed_at,
            rule_version=self.rule_version
        )
        historical_result.save()

def archive_agent_results(result_class, agent_uuid):
    '''
    Archives all results for an agent
    '''
    
    update_query = UpdateByQuery(
        index=result_class.Index.name,
        conflicts='proceed',
        refresh=True
    ).query(
        'bool',
        must=[
            Q('term', agent=agent_uuid),
            Q('term', archived=False)
        ]
    ).script(
        source='ctx._source.archived = true'
    )

    update_query.execute()
