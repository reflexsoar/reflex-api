"""Reflex Models Module

This module contains all the data models for documents used by the Reflex system and stored
in the Elasticsearch or Opensearch backend.
"""

import os

from app.utils.memcached import MemcachedClient

mc = None
if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') and os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT'):
    mc = MemcachedClient(host=os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST'), port=os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT'))

memcached_client = mc

if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl.utils import AttrList
    
    from opensearch_dsl import (
        Document,
        InnerDoc,
        Date,
        Integer,
        Long,
        Keyword,
        Text,
        Boolean,
        Nested,
        Ip,
        Object,
        Float,
        A,
        Search,
        Nested,
        Q,
        UpdateByQuery,
        Binary,
        analyzer
    )
    from opensearchpy.helpers import bulk
else:
    from elasticsearch_dsl.utils import AttrList
    from elasticsearch_dsl import (
        Document,
        InnerDoc,
        Date,
        Integer,
        Long,
        Keyword,
        Text,
        Boolean,
        Nested,
        Ip,
        Object,
        Float,
        A,
        Search,
        Nested,
        Q,
        UpdateByQuery,
        Binary,
        analyzer
    )
    from elasticsearch.helpers import bulk

from .user import User, Role, ExpiredToken, Organization, ServiceAccount
from .agent import Agent, AgentGroup, AgentPolicy, AgentLogMessage
from .inout import Input, FieldMappingTemplate, VALID_DATA_TYPES
from .threat import ThreatList, ThreatValue
from .event import Event, EventRule, EventStatus, EventComment, EventView, EventRelatedObject
from .case import (
    Case,
    CaseComment,
    CaseHistory,
    CaseStatus,
    CaseTask,
    TaskNote,
    CaseTemplate,
    CaseTemplateTask,
    CloseReason
)
from .plugin import Plugin, PluginConfig
from .credential import Credential
from .system import Tag, DataType, Settings, Observable, EventLog, ObservableHistory, APINodeMetric
from .detection import (
    Detection,
    DetectionLog,
    DetectionRepositoryToken,
    DetectionRepository,
    DetectionRepositoryBundle,
    DetectionRepositorySubscription,
    DetectionState,
    RepositorySyncLog
)
from .task import Task
from .mitre import MITRETactic, MITRETechnique
from .notification import EmailNotificationTemplate, NotificationChannel, Notification, NOTIFICATION_CHANNEL_TYPES, SOURCE_OBJECT_TYPE
from .asset import Asset, UserAsset, GroupAsset, ComputerAsset, NetworkInterface, OperatingSystem
from .integration import Integration, IntegrationConfiguration, IntegrationLog, IntegrationActionQueue
from .sso import SSOProvider, RoleMappingPolicy
from .package import Package
from .data_source import DataSourceTemplate, DataSourceDefinition
from .schedule import Schedule
from .fim import FimRule
from .tag import AgentTag
from .benchmark import (
    BenchmarkRule,
    BenchmarkRuleset,
    BenchmarkException,
    BenchmarkResultHistory,
    BenchmarkResult,
    BenchmarkFrameworkRule
)

from .search import (
    SearchProxyJob
)

from .application import (
    ApplicationInventory
)

VERSION = (2, 0, 0)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))
__all__ = [
    'User',
    'Role',
    'ExpiredToken',
    'Agent',
    'AgentGroup',
    'AgentPolicy',
    'AgentLogMessage',
    'Input',
    'FieldMappingTemplate',
    'Tag',
    'DataType',
    'ThreatList',
    'Settings',
    'Event',
    'EventComment',
    'EventRule',
    'EventStatus',
    'Observable',
    'Case',
    'CaseComment',
    'CaseHistory',
    'CaseStatus',
    'CaseTask',
    'CaseTemplate',
    'CaseTemplateTask',
    'CloseReason',
    'Plugin',
    'PluginConfig',
    'EventLog',
    'Credential',
    'TaskNote',
    'Search',
    'Organization',
    'ObservableHistory',
    'Detection',
    'DetectionLog',
    'DetectionRepositoryToken',
    'DetectionRepository',
    'DetectionRepositoryBundle',
    'DetectionState',
    'Task',
    'ThreatValue',
    'MITRETactic',
    'MITRETechnique',
    'EventView',
    'NotificationChannel',
    'Notification',
    'EmailNotificationTemplate',
    'ServiceAccount',
    'Asset',
    'UserAsset',
    'GroupAsset',
    'ComputerAsset',
    'NetworkInterface',
    'OperatingSystem',
    'NOTIFICATION_CHANNEL_TYPES',
    'SOURCE_OBJECT_TYPE',
    'memcached_client',
    'Ip',
    'VALID_DATA_TYPES',
    'Integration',
    'IntegrationConfiguration',
    'IntegrationLog',
    'IntegrationActionQueue',
    'SSOProvider',
    'RoleMappingPolicy',
    'Binary',
    'Package',
    'analyzer',
    'DataSourceTemplate',
    'DataSourceDefinition',
    'Schedule',
    'FimRule',
    'AgentTag',
    'BenchmarkRule',
    'BenchmarkRuleset',
    'BenchmarkException',
    'BenchmarkResultHistory',
    'BenchmarkResult',
    'BenchmarkFrameworkRule',
    'EventRelatedObject',
    'SearchProxyJob',
    'ApplicationInventory',
    'bulk',
    'APINodeMetric'
]