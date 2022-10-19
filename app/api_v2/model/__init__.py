"""Reflex Models Module

This module contains all the data models for documents used by the Reflex system and stored
in the Elasticsearch or Opensearch backend.
"""

import os

from app.utils.memcached import MemcachedClient

mc = None
if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') and os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT'):
    mc = MemcachedClient(f"{os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST')}:{os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT')}")

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
        UpdateByQuery
    )
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
        UpdateByQuery
    )

from .user import User, Role, ExpiredToken, Organization
from .agent import Agent, AgentGroup, AgentPolicy
from .inout import Input, FieldMappingTemplate
from .threat import ThreatList, ThreatValue
from .event import Event, EventRule, EventStatus, EventComment, EventView
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
from .system import Tag, DataType, Settings, Observable, EventLog, ObservableHistory
from .detection import (
    Detection,
    DetectionLog,
    DetectionRepositoryToken,
    DetectionRepository,
    DetectionRepositoryBundle
)
from .task import Task
from .mitre import MITRETactic, MITRETechnique
from .notification import NotificationChannel, Notification, NOTIFICATION_CHANNEL_TYPES, SOURCE_OBJECT_TYPE

VERSION = (2, 0, 0)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))
__all__ = [
    User,
    Role,
    ExpiredToken,
    Agent,
    AgentGroup,
    AgentPolicy,
    Input,
    FieldMappingTemplate,
    Tag,
    DataType,
    ThreatList,
    Settings,
    Event,
    EventComment,
    EventRule,
    EventStatus,
    Observable,
    Case,
    CaseComment,
    CaseHistory,
    CaseStatus,
    CaseTask,
    CaseTemplate,
    CaseTemplateTask,
    CloseReason,
    Plugin,
    PluginConfig,
    EventLog,
    Credential,
    TaskNote,
    Search,
    Organization,
    ObservableHistory,
    Detection,
    DetectionLog,
    DetectionRepositoryToken,
    DetectionRepository,
    DetectionRepositoryBundle,
    Task,
    ThreatValue,
    MITRETactic,
    MITRETechnique,
    EventView,
    NotificationChannel,
    Notification,
    NOTIFICATION_CHANNEL_TYPES,
    SOURCE_OBJECT_TYPE
]