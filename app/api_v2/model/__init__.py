"""Reflex Models Module

This module contains all the data models for documents used by the Reflex system and stored
in the Elasticsearch or Opensearch backend.
"""

import os

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
from .agent import Agent, AgentGroup
from .inout import Input
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
    Input,
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