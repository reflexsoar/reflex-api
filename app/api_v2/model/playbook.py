from .base import BaseDocument

from . import (
    base,
    Integer,
    Boolean,
    Keyword,
    Text,
    Object
)

class Playbook(base.BaseDocument):
    '''
    Playbooks are used to execute actions and custom workflows on events or 
    their underlying properties
    '''

    name = Text()
    description = Text()
    priority = Integer()
    configuration = Object()
    enabled = Boolean()
    item_types = Keyword()
    tags = Keyword()