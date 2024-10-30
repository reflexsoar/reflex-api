""" Defines a Pydantic model for validating Integration
manifests against a standard schema."""

import re
from enum import Enum
from typing import Optional, Union, List, Dict, Literal
from pydantic import BaseModel, Field

class ConfigFieldTypes(str, Enum):
    """ Defines the types of configuration fields that can be used in an integration manifest. """

    INT = 'int'
    STR = 'str'
    STR_SELECT = 'str-select'
    BOOL = 'bool'
    STR_MULTIPLE = 'str-multiple'

class ActionTypes(str, Enum):
    """ Defines the types of actions that can be used in an integration manifest. """

    INVENTORY = 'inventory'
    ACTION = 'action'
    INPUT = 'input'
    WEBHOOK = 'webhook'

class ValidTriggers(str, Enum):
    """ Defines the valid triggers when running a scheduled action """

    MANUAL = 'manual'
    SCHEDULE = 'schedule'
    EVENT_RULE = 'event_rule'
    SYSTEM = 'system'

# A normal UUID4 regex
UUID4_REGEX = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'

# Authors should be their name and email address like Name <email@address.com>
AUTHOR_REGEX = r'^[a-zA-Z0-9 ]+<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$'

# Base64 encoded image regex
BASE64_IMAGE_REGEX = r'^data:image\/(png|jpg|jpeg|gif|svg\+xml);base64,[a-zA-Z0-9+/]+={0,2}$'


class ParameterField(BaseModel):

    type: ConfigFieldTypes = Field(..., description="Type of the parameter field")
    required: Optional[bool] = Field(False, description="Whether the parameter field is required")
    default_options_from: Optional[str] = Field(None, description="Name of the configuration field to get default options from")
    observable_data_type: Optional[str] = Field(None, description="Observable data type of the parameter field")
    description: str = Field(..., description="Description of the parameter field")

class ConfigurationField(BaseModel):

    type: str = Field(..., description="Type of the configuration field")
    required: Optional[bool] = Field(False, description="Whether the configuration field is required")
    secret: Optional[bool] = Field(False, description="Whether the configuration field is a secret")
    default: Optional[Union[str,int,float]] = Field(None, description="Default value of the configuration field")
    description: str = Field(..., description="Description of the configuration field")
    options: List[str] = Field([], description="Options for the configuration field")


class Action(BaseModel):

    friendly_name: str = Field(..., description="Friendly name of the action")
    name: str = Field(..., description="Name of the action")
    description: str = Field(..., description="Description of the action")
    type: ActionTypes = Field(..., description="Type of the action")
    run_from: Literal['console','agent'] = Field(..., description="Where the action is run from")
    configuration: Optional[Dict[str, ConfigurationField]] = Field(None, description="Configuration fields for the action")
    parameters: Optional[Dict[str, ParameterField]] = Field(None, description="Parameters for the action")
    trigger: Optional[List[ValidTriggers]] = Field([], description="Trigger for the action")


class Manifest(BaseModel):

    actions: List[Action] = Field(..., description="Actions for the integration")
    configuration: Dict[str, ConfigurationField] = Field(..., description="Configuration fields for the integration")


class Integration(BaseModel):

    name: str = Field(..., description="Name of the integration")
    product_identifier: str = Field(..., description="Product identifier of the integration", pattern=UUID4_REGEX)
    brief_description: str = Field(..., description="Brief description of the integration", max_length=100)
    description: str = Field(..., description="Description of the integration")
    version: str = Field(..., description="Version of the integration", pattern=r'^\d+\.\d+\.\d+$')
    author: str = Field(..., description="Author of the integration", pattern=AUTHOR_REGEX)
    integration_url: Optional[str] = Field(None, description="URL of the integration")
    contributor: List[str] = Field([], description="Contributors to the integration", validator=lambda v: all(re.match(AUTHOR_REGEX, i) for i in v))
    tags: List[str] = Field([], description="Tags for the integration")
    categories: List[str] = Field([], description="Categories for the integration")
    enabled: bool = Field(True, description="Whether the integration is enabled")
    license: Optional[str] = Field(None, description="License of the integration")
    manifest: Manifest = Field(..., description="Manifest of the integration")
    logo: Optional[str] = Field(None, description="Logo of the integration", pattern=BASE64_IMAGE_REGEX)


# Defines a function that takes in a JSON object and validates it
# against the Integration model
def validate_integration(manifest: dict) -> Integration:
    return Integration(**manifest)