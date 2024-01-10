import os
import json
import inspect
from typing import List
from uuid import uuid4
from datetime import datetime
from flask_restx import Namespace, Resource
from app.api_v2.model import (
    UpdateByQuery,
    Event,
    EventRelatedObject
)
from app.api_v2.model.case import CloseReason
from app.api_v2.model.threat import ThreatList
from app.api_v2.model.integration import IntegrationConfiguration, IntegrationLog
from app.api_v2.model.utils import IndexedDict

integration_registry = {}


api = Namespace('Integrations', description="Exposes API endpoints for every integration that requires one", path="/integrations")

class IntegrationJob:
    """
    The IntegrationJob class is used to define a job that will be run by either
    a specific agent, a pool of agents or the management console itself
    """
    pass

class IntegrationBase(object):
    """
    Defines a base class that all integrations should inherit from to ensure
    they have the required methods and properties and can easily integrate
    in to the Reflex ecosystem
    """

    def __init__(self, *args, **kwargs):

        self.manifest = None
        self.load_manifest()

        self.name = self.manifest.get('name', '')
        self.product_identifier = self.manifest.get('product_identifier', '')
        self.version = self.manifest.get('version', '1.0.0')
        self.description = self.manifest.get('description', '')
        self.author = self.manifest.get('author', '')
        self.contributor = self.manifest.get('contributor', [])
        self.license = self.manifest.get('license', '')
        self.configuration = self.manifest.get('configuration', {})
        self.unique_name = self.manifest.get('unique_name', f"{self.name}".replace(' ','_').lower())
        self.actions = {}

        self.setup_routes()
        self.register_integration()
        self.register_actions()

    def register_integration(self):
        integration_registry[self.product_identifier] = self

    def register_actions(self):
        """
        Locate any self method that starts with action_ and place it
        in a dictionary of actions where the key is the function name
        after action_
        """
        self.actions = {}
        for name, method in inspect.getmembers(self):
            if name.startswith('action_'):
                self.actions[name.replace('action_', '')] = method

    def run_action(self, action, *args, **kwargs):
        """
        Runs a specific action
        """
        if action not in self.actions:
            self.log_message(f"Action {action} not found", kwargs.get('configuration_uuid'), kwargs.get('configuration_name'), level='ERROR', action=action)
            raise ValueError(f"Action {action} not found")

        self.log_message(f"Running action {action}", kwargs.get('configuration_uuid'), kwargs.get('configuration_name'), action=action)
        return self.actions[action](*args, **kwargs)
    
    def flatten_dict(self, data):
        """
        Flattens a dictionary into a single level dictionary
        """
        return IndexedDict(data)
    
    def dict_as_markdown_table(self, data):
        """
        Converts a dictionary in to a markdown table with the first column as
        keys and the second column as their value
        """

        def format_value(v):
            if isinstance(v, str) and '\n' in v:
                return v.replace('\n', '<br>')
            if isinstance(v, (int, float)):
                return str(v)
            return v

        # Always flatten the dictionary first
        data = self.flatten_dict(data)

        table = "Field | Value\n| --- | --- |\n"
        for key, value in data.items():

            value = format_value(value)

            if isinstance(value, list):
                value = '<br>'.join(format_value(v) for v in value)

            table += f"| **{key}** | {value} |\n"

        return table
    
    def log_message(self, message, configuration_uuid, configuration_name=None, level='INFO', action=None):
        """
        Logs a message to the integration log
        """
        log = IntegrationLog()
        log.action = action
        log.level = level
        log.configuration_uuid = configuration_uuid
        log.configuration_name = configuration_name
        log.integration_uuid = self.product_identifier
        log.integration_name = self.name
        log.message = message
        log.save()

    def add_output_to_event(self, events, action, configuration, output, output_format='json'):
        """
        Creates an entry on the events integration_output field
        """

        entry = {
            "action": action,
            "integration_uuid": self.product_identifier,
            "integration_name": self.name,
            "configuration_name": configuration.name,
            "configuration_uuid": configuration.uuid,
            "output": output,
            "output_format": output_format,
            "created_at": datetime.utcnow().isoformat()+"Z",
        }

        query = UpdateByQuery(index=Event._index._name)
        query = query.filter('terms', uuid=events)

        # Using painless script
        # Add the entry to the integration_output array if it already exists
        # if it does not exist, create the array and add the entry
        query = query.script(
            source="""
                if (ctx._source.containsKey('integration_output')) {
                    ctx._source.integration_output.add(params.entry)
                } else {
                    ctx._source.integration_output = [params.entry]
                }
            """,
            params={
                "entry": entry
            }
        )

        try:
            query.execute()
        except Exception as e:
            self.log_message(f"Error adding output to event: {e}", configuration.uuid, configuration.name, level='ERROR')
            raise e
            

    def load_configuration(self, configuration_uuid):
        """
        Loads the configuration for the integration
        """
        configuration = IntegrationConfiguration.search()
        configuration = configuration.filter('term', uuid=configuration_uuid)
        configuration = configuration.filter('term', integration_uuid=self.product_identifier)
        configuration = configuration.execute()

        if not configuration:
            raise Exception(f"Configuration with UUID {configuration_uuid} not found")
        
        return configuration[0]

    def load_manifest(self):
        """
        Loads the manifest file for the integration
        """
        
        # Find the path of the module that inherits from this class
        dir_path = os.path.dirname(inspect.getfile(self.__class__))
        
        # Load the manifest file
        try:
            with open(f"{dir_path}/manifest.json", "r") as f:
                self.manifest = json.load(f)
        except FileNotFoundError:
            pass

    def _events_to_list(self, events):

        _events = []

        if isinstance(events, Event):
            _events = [events]

        if isinstance(events, list):
            # If any events are not Event objects, remove them from the list
            _events = [event for event in events if isinstance(event, Event)]

        return _events
    
    def get_value_from_source_field(self, source_field, event):
        """
        Returns the value of a source field from an event
        """

        try:
            event.raw_log = json.loads(event.raw_log)
        except json.JSONDecodeError:
            pass

        # Flatten the event
        event = self.flatten_dict(event.to_dict())

        if source_field in event:
            return event[source_field]
        return None    
    
    def extract_observables_by_type(self, events, observable_data_type):
        """
        Returns the observables of a specific type from the events
        """
        observables = []
        for event in events:
            for observable in event.observables:
                if observable['data_type'] == observable_data_type:
                    observables.append(observable)
        return observables
    
    def close_event(self, events, reason, comment):
        """
        Closes the event
        """

        try:

            events = self._events_to_list(events)

            query = UpdateByQuery(index=Event._index._name)
            query = query.filter('terms', uuid=[event.uuid for event in events])

            if reason is None:
                reason = 'Other'
            else:
                reason = CloseReason.get_by_uuid(reason)
                if reason is None:
                    reason = 'Other'

            # Using painless script
            # Close the event
            script = {
                "source": """
                    ctx._source.status.name = 'Dismissed';
                    ctx._source.status.closed = true;
                    ctx._source.dismissed_at = params.dismissed_at;
                    ctx._source.dismissed_by = params.dismissed_by;
                    ctx._source.dismiss_reason = params.reason;
                    ctx._source.dismiss_comment = params.comment;
                """,
                "lang": "painless",
                "params": {
                    "reason": reason,
                    "comment": comment,
                    "dismissed_at": datetime.utcnow(),
                    "dismissed_by": {'username': f"{self.__class__.__name__} integration"}
                }
            }
            
            query = query.script(**script)
            query.execute()
        except Exception:
            return False
        return True


    def load_events(self, **kwargs):

        events = Event.search()
        for key, value in kwargs.items():
            if isinstance(value, list):
                events = events.filter('terms', **{key: value})
            else:
                events = events.filter('term', **{key: value})

        results = events.scan()
        return [r for r in results]
    
    def set_event_integration_attribute(self, events, attributes):
        """
        Sets the integration attribute for the event
        """

        events = self._events_to_list(events)

        query = UpdateByQuery(index=Event._index._name)
        query = query.filter('terms', uuid=[event.uuid for event in events])

        # Using painless script
        # Add the integration attribute to the event, if the integration_attributes field doesn't exist, create it

        script = {
            "source": """
                if (ctx._source.containsKey('integration_attributes')) {
                    ctx._source.integration_attributes.putAll(params.integration_attributes);
                } else {
                    ctx._source.integration_attributes = params.integration_attributes;
                }
            """,
            "lang": "painless",
            "params": {
                "integration_attributes": attributes
            }
        }

        query = query.script(**script)
        query.execute()

    def add_event_comment_as_artifact(self, events, comment, created_by=None, action=None, configuration=None):
        """
        Adds a comment as an Event artifact to all provided events.
        """

        _comments = []
        for event in events:
            _comment = {
                'event': {
                    'uuid': event.uuid,
                    'organization': event.organization,
                },
                'entry': {
                    'type': 'comment'
                },
                'uuid': str(uuid4()),
                'comment': {
                    'uuid': str(uuid4()),
                    'comment': comment,
                    'created_at': datetime.utcnow(),
                    'created_by': created_by if created_by else f"{self.__class__.__name__} integration",
                    'organization': event.organization
                },
                'integration': {
                    'uuid': self.product_identifier,
                    'name': self.name,
                    'action': action,
                    'configuration': configuration

                },
                'organization': event.organization,
                'created_by': {
                    'username': created_by if created_by else f"{self.__class__.__name__} integration"
                },
                'created_at': datetime.utcnow()
            }

            _comments.append(_comment)

        EventRelatedObject.bulk(_comments)


    def add_event_comment(self, events, comment, created_by=None):
        """
        Adds a comment to one more events
        DEPRECATION WARNING: This method will be removed in a future release
        in favor of comments being added as artifacts instead of directly
        to the event.
        """

        events = self._events_to_list(events)

        if len(events) > 0:
            # Use a bulk update to add the comment to each event
            query = UpdateByQuery(index=Event._index._name)
            query = query.filter('terms', uuid=[event.uuid for event in events])

            # Using painless script
            # Create the comment object
            # Add the comment to the event, if the comments field doesn't exist, create it

            script = {
                "source": """
                    def comment = new HashMap();
                    comment.put('uuid', UUID.randomUUID().toString());
                    comment.put('comment', params.comment);
                    comment.put('organization', ctx._source.organization);
                    comment.put('created_by', params.created_by);
                    comment.put('created_at', params.created_at);
                    if (ctx._source.containsKey('comments')) {
                        ctx._source.comments.add(comment);
                    } else {
                        ctx._source.comments = [comment];
                    }
                """,
                "lang": "painless",
                "params": {
                    "comment": comment,
                    "created_by": created_by if created_by else f"{self.__class__.__name__} integration",
                    "created_at": datetime.utcnow()
                }
            }

            query = query.script(**script)

            query.execute()

    def create_intel_list(self, list_name: str, list_type: str, data_type: str, values: List[str]) -> str:
        """
        Creates an Intel List and returns the UUID
        """

        if list_type not in ['values','regex','csv']:
            raise ValueError(f"Invalid list type {list_type}")

        tl = ThreatList(
            name=list_name,
            description=f"Created by {self.__class__.__name__} integration",
            type=list_type,
            data_type_name=data_type,
        )

        tl.save()

        tl.set_values(values)
        
        return tl.uuid

    def setup_routes(self):
        """
        Locates at any sub-class of IntegrationBase that inherits from
        Resource and loads it in to the api
        """
        
        # Find all classes that are a subclass of Resource
        for _, cls in inspect.getmembers(self, inspect.isclass):
            if issubclass(cls, Resource):

                # Prepend the path with the product identifier and version
                cls.path = f"/{self.unique_name}/{self.version}{cls.path}"
                
                # Add the class to the api and include its docstring
                api.add_resource(cls, cls.path)

