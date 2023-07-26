import os
import json
import inspect
from uuid import uuid4
from datetime import datetime
from flask_restx import Namespace, Resource
from app.api_v2.model import (
    UpdateByQuery,
    Event
)

from app.api_v2.model.integration import IntegrationConfiguration


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

        self.setup_routes()

    def load_configuration(self, configuration_uuid):
        """
        Loads the configuration for the integration
        """
        configuration = IntegrationConfiguration.search()
        configuration = configuration.filter('term', uuid=configuration_uuid)
        configuration = configuration.filter('term', integration_uuid=self.uuid)
        configuration = configuration.execute()

        return configuration        

    def load_manifest(self):
        """
        Loads the manifest file for the integration
        """
        
        # Find the path of the module that inherits from this class
        dir_path = os.path.dirname(inspect.getfile(self.__class__))
        
        # Load the manifest file
        with open(f"{dir_path}/manifest.json", "r") as f:
            self.manifest = json.load(f)

    def _events_to_list(self, events):

        _events = []

        if isinstance(events, Event):
            _events = [events]

        if isinstance(events, list):
            # If any events are not Event objects, remove them from the list
            _events = [event for event in events if isinstance(event, Event)]

        return _events
    
    def close_event(self, events, reason, comment):
        """
        Closes the event
        """

        events = self._events_to_list(events)
        print(events)

    def load_events(self, **kwargs):

        events = Event.search()
        for key, value in kwargs.items():
            if isinstance(value, list):
                events = events.filter('terms', **{key: value})
            else:
                events = events.filter('term', **{key: value})

        print(json.dumps(events.to_dict(), indent=4, default=str))
        results = events.scan()
        return [r for r in results]
    
    def set_event_integration_attribute(self, events, attributes):
        """
        Sets the integration attribute for the event
        """

        print(f"EVENTS: {events}")

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


    def add_event_comment(self, events, comment, created_by):
        """
        Adds a comment to one more events
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
                    "created_by": f"{created_by} via {self.__class__.__name__} integration",
                    "created_at": datetime.utcnow()
                }
            }

            query = query.script(**script)

            query.execute()

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

