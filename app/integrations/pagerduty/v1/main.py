from flask_restx import Resource, fields

from app.integrations.base import IntegrationBase, IntegrationApi

from requests import Session

mod_webhook_payload = IntegrationApi.model('WebhookPayload', {
})

mod_create_incident = IntegrationApi.model('CreateIncident', {
    'events': fields.List(fields.String)
})

mod_test = IntegrationApi.model('Test', {
    'test': fields.String
})

class PagerDuty(IntegrationBase):


    def action_create_incident(self, events, configuration_uuid, *args, **kwargs):
        """
        Creates an incident in PagerDuty
        """

        configuration = self.load_configuration(configuration_uuid)

        global_settings = configuration.global_settings.to_dict()

        create_incident_config = configuration.actions.create_incident
        create_incident_config = create_incident_config.to_dict()

        pager_duty_api_key = global_settings['api_access_key']
        incident_key_field = create_incident_config['incident_key_field']
        service_id = create_incident_config['service_id']
        incident_from = create_incident_config['from']

        if 'from_event_rule' in kwargs and kwargs['from_event_rule']:
            _events = events
        else:
            _events = self.load_events(uuid=events)

        # Group all the events by the incident_key_field
        grouped_events = {}

        for event in _events:
            key_value = self.get_value_from_source_field(incident_key_field, event)
            if key_value not in grouped_events:
                grouped_events[key_value] = []
            grouped_events[key_value].append(event)

        # Create a new session to use for the PagerDuty API calls
        session = Session()
        session.headers.update({
            "Authorization": f"Token token={pager_duty_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "From": incident_from
        })

        # Iterate over the grouped events and create an incident for each
        for incident_key, events in grouped_events.items():

            observables = []

            # Iterate over the events and create a list of related observables
            for event in events:
                for o in event.observables:
                    if o not in observables:
                        observables.append(f"- {o.data_type}: {o.value}\n")

            incident_body = {
                "incident": {
                    "type": "incident",
                    "title": events[0].title,
                    "service": {
                        "id": service_id,
                        "type": "service_reference"
                    },
                    "incident_key": incident_key,
                    "body": {
                        "type": "incident_body",
                        "details": f"""{len(events)} events were detected for this incident.\n
Description:
{events[0].description}\n
Related Observables:\n
{''.join(observables)}
                        """
                    }
                }
            }

            
            # Try to create a new incident in PagerDuty
            response = session.post("https://api.pagerduty.com/incidents", json=incident_body)
            if response.status_code == 201:

                incident = response.json()['incident']

                # For all of the events for this incident_key update the events using
                # set the pagerduty.incident_key attribute
                pagerduty.set_event_integration_attribute(events, attributes={'pagerduty': {
                            'incident_key': incident_key,
                            'incident_id': incident['id'],
                            'url': incident['html_url']
                        }
                    })

    class CreateIncident(Resource):

        # TODO: Add authentication and authorization to this endpoint

        path = "/create_incident/<string:configuration_uuid>"
        @IntegrationApi.expect(mod_create_incident)
        def post(self, configuration_uuid):
            """
            Creates a new incident by looking for the events provided in the
            POST payload and deduping them by the incident_key_field defined
            in the integration configuration
            """

            if 'events' in IntegrationApi.payload:
                pagerduty.create_incident(IntegrationApi.payload['events'], configuration_uuid)

            return "OK"


    class WebHookResource(Resource):
        path = "/webhook/<string:configuration_uuid>"

        @IntegrationApi.expect(mod_webhook_payload)
        def post(self, configuration_uuid):
            
            # Grab the integration configuration
            config = pagerduty.load_configuration(configuration_uuid)

            if not config:
                IntegrationApi.abort(404, "Configuration not found")

            config = config.actions.incoming_event_webhook.to_dict()
    
            # Grab this from the integration configuration
            incident_key_field = config["incident_key_field"]

            # Determine if the action is supported
            event_type = None
            pd_event = None
            supported_event_types = ['incident.acknowledged', 'incident.resolved', 'incident.annotated', 'incident.unacknowledged','incident.priority_updated']

            if "event" in IntegrationApi.payload:
                pd_event = IntegrationApi.payload['event']

                event_type = pd_event["event_type"]

            if event_type in supported_event_types:

                # Find the event or events using the incident_key which should
                # be the Events signature hash

                if event_type == "incident.annotated":

                    event_filter = {
                        "integration_attributes__pagerduty__incident_id__keyword": pd_event["data"]["incident"]["id"]
                    }

                    events = pagerduty.load_events(**event_filter)
                    pagerduty.add_event_comment(events, pd_event["data"]["content"], pd_event["agent"]["summary"])

                if event_type == "incident.resolved":

                    event_filter = {
                        incident_key_field: pd_event["data"]["incident_key"],
                        "integration_attributes__pagerduty__incident_id__keyword": pd_event["data"]["id"]
                    }

                    events = pagerduty.load_events(**event_filter)
                    pass
                    # Fetch the configuration parameters from the integration configuration
                    # which tell us which Closure Reason to use

        def verify(self):
            # Verify the webhook is valid by checking the pagerduty
            # signature
            
            # TODO: Move this to the IntegrationAction configuration
            SIGNATURE = ""
            pass

    class TestResource(Resource):
        path = "/test"

        @IntegrationApi.expect(mod_test)
        def get(self):
            return "Hello World"

pagerduty = PagerDuty()
