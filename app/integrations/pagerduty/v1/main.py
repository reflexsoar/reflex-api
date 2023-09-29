from flask_restx import Resource, fields
from app.api_v2.model.case import CloseReason

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

    def __init__(self):

        super().__init__()

        self.incident_ids = {}

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

                incident_id = incident.get('id', None)
                if incident_id:
                    if incident_id in self.incident_ids:
                        self.incident_ids[incident_id].append(incident_key)
                    else:
                        self.incident_ids[incident_id] = [incident_key]

                    comment = f"""**PagerDuty Incident Created**\n\n**Incident ID:** {incident['id']}\n**Incident URL:** [{incident['html_url']}]({incident['html_url']})"""
                    pagerduty.add_event_comment(events, comment, incident_from)

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
            supported_event_types = ['incident.acknowledged', 'incident.resolved',
                                     'incident.annotated', 'incident.unacknowledged',
                                     'incident.priority_updated', 'incident.reassigned']

            if "event" in IntegrationApi.payload:
                pd_event = IntegrationApi.payload['event']

                event_type = pd_event["event_type"]

            if event_type in supported_event_types:

                # Find the event or events using the incident_key which should
                # be the Events signature hash

                if event_type == "incident.annotated":

                    incident_id = pagerduty.incident_ids.get(pd_event["data"]["incident"]["id"], None)

                    if incident_id:

                        event_filter = {
                            incident_key_field: incident_id
                        }

                        events = pagerduty.load_events(**event_filter)
                        pagerduty.add_event_comment(events, pd_event["data"]["content"], pd_event["agent"]["summary"])

                if event_type == "incident.acknowledged":

                    incident_id = pagerduty.incident_ids.get(pd_event["data"]["id"], None)

                    if incident_id:

                        event_filter = {
                            incident_key_field: incident_id
                        }

                        events = pagerduty.load_events(**event_filter)
                        pagerduty.add_event_comment(events, "Incident Acknowledged", pd_event["agent"]["summary"])

                if event_type == "incident.unacknowledged":

                    incident_id = pagerduty.incident_ids.get(pd_event["data"]["id"], None)

                    if incident_id:

                        event_filter = {
                            incident_key_field: incident_id
                        }

                        events = pagerduty.load_events(**event_filter)
                        pagerduty.add_event_comment(events, "Incident Unacknowledged", pd_event["agent"]["summary"])

                if event_type == "incident.reassigned":

                    incident_id = pagerduty.incident_ids.get(pd_event["data"]["id"], None)

                    if incident_id:

                        event_filter = {
                            incident_key_field: incident_id
                        }

                        events = pagerduty.load_events(**event_filter)

                        if 'assignees' in pd_event["data"] and len(pd_event["data"]["assignees"]) > 0:
                            assignee = pd_event["data"]["assignees"][0]["summary"]
                            message = f"Incident Reassigned\n\n**New Responder:** {assignee}"
                        else:
                            message = f"Incident Reassigned"                        

                        pagerduty.add_event_comment(events, message, pd_event["agent"]["summary"])


                if event_type == "incident.resolved":

                    incident_id = pd_event["data"]["id"]

                    event_filter = {
                        incident_key_field: pd_event["data"]["incident_key"],
                        "status__name__keyword": ["New","Open"]
                    }

                    events = pagerduty.load_events(**event_filter)
                    
                    close_reason_payload = {
                        'reason': None,
                        'comment': 'Incident resolved in PagerDuty'
                    }

                    # Fetch the configuration parameters from the integration configuration
                    # which tell us which Closure Reason to use

                    if 'default_close_reason' in config:
                        default_close_reason = config['default_close_reason']
                        close_reason = CloseReason.get_by_uuid(default_close_reason)
                        if close_reason:
                            close_reason_payload['reason'] = close_reason.title

                    if 'default_close_comment' in config:
                        close_reason_payload['comment'] = config['default_close_comment']

                    success = pagerduty.close_event(events, **close_reason_payload)
                    
                    if success:
                        if incident_id in pagerduty.incident_ids:
                            del pagerduty.incident_ids[incident_id]

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
