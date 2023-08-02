
from flask_restx import Resource, fields

from app.integrations.base import IntegrationBase, IntegrationApi


mod_test = IntegrationApi.model('Test', {
    'test': fields.String
})


class ReflexSOAR(IntegrationBase):

    def action_tag_event(self, events, tags):
        """
        Tags all observables in the events with the provided tags
        """

        # Fetch all the events based on the uuids
        events = self.load_events(uuid=events)

        if isinstance(events, list):
            for event in events:
                if event.tags:
                    event.tags.extend(tags)
                    
                else:
                    event.tags = tags
                    event.tags = list(set(event.tags))
                event.save()

    def action_tag_all_observables(self, events, tags):
        """
        Tags all observables in the events with the provided tags
        """

        # Fetch all the events based on the uuids
        events = self.load_events(uuid=events)

        if isinstance(events, list):
            for event in events:
                for observable in event.observables:
                    if observable.tags:
                        observable.tags.extend(tags)
                    else:
                        observable.tags = tags
                    observable.tags = list(set(observable.tags))
                event.save()

    def action_test(self):
        print("HELLO WORLD THIS IS A TEST ACTION")

    class TestResource(Resource):
        path = "/test"

        @IntegrationApi.expect(mod_test)
        def get(self):
            return "Hello World"


reflexsoar = ReflexSOAR()

'''

mod_event_webhook_update_payload = api.model('EventWebhookUpdatePayload', {
    'action': fields.String,
    'event_uuid': fields.String,
    'comment': fields.String,
    'status_name': fields.String
})

mod_event_webhook_payload = api.model('EventWebhookPayload', {
    'action': fields.String,
    'create_payload': JSONField,
    'update_payload': fields.Nested(mod_event_webhook_update_payload)
})


@r.api.route("/event_webhook/<string:action_uuid>")
class EventWebhook(Resource):

    @api.expect(mod_event_webhook_payload)
    def post(self, action_uuid):
        """
        Search for a configuration by the product_identifer and the integration uuid
        """
        integration = Integration.get(
            manifest['product_identifier'], version=manifest['version'])

        if not integration:
            api.abort(
                404, f"Integration {manifest['product_identifier']} not found")

        action = integration.get_action(action_uuid)

        if not action:
            api.abort(404, f"Action {action_uuid} not found")

        if action.configuration:

            if hasattr(action.configuration, 'ip_restrictions'):
                ips = action.configuration.ip_restrictions
                # Check to see if the request is coming from a valid IP address
                if request.remote_addr not in ips:
                    api.abort(
                        403, f"Request from {request.remote_addr} is not allowed")

            if hasattr(action.configuration, 'user_agent_restritions'):

                agents = action.configuration.user_agent_restrictions

                # Check to see if the request is coming from a valid User-Agent
                if request.user_agent.string not in agents:
                    api.abort(
                        403, f"Request from {request.user_agent.string} is not allowed")

        if not 'action' in api.payload:
            api.abort(400, "Missing 'action' in payload")

        if api.payload['action'] not in ['create', 'update']:
            api.abort(
                400, f"Invalid 'action' in payload: {api.payload['action']}")

        if api.payload['action'] == 'create':
            pass
            # CREATE A NEW EVENT

        if api.payload['action'] == 'update':

            update_payload = api.payload.get('update_payload')
            if not update_payload:
                api.abort(400, "Missing 'update_payload' in payload")

            if 'action' not in update_payload:
                api.abort(400, "Missing 'action' in update_payload")

            if update_payload['action'] not in ['comment', 'dismiss']:
                api.abort(
                    400, f"Invalid 'action' in update_payload: {update_payload['action']}")

            # Find the source event by the event_uuid
            event = Event.get_by_uuid(
                update_payload['event_uuid'], organization=action.organization)

            if not event:
                api.abort(
                    404, f"Event {update_payload['event_uuid']} not found")

            if update_payload['action'] == 'comment' and 'comment' in update_payload:
                comment = {
                    'uuid': uuid4(),
                    'comment': update_payload['comment'],
                    'organization': event.organization,
                    'created_by': f"{manifest['name']} Integration",
                    'created_at': datetime.datetime.utcnow(),
                }

                event.add_comment(comment)
                event.save()

            if update_payload['action'] == 'dismiss' and 'status_name' in update_payload:

                dismiss = {
                    'reason': None,
                    'comment': None,
                    'advice': None
                }

                # Find the close reason
                dismiss['reason'] = CloseReason.get_by_name(
                    update_payload['status_name'], organization=action.organization)

                if not dismiss['reason']:
                    api.abort(
                        404, f"Close Reason {update_payload['status_name']} not found")

                if 'dismiss_comment' in update_payload:
                    dismiss['comment'] = update_payload['dismiss_comment']

                if 'advice' in update_payload:
                    dismiss['advice'] = update_payload['advice']

                event.set_dismissed(**dismiss)

        return "SUCCESS"


class Test(Resource):

    def get(self):
        return "Test ReflexSOAR Integration"

'''
