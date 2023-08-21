import time
import datetime

from ...integrations.base import integration_registry
from app.api_v2.model import IntegrationActionQueue, Event


class ActionRunner(object):
    """
    Defines a process that accepts action configurations and places them
    in to a priority queue for processing.
    """

    def __init__(self):
        pass

    def get_actions(self):
        """
        Query the IntegrationActionQueue for actions to run
        """
        search = IntegrationActionQueue.search()
        search = search.filter('term', status='pending')
        search = search.sort('priority', 'asc')
        search = search.sort('created_at', 'asc')

        actions = [a for a in search.scan()]
        if actions:
            return actions

        return []

    def run_action(self, action):
        '''
        Runs an action against an event
        '''
        max_attempts = 5

        # Look to see if the event has been indexed yet
        attempts = 0
        while attempts != max_attempts:
            attempts += 1
            try:
                event = Event.get_by_uuid(action['events'])
                if event:
                    break
                time.sleep(5)
            except Exception as e:
                print(f"Error fetching event: {e}")
                time.sleep(5)

        if attempts == max_attempts:
            return

        for e in event:
            action_start = datetime.datetime.utcnow()

            if 'event_integration_duration' not in e.metrics:
                e.metrics['event_integration_duration'] = {}

            try:
                integration = integration_registry[action['integration_uuid']]
            except KeyError:
                print(f"Integration not found: {action['integration_uuid']}")
                return

            try:
                if 'parameters' not in action:
                    action['parameters'] = {}

                integration.run_action(action['action'],
                                    events=[e],
                                    configuration_uuid=action['configuration_uuid'],
                                    **action['parameters'].to_dict(),
                                    from_event_rule=True)
            except ValueError as err:
                print(f"Action not found: {err}")
            except Exception as err:
                print(f"Error running action: {err}")

            action_end = datetime.datetime.utcnow()
            action_duration = (action_end - action_start).total_seconds()
            e.metrics['event_integration_duration'][action['action']
                                                        ] = action_duration
            
            # Refresh the Events index
            Event._index.refresh()
            
            _event = Event.get_by_uuid(e.uuid)
            _event.metrics = e.metrics
            _event.save()

    def run(self):
        print("ActionRunner cycle started")
        while True:

            actions = self.get_actions()
            for action in actions:

                action.update(status='running', refresh=True)
                try:
                    self.run_action(action, )
                except Exception as e:
                    print(f"Error running action: {e}")
                    action.update(status='error')
                    continue
                action.update(status='complete')

            time.sleep(1)
            print("ActionRunner waiting for actions...")
