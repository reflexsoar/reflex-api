import math
from ..model import Agent, Detection


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]

def redistribute_detections(organization=None):
    '''
    When the following criteria is true this function will redistribute the detection workload
    of all agents in the given organization

    If a new detection is added
    If a detection is disabled or deleted
    If an agent is added or its health changes to unhealthy
    '''
    agents = Agent.get_by_organization(organization)

    # If there are agents
    if len(agents) > 0:
        
        # Filter for agents that are detectors
        # TODO: Uncomment and agent.is_healthy when agent health is integrated
        agents = [agent for agent in agents if 'detector' in agent.roles] # and agent.is_healthy]
        if len(agents) > 0:

            detection_sets = []

            # Distribute the agents across all the detections
            detections = Detection.get_by_organization(organization)
            if len(detections) > 0:
                detection_sets = list(chunks(detections, math.ceil(len(detections)/len(agents))))

            for i in range(0,len(detection_sets)):
                for detection in detection_sets[i]:
                    if detection.assigned_agent != agents[i].uuid:
                        detection.assigned_agent = agents[i].uuid
                        detection.save()
                    