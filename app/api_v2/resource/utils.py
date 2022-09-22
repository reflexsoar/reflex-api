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
    detections = Detection.get_by_organization(organization)

    # If there are agents
    if len(agents) > 0:
        
        # Filter for agents that are detectors
        agents = [agent for agent in agents if agent.roles and 'detector' in agent.roles and agent.healthy]
        if len(agents) > 0:

            detection_sets = []

            # Distribute the agents across all the detections
            if len(detections) > 0:
                detection_sets = list(chunks(detections, math.ceil(len(detections)/len(agents))))

            for i in range(0,len(detection_sets)):
                for detection in detection_sets[i]:
                    if detection.active:
                        if detection.assigned_agent != agents[i].uuid:                            
                            detection.assigned_agent = agents[i].uuid
                            detection.save(skip_update_by=True)
        else:
            # If there are no agents set all assigned_agents to None
            for detection in detections:
                detection.assigned_agent = None
                detection.save(skip_update_by=True)
                    