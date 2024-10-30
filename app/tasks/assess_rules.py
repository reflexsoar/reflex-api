from app.api_v2.model import (
    Detection
)

def flag_rules_for_periodic_assessment():
    """ Discover all rules that have not been assessed in the last 24 hours
    and flag them for assessment
    """

    # Find all where last_assessed is not set or is more than 24 hours ago
    search = Detection.search().filter().query("range", last_assessed={"lte": "now-24h"}).query("term", rule_type=0)
    detections = [d for d in search.scan()]

    if len(detections) > 0:
        print('Flagging rules for periodic assessment...')
        for detection in detections:
            detection.assess_rule = True
            detection.save()