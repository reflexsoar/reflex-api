from datetime import datetime, timedelta

SEVERITY_WEIGHTS = {
    1: 1,
    2: 4,
    3: 9,
    4: 16,
    5: 25
}

class RiskScoring:
    '''
    Calculates the overall risk score for an object based on a list of events.
    '''

    def __init__(self, max_decay_days=365, decay_factor=None, use_sev_weight=True):
        if decay_factor is None:
            self.decay_factor = 1 / max_decay_days
        else:
            self.decay_factor = decay_factor
        self.max_decay_days = max_decay_days
        self.use_sev_weight = use_sev_weight
    
    def calculate_overall_risk(self, events):
        total_weight = 0
        total_risk = 0
        today = datetime.now().date()
        
        for event in events:
            event_date = datetime.strptime(event['date'], "%Y-%m-%d").date()
            days_diff = (today - event_date).days

            if days_diff <= self.max_decay_days and days_diff >= 0:
                risk_score = event['risk_score']
                severity = event['severity']
                weight = 1 / (1 + (self.decay_factor * days_diff))
                if self.use_sev_weight:
                    weight = weight * SEVERITY_WEIGHTS[severity]

                total_weight += weight
                total_risk += risk_score * weight

        if total_weight > 0:
            overall_risk = total_risk / total_weight
        else:
            overall_risk = 0
            
        return overall_risk