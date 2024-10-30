import datetime
from app.api_v2.model import (
    Case,
    CaseComment,
    CaseStatus,
    CaseHistory,
    Settings,
    CloseReason
)
from app.api_v2.model.utils import _current_user_id_or_none

def auto_close_cases():
    """ Queries for any cases that are not closed and do not have the 
    block_auto_close property set to True. If there are any, the settings for
    the organization they belong to are fetched and if the number of days 
    since the last activity exceeds the case_auto_close_days setting, the case
    is automatically closed with the case_auto_close_reason and
    case_auto_close_comment settings.
    """

    # Find all cases that are not closed and do not have block_auto_close set
    search = Case.search()

    # closed = False or does not exist
    search = search.filter().query("bool", must_not=[{"term": {"closed": True}}])

    # block_auto_close = False or does not exist
    search = search.filter().query("bool", must_not=[{"term": {"block_auto_close": True}}])    

    # Filter 
    cases = [c for c in search.scan()]

    # Group the cases by organization
    cases_by_org = {}
    for case in cases:
        if case.organization not in cases_by_org:
            cases_by_org[case.organization] = []
        cases_by_org[case.organization].append(case)
        
    # For each organization, get the settings and check if the case should be closed
    for org in cases_by_org:
        settings = Settings.load(org)
        reason = CloseReason.get_by_name('Other', organization=org)
        status = CaseStatus.get_by_name('Closed', organization=org)
        if settings and settings.case_auto_close:
            print(f"Checking {len(cases_by_org[org])} case(s) for automatic closure in organization {org}...")

            for case in cases_by_org[org]:
            
                case_history_search = CaseHistory.search()
                case_history_search = case_history_search.filter().query("term", organization=org)
                case_history_search = case_history_search.filter().query("term", case__keyword=case.uuid)
                
                # Filter to now - case_auto_close_days
                case_history_search = case_history_search.filter().query("range", created_at={"gte": f"now-{settings.case_auto_close_days}d"})
                history = [h for h in case_history_search.scan()]
                if len(history) == 0:

                    comment = f"Case automatically closed after {settings.case_auto_close_days} days of inactivity."

                    case_comment = CaseComment(case_uuid=case.uuid,
                                               message=comment,
                                               is_closure_comment=True,
                                               closure_reason=reason)
                    case_comment.save()
                    case.add_history(message="Comment added to case")
                    
                    case.close_reason = reason
                    case.closed_at = datetime.datetime.utcnow()
                    case.closed = True
                    case.closed_by = _current_user_id_or_none()
                    case.status = status
                    case.save()
