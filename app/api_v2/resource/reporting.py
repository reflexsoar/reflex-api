import json
import datetime
from app import cache
from flask import render_template, make_response
from flask_restx import Resource, Namespace, fields
from ..utils import token_required, user_has

from ..model import Event, Organization, Case, Settings

api = Namespace('Reporting', description='Reporting related operations', path='/reporting')


def severity_as_string(severity):
    if severity == 1:
        return 'Low'
    elif severity == 2:
        return 'Medium'
    elif severity == 3:
        return 'High'
    elif severity == 4:
        return 'Critical'
    else:
        return 'Unknown'

def trend_direction(current, previous):
    if current > previous:
        return 'up'
    elif current < previous:
        return 'down'
    else:
        return 'flat'


report_parser = api.parser()
report_parser.add_argument('days', type=int, required=False, help='Number of days to report on', default=14)
report_parser.add_argument('utc_offset', type=str, required=False, help='UTC offset', default="00:00"),
report_parser.add_argument('soc_start_hour', type=int, required=False, help='Start hour of SOC', default=14)
report_parser.add_argument('soc_end_hour', type=int, required=False, help='End hour of SOC', default=22)

@api.route("/<organization_uuid>")
class Reporting(Resource):

    @api.doc(security='Bearer')
    @api.expect(report_parser)
    @token_required    
    def get(self, current_user, organization_uuid):

        if not current_user.default_org and current_user.organization != organization_uuid:
            api.abort(403, "You do not have permission to view this report")

        org_settings = Settings.load(organization=organization_uuid)
        
        headers = {'Content-Type': 'text/html'}

        args = report_parser.parse_args()

        if hasattr(org_settings, 'utc_offset'):
            timezone = org_settings.utc_offset
        else:
            timezone = args.utc_offset

        if not timezone.startswith('-'):
            timezone = '+' + timezone

        report_days = args.days
        soc_start_hour = args.soc_start_hour
        soc_end_hour = args.soc_end_hour
        base_url = "http://localhost:8080"
        #####

        if timezone.startswith('-'):
            offset = int(timezone[1:3])*-1
        if timezone.startswith('+'):
            offset = int(timezone[1:3])

        current_period = {
            'gte': datetime.datetime.utcnow() - datetime.timedelta(days=report_days),
            'time_zone': f'{timezone}'
        }

        previous_period = {
            'gte': datetime.datetime.utcnow() - datetime.timedelta(days=report_days*2),
            'lt': datetime.datetime.utcnow() - datetime.timedelta(days=report_days),
            'time_zone': f'{timezone}:00'
        }

        organization = Organization.get_by_uuid(organization_uuid)
        if not organization:
            api.abort(404, "Organization not found")

        
        # Find the total number of Events for the organization
        total_events_search = Event.search()
        total_events_search = total_events_search.filter('term', organization=organization_uuid)
        total_events = total_events_search.count()

        # Find the total number of events for this search period
        current_events_search = Event.search()
        current_events_search = current_events_search.filter('term', organization=organization_uuid)
        previous_events_search = current_events_search

        current_events_search = current_events_search.filter('range', created_at=current_period)
        current_period_events = current_events_search.count()

        # Find the number of events per day for this period
        events_per_day = Event.search().filter('term', organization=organization_uuid).filter('range', created_at=current_period)
        events_per_day.aggs.bucket('dates', 'date_histogram', field='created_at', fixed_interval='1d', time_zone=timezone, extended_bounds={
          "min": f"now-{report_days}d",
          "max": "now/d"
        })        
        events_per_day = events_per_day.execute()
        current_days = {}
        for day in events_per_day.aggregations.dates.buckets:
            current_days[datetime.datetime.fromisoformat(day.key_as_string.replace('Z','')).strftime('%Y-%m-%d')] = day.doc_count

        # Find the number of events per day for this period
        events_per_day = Event.search().filter('term', organization=organization_uuid).filter('range', created_at=previous_period)
        events_per_day.aggs.bucket('dates', 'date_histogram', field='created_at', fixed_interval='1d', time_zone=timezone, extended_bounds={
          "min": f"now-{report_days*2}d",
          "max": f"now-{report_days}d"
        })        
        events_per_day = events_per_day.execute()
        previous_days = {}
        for day in events_per_day.aggregations.dates.buckets:
            previous_days[datetime.datetime.fromisoformat(day.key_as_string.replace('Z','')).strftime('%Y-%m-%d')] = day.doc_count


        previous_events_search = previous_events_search.filter('range', created_at=previous_period)
        previous_events_count = previous_events_search.count()

        handled_by_auto_search = Event.search()
        handled_by_auto_search = handled_by_auto_search.filter('term', organization=organization_uuid)
        handled_by_auto_search = handled_by_auto_search.filter('term', dismissed_by_rule=True)
        handled_by_auto_previous_period_search = handled_by_auto_search

        handled_by_auto_search = handled_by_auto_search.filter('range', created_at=current_period)
        handled_by_auto = handled_by_auto_search.count()

        handled_by_auto_previous_period_search = handled_by_auto_previous_period_search.filter('range', created_at=previous_period)
        handled_by_auto_previous_period = handled_by_auto_previous_period_search.count()

        handled_by_analyst_search = Event.search()
        handled_by_analyst_search = handled_by_analyst_search.filter('term', organization=organization_uuid)
        handled_by_analyst_search = handled_by_analyst_search.filter('exists', field='dismissed_by.username.keyword')
        handled_by_analyst_previous_period_search = handled_by_analyst_search

        handled_by_analyst_search = handled_by_analyst_search.filter('range', created_at=current_period)
        handled_by_analyst = handled_by_analyst_search.count()

        handled_by_analyst_previous_period_search = handled_by_analyst_previous_period_search.filter('range', created_at=previous_period)
        handled_by_analyst_previous_period = handled_by_analyst_previous_period_search.count()

        customer_search = Event.search()
        customer_search = customer_search.filter('term', organization=organization_uuid)
        customer_search = customer_search.filter('exists', field='case')
        customer_search = customer_search.filter('term', status__name__keyword='Open')
        customer_search_previous_period = customer_search

        customer_search = customer_search.filter('range', created_at=current_period)
        customer_count = customer_search.count()

        customer_search_previous_period = customer_search_previous_period.filter('range', created_at=previous_period)
        customer_count_previous_period = customer_search_previous_period.count()

        current_data = [current_days[day] for day in current_days]
        previous_data = [previous_days[day] for day in previous_days]
        delta = [current_data[i] - previous_data[i] for i in range(len(current_data))]
        event_chart_labels = [day for day in current_days.keys()]

        # Get the customers alerts by severity by hour of the day
        event_hours_search = Event.search().filter('term', organization=organization_uuid).query('range', created_at=current_period)
        event_hours_search.aggs.bucket('severity', 'terms', field='severity')
        event_hours_search.aggs['severity'].bucket('timeslice', 'histogram', script=f"doc['created_at'].value.withZoneSameInstant(ZoneId.of('{timezone}')).getHour()", interval=1, min_doc_count=0, extended_bounds={'min': 0, 'max': 23}, order={'_key': 'desc'})
        event_hours_search.extra(size=0)
        event_hours_search = event_hours_search.execute()
        event_hours = []
        sorted_severity = sorted(event_hours_search.aggregations.severity.buckets, key=lambda x: x.key)
        for severity in sorted_severity:
            series = {'name': severity_as_string(severity.key), 'data': []}
            timesorted = sorted(severity.timeslice.buckets, key=lambda x: x.key)
            for timeslice in timesorted:
                series['data'].append({'x': str(int(timeslice.key)), 'y': timeslice.doc_count})
            event_hours.append(series)            

        # Create warnings for the Events Over Time chart
        warnings = []

        # Case Metrics
        case_search = Case.search()
        case_search = case_search.filter('term', organization=organization_uuid)
        total_cases = case_search.count()

        case_search = case_search.filter('range', created_at=current_period)
        cases_this_period = case_search.count()

        # Case count from previous period
        case_search = Case.search()
        case_search = case_search.filter('term', organization=organization_uuid)
        case_search = case_search.filter('range', created_at=previous_period)
        cases_previous_period = case_search.count()

        # Open case count by severity
        open_case_search = Case.search()
        open_case_search = open_case_search.filter('term', organization=organization_uuid)
        open_case_search = open_case_search.filter('terms', status__name__keyword=[
              "New",
              "Open",
              "In Progress",
              "Hold"
            ])
        open_case_search.aggs.bucket('severity', 'terms', field='severity', size=10)

        open_case_search = open_case_search.execute()
        open_case_severity = {}
        for severity in open_case_search.aggregations.severity.buckets:
            open_case_severity[severity.key] = severity.doc_count

        # Get all open cases
        open_case_search = Case.search()
        open_case_search = open_case_search.filter('term', organization=organization_uuid)
        open_case_search = open_case_search.filter('terms', status__name__keyword=[
                "New",
                "Open",
                "In Progress",
                "Hold"
            ])
        open_case_search = open_case_search.sort('-created_at').source(includes=['uuid', 'title', 'description', 'severity', 'status', 'created_at', 'updated_at'])
        open_cases = [case for case in open_case_search.scan()]
        [setattr(case, 'total_events', case.event_count) for case in open_cases]
        open_cases = [c.to_dict() for c in open_cases]

        if current_period_events == 0:
            automation_percentage = 0
            manual_percentage = 0
            customer_percent = 0
        else:
            automation_percentage = round((handled_by_auto / current_period_events) * 100,0)
            manual_percentage = round((handled_by_analyst / current_period_events) * 100,0)
            customer_percent = round((customer_count / current_period_events) * 100,0)

        adjusted_soc_end_hour = soc_end_hour + offset
        adjusted_soc_start_hour = soc_start_hour + offset

        report = {
            'title': f'Monthly SOC Report for {organization.name}',
            'generated_on': datetime.datetime.utcnow().isoformat(),
            'soc_hours': {
                'start': adjusted_soc_start_hour,
                'end': adjusted_soc_end_hour
            },
            'date': {
                'total_days': args.days,
                'start_date': '2020-01-01',
                'end_date': '2020-01-31'
            },
            'cases': {
                'total': total_cases,
                'this_period': cases_this_period,
                'previous_period': cases_previous_period,
                'open_by_severity': open_case_severity,
                'details': {
                    'open': open_cases
                }
            },
            'events': {
                'severity_by_hour_of_day': event_hours,
                'this_period': {
                    'total': current_period_events,
                    'total_trend_direction': trend_direction(current_period_events, previous_events_count),
                    'automation_total': handled_by_auto,
                    'automation_percent': automation_percentage,
                    'automation_trend_direction': trend_direction(handled_by_auto, handled_by_auto_previous_period),
                    'manual_total': handled_by_analyst,
                    'manual_percent': manual_percentage,
                    'manual_trend_direction': trend_direction(handled_by_analyst, handled_by_analyst_previous_period),
                    'customer_total': customer_count,
                    'customer_percent': customer_percent,
                    'customer_trend_direction': trend_direction(customer_count, customer_count_previous_period)
                },
                'last_period': {
                    'total': previous_events_count,
                    'automation_total': handled_by_auto_previous_period,
                    'manual_total': handled_by_analyst_previous_period,
                    'customer_total': customer_count_previous_period
                },
                'chart': {
                    'labels': event_chart_labels,
                    'current_period_data': current_data,
                    'previous_period_data': previous_data,
                    'delta': delta,
                    'warnings': warnings
                },
                'total': total_events,
                'details': [
                    {
                        'title': 'Event 1',
                        'hits': 35,
                        'description': 'Event 1 Description',
                        'dismiss_comment': [
                            'Comment 1',
                            'Comment 2',
                            'Comment 3'
                        ],
                        'tuning_advice': [
                            'Tuning Advice 1'
                        ]
                    },
                    {
                        'title': 'Event 2',
                        'hits': 10,
                        'description': 'Event 2 Description',
                        'dismiss_comment': [
                            'Comment 1',
                            'Comment 2',
                            'Comment 3'
                        ],
                        'tuning_advice': [
                        ]
                    }
                ]
            }
        }

        response = make_response(render_template('reporting/report.html', report=report, base_url=base_url), 200, headers)
        return response