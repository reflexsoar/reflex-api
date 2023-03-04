import json
import datetime
from flask import render_template, make_response
from flask_restx import Resource, Namespace, fields

from ..model import Event, Organization, Case

api = Namespace('reporting', description='Reporting related operations', path='/reporting')


def events_per_period_per_day(events, start_date, end_date):
    date_span = end_date - start_date
    for i in range(date_span.days + 1):
        print(i)

def trend_direction(current, previous):
    if current > previous:
        return 'up'
    elif current < previous:
        return 'down'
    else:
        return 'flat'


@api.route("/<string:report_title>")
class Reporting(Resource):

    def get(self, report_title):
        headers = {'Content-Type': 'text/html'}

        # MOVE THESE TO A CONFIG
        organization_uuid = "ef7627cf-e006-4d8b-8e83-6d34a2e41457"
        report_days = 14
        base_url = "http://localhost:8080"
        #####

        current_period = {
            'gte': datetime.datetime.utcnow() - datetime.timedelta(days=report_days)
        }

        previous_period = {
            'gte': datetime.datetime.utcnow() - datetime.timedelta(days=report_days*2),
            'lt': datetime.datetime.utcnow() - datetime.timedelta(days=report_days)
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
        events_per_day.aggs.bucket('dates', 'date_histogram', field='created_at', fixed_interval='1d', extended_bounds={
          "min": f"now-{report_days}d",
          "max": "now/d"
        })        
        events_per_day = events_per_day.execute()
        current_days = {}
        for day in events_per_day.aggregations.dates.buckets:
            current_days[datetime.datetime.fromisoformat(day.key_as_string.replace('Z','')).strftime('%Y-%m-%d')] = day.doc_count

        # Find the number of events per day for this period
        events_per_day = Event.search().filter('term', organization=organization_uuid).filter('range', created_at=previous_period)
        events_per_day.aggs.bucket('dates', 'date_histogram', field='created_at', fixed_interval='1d', extended_bounds={
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
        

        report = {
            'title': f'Monthly SOC Report for {organization.name}',
            'generated_on': datetime.datetime.utcnow().isoformat(),
            'date': {
                'total_days': 30,
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
                'this_period': {
                    'total': current_period_events,
                    'total_trend_direction': trend_direction(current_period_events, previous_events_count),
                    'automation_total': handled_by_auto,
                    'automation_percent': round(handled_by_auto/current_period_events*100,0),
                    'automation_trend_direction': trend_direction(handled_by_auto, handled_by_auto_previous_period),
                    'manual_total': handled_by_analyst,
                    'manual_percent': round(handled_by_analyst/current_period_events*100,0),
                    'manual_trend_direction': trend_direction(handled_by_analyst, handled_by_analyst_previous_period),
                    'customer_total': customer_count,
                    'customer_percent': round(customer_count/current_period_events*100,0),
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