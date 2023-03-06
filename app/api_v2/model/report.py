"""app/api_v2/model/report.py

Contains the models for the report API
"""

from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Date,
)

class ReportResult(base.BaseDocument):

    class Index:
        name = "reflex-report-results"
        settings = {
            "refresh_interval": "1s"
        }

    report_uuid = Keyword() # The report UUID this result is for
    report_html = Text() # The HTML of the report

class Report(base.BaseDocument):

    class Index:
        name = "reflex-reports"
        settings = {
            "refresh_interval": "1s"
        }

    title = Keyword(fields={'text':Text()})
    description = Keyword(fields={'text':Text()})
    scheduled_report = Boolean() # Is a scheduled report
    logo = Keyword() # A refernece to a logo image
    report_format = Keyword() # Markdown, HTML, PDF, JSON, CSV, etc.
    days_of_week = Keyword() # A comma separated list of days of the week
    report_hour = Integer() # The hour of the day to run the report
    report_minute = Integer() # The minute of the hour to run the report
    report_second = Integer() # The second of the minute to run the report
    start_date = Date() # When to start the report scheduling
    end_date = Date() # When to end the report scheduling
    active = Boolean() # Is the report active
    report_type = Keyword() # The type of report (False Positive Reducation, SOC Health, etc.)
    delivery_type = Keyword() # The type of delivery (Email, Slack, etc.)
    mail_recipients = Keyword()
    mail_subject = Keyword()