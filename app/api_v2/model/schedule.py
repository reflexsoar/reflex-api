from datetime import datetime
from pytz import timezone
from . import (
    base,
    Text,
    Keyword,
    Integer,
    InnerDoc,
    Nested,
    Boolean
)

DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

class ScheduleDayTime(InnerDoc):

    start = Integer()
    end = Integer()


class ScheduleDay(InnerDoc):
    '''
    Defines a day of the week that a schedule can run on.
    '''
    hours = Nested()
    custom = Boolean()
    active = Boolean()

class Schedule(base.BaseDocument):
    ''' Defines a schedule that can be used to informat Detections,
     Event Rules, Notification Channels and other objects that run on 
     a schedule when they are allowed to run. '''
    
    name = Keyword(fields={'text': Text()})
    description = Text()
    monday = Nested(ScheduleDay)
    tuesday = Nested(ScheduleDay)
    wednesday = Nested(ScheduleDay)
    thursday = Nested(ScheduleDay)
    friday = Nested(ScheduleDay)
    saturday = Nested(ScheduleDay)
    sunday = Nested(ScheduleDay)
    timezone = Keyword()
    active = Boolean()

    class Index:
        name = "reflex-schedules"
        settings = {
            "refresh_interval": "1s"
        }

    @property
    def schedule_active(self):
        return self.is_active()

    def is_active(self):
        ''' Returns true if the current time is within the schedules days
        and hours. '''

        if not hasattr(self, 'timezone'):
            return False
        
        now = datetime.now(timezone(self.timezone))

        if not self.active:
            return False

        for day in DAYS:
            day_config = getattr(self, day)
            current_day_name = now.strftime('%A').lower()
            if day_config.active and day == current_day_name:

                if not day_config.custom:
                    return True
                
                for hour in day_config.hours:

                    now_time = f"{now.hour:02d}{now.minute:02d}"
                    now_time = int(now_time)
                    
                    start_time = int(hour['start'].replace(':', ''))
                    end_time = int(hour['end'].replace(':', ''))

                    if now_time >= start_time and now_time <= end_time:
                        return True
                    
        return False

    @classmethod
    def get_active_schedules(cls):
        ''' Returns a list of active schedules. '''

        return [s for s in cls.search().filter('term', active=True).scroll()]

    @classmethod
    def merge_schedules(cls, schedules):
        ''' Merges a list of Schedule objects into a single schedule object 
        by taking the union of the days and hours and returns it as a new 
        Schedule object. '''

        # Create a new schedule object to return
        new_schedule = cls()
        new_schedule.name = 'Merged Schedule'
        new_schedule.description = 'A schedule merged from the following schedules: \n\n'

        # Iterate over the schedules and merge them into the new schedule
        for schedule in schedules:
            new_schedule.description += schedule.name + '\n'
            new_schedule.timezone = schedule.timezone

            # Iterate over the days of the week and merge them
            for day in DAYS:
                # Get the day from the new schedule
                new_day = getattr(new_schedule, day)
                # Get the day from the schedule we are merging
                day_to_merge = getattr(schedule, day)
                # If the day is not set in the new schedule, set it to the day to merge
                if not new_day:
                    setattr(new_schedule, day, day_to_merge)
                # If the day is set in the new schedule, merge the hours
                else:
                    # Iterate over the hours in the day to merge
                    for hour in day_to_merge.hours:
                        # If the hour is not in the new day, add it
                        if hour not in new_day.hours:
                            new_day.hours.append(hour)
        
        return new_schedule
