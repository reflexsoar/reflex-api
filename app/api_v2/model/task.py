"""app/api_v2/model/task.py

Contains all the logic for tracking background tasks
"""

import datetime
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Date
)


class Task(base.BaseDocument):
    '''
    A Task is a background job that is performing an operation behind the scenes for Reflex
    A Task object just tracks completion for the UI to represent back to the end user
    '''

    started = Boolean() # Is the task started?
    message = Text() # A special message detailing this task
    start_date = Date()
    end_date = Date()
    elapsed_seconds = Integer()
    complete = Boolean() # Is the task complete or not?
    task_type = Keyword() # What type of task is it
    dead = Boolean() # Is the task dead?
    broadcast = Boolean() # Should the completion of this task be broadcast to other users

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-tasks'
        settings = {
            'refresh_interval': '1s'
        }

    def create(self, task_type, start=True, message=None, broadcast=False):
        '''
        Creates a task and sets the defaults
        '''
        if start:
            self.start(save=False)
        else:
            self.started = False
        self.complete = False
        self.message = message
        self.broadcast = broadcast
        self.task_type = task_type
        self.save(refresh=True)
        return self.uuid

    def start(self, save=True):
        '''
        Starts a task
        '''
        self.started = True
        self.start_date = datetime.datetime.utcnow()
        if save:
            self.save()

    def finish(self):
        '''
        Sets a task as completed
        '''
        self.complete = True
        self.end_date = datetime.datetime.utcnow()
        self.elapsed_seconds = (self.end_date - self.start_date).total_seconds()
        self.save()

    def mark_dead(self):
        '''
        Marks the task as dead
        '''
        self.complete = True
        self.dead = True
        self.end_date = datetime.datetime.utcnow()
        self.elapsed_seconds = (self.end_date - self.start_date).total_seconds()
        self.save()

    def set_message(self, message):
        '''
        Sets a new message on this task
        '''
        self.message = message
        self.save(refresh=True)