import datetime
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Date,
    Object,
    Integer,
    Nested,
    InnerDoc,
    system,
    user,
    event
)

class CaseHistory(base.BaseDocument):
    '''
    A case history entry that shows what changed on the case
    the message should be stored in markdown format
    so that it can be processed by the UI
    '''

    message = Text()
    case_uuid = Keyword()  # The uuid of the case this history belongs to

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-history'

    @classmethod
    def get_by_case(self, uuid, sort_by="-created_at"):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case=uuid)
        response = response.sort(sort_by)
        response = response.execute()
        if response:
            return [r for r in response]
        return []


class CaseComment(base.BaseDocument):
    '''
    A case comment that allows analysts to exchange information
    and notes on a case
    '''

    message = Text()
    case_uuid = Keyword()  # The uuid of the case this comment belongs to
    is_closure_comment = Boolean()  # Is this comment related to closing the case
    edited = Boolean()  # Should be True when the comment is edited, Default: False
    closure_reason = Object()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-comments'

    @classmethod
    def get_by_case(self, uuid):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case_uuid=uuid).execute()
        if response:
            return [r for r in response]
        return []


class CaseStatus(base.BaseDocument):
    '''
    The status of a case, e.g. New, Closed, In Progress, etc.
    '''

    name = Keyword()
    description = Text()
    closed = Boolean()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-statuses'

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            user = response[0]
            return user
        return response


class TaskNote(base.BaseDocument):
    '''
    A note on a case task
    '''

    note = Text()
    task = Keyword() # The UUID of the associated task

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-task-notes'

    @classmethod
    def get_by_task_uuid(self, uuid):
        '''
        Fetches a note by the associated task UUID
        '''
        response = self.search().query('match', task=uuid).execute()
        if response:
            return list(response)
        return []



class CaseTask(base.BaseDocument):
    '''
    An action that needs to occur on a Case
    '''

    title = Keyword()
    order = Integer()
    description = Text()
    owner = Nested()  # The user that is assigned to this task by default
    group = Nested()  # The group that is assigned to this task by default
    case = Keyword()  # The UUID of the case this task belongs to
    from_template = Boolean()  # Indicates if the task came from a template. Default: False
    status = Integer()  # 0 = Open, 1 = Started, 2 = Complete
    start_date = Date()
    finish_date = Date()
    notes = Keyword()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-tasks'

    @property
    def _notes(self):
        notes = TaskNote.get_by_task_uuid(self.uuid)
        return notes

    @_notes.setter
    def observables(self, value):
        self.notes.append(value)
        self.save()

    @classmethod
    def get_by_case(self, uuid):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case=uuid).execute()
        if response:
            return [r for r in response]
        return []

    @classmethod
    def get_by_title(self, title, case_uuid):
        '''
        Fetches a task by the title and case uuid
        '''
        response = self.search().query('match', case=case_uuid).query(
            'term', title=title).execute()
        if response:
            document = response[0]
            return document
        return response

    def close_task(self):
        '''
        Closes the task and gives it a completion date
        '''
        self.status = 2
        self.finish_date = datetime.datetime.utcnow()
        case = Case.get_by_uuid(uuid=self.case)
        case.add_history(f'Task **{self.title}** closed')
        self.save()

    def start_task(self, owner_uuid=None):
        '''
        Starts the task and gives it a date
        '''
        self.status = 1
        self.start_date = datetime.datetime.utcnow()
        if owner_uuid:
            self.set_owner(owner_uuid)
        case = Case.get_by_uuid(uuid=self.case)
        case.add_history(f'Task **{self.title}** started')
        self.save()

    def reopen_task(self):
        '''
        Reopens the task and resets the finish_date
        '''
        self.status = 1
        self.finish_date = None
        case = Case.get_by_uuid(uuid=self.case)
        case.add_history(f'Task **{self.title}** reopened')
        self.save()

    def set_owner(self, owner_uuid):
        '''
        Sets the owner of the case by the users uuid
        '''
        if owner_uuid:
            owner = user.User.get_by_uuid(owner_uuid)
            if owner:
                self.owner = {k: owner[k]
                              for k in owner if k in ['uuid', 'username']}

    def add_note(self, note):
        '''
        Adds a note to this task
        '''
        if note:
            note = TaskNote(note=note, task=self.uuid)
            note.save()
            if self.notes:
                self.notes.append(note.uuid)
            else:
                self.notes = [note.uuid]
        self.save()
        return note

    def delete(self, **kwargs):
        '''
        Deletes a task and appends a history message
        to the associated parent case
        '''

        case = Case.get_by_uuid(uuid=self.case)
        case.add_history(f'Task **{self.title}** deleted')

        return super(CaseTask, self).delete(**kwargs)


class CloseReason(base.BaseDocument):
    '''
    A custom sub-status for why a case was closed
    e.g. False Positive, Not Enough Information
    '''

    title = Keyword()
    description = Text()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-close-reasons'

    @classmethod
    def get_by_name(self, title):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', title=title).execute()
        if response:
            user = response[0]
            return user
        return response



class Case(base.BaseDocument):
    '''
    A case contains all the investigative work related to a
    series of events that were observed in the system
    '''

    title = Keyword()
    description = Text()
    severity = Integer()
    owner = Object()
    tlp = Integer()
    tags = Keyword()
    status = Object()
    related_cases = Keyword()  # A list of UUIDs related to this case
    closed = Boolean()
    closed_at = Date()
    close_reason = Object()
    case_template = Object()
    files = Keyword()  # The UUIDs of case files
    events = Keyword()
    _open_tasks = 0
    _total_tasks = 0

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-cases'

    @property
    def observables(self):
        observables = system.Observable.get_by_case_uuid(self.uuid)
        if observables:
            return list(observables)
        return []

    @observables.setter
    def observables(self, value):
        self.case_observables = value
        self.save

    @property
    def open_tasks(self):
        return self._open_tasks

    @open_tasks.setter
    def open_tasks(self, value):
        self._open_tasks = value

    def add_observables(self, observable, case_uuid=None):
        '''
        Adds an observable to the case by adding it to the observables index
        and linking the case
        '''

        if isinstance(observable, list):
            for obs in observable:
                _observable = system.Observable.get_by_case_and_value(self.uuid, obs['value'])
                if not _observable:
                    _observable = system.Observable(tags=obs['tags'],
                        value=obs['value'],
                        data_type=obs['data_type'],
                        ioc=obs['ioc'],
                        spotted=obs['spotted'],
                        tlp=obs['tlp'],
                        safe=obs['safe'],
                        case=case_uuid
                    )
                    _observable.check_threat_list()
                    _observable.enrich()
                    _observable.save()
        else:
            obs = observable
            _observable = system.Observable.get_by_case_uuid(self.uuid, obs['value'])
            if not _observable:
                _observable = system.Observable(tags=obs['tags'],
                    value=obs['value'],
                    data_type=obs['data_type'],
                    ioc=obs['ioc'],
                    spotted=obs['spotted'],
                    tlp=obs['tlp'],
                    safe=obs['safe'],
                    case=case_uuid
                )
                _observable.check_threat_list()
                _observable.enrich()
                _observable.save()

    def get_observable_by_value(self, value):
        ''' Returns an observable based on its value '''
        if obs := [o for o in self.observables if o.value == value]:
            return obs[0]
        return None

    def set_owner(self, uuid):
        '''
        Sets the bare minimum information about the
        owner of the case so the UI can render it
        '''

        owner = user.User.get_by_uuid(uuid=uuid)

        if owner:
            owner_data = {
                'username': owner.username,
                'uuid': owner.uuid
            }
            self.owner = owner_data
            username = owner_data['username']
            self.add_history(f'Owner changed to **{username}**')
        self.save()

    def set_template(self, uuid):
        '''
        Sets the case template
        '''

        template = CaseTemplate.get_by_uuid(uuid=uuid)
        self.case_template = template
        self.save()

    def close(self, uuid):
        '''
        Closes a case and sets the time that it was closed
        '''
        self.close_reason = CloseReason.get_by_uuid(uuid=uuid)
        self.closed_at = datetime.datetime.utcnow()
        self.closed = True

        # Close all the related events
        if self.events:
            for _ in self.events:
                event = event.Event.get_by_uuid(_)
                event.set_closed()

        self.save()

    def reopen(self):
        '''
        Reopens a case
        '''
        self.closed = False
        self.closed_at = None

        # Reopen all the related events
        if self.events:
            for _ in self.events:
                event = event.Event.get_by_uuid(_)
                event.set_open()

        self.save()

    @classmethod
    def get_related_cases(self, uuid):
        cases = self.search().query('term', related_cases=uuid).execute()
        if cases:
            return list(cases)
        return []

    def add_history(self, message):
        '''
        Creates a history message and associates it with
        this case
        '''
        history = CaseHistory(message=message, case=self.uuid)
        history.save()

    def add_task(self, **task):
        '''
        Adds a task to the cases tasks list and adds a history entry
        '''
        task = CaseTask(**task, case=self.uuid)
        task.status = 0
        task.save()
        self.add_history(f'Task **{task.title}** added')
        return task

    def add_event(self, events):
        '''Adds an event or list of events to the case

        Parameter:
            events (Event): A list of events or a single event
        '''

        # If dealing with many events
        if isinstance(events, list):
            for event in events:
                event.set_open()
                event.set_case(self.uuid)
                self.process_event_observables(event)
                if self.events:
                    self.events.append(event.uuid)
                else:
                    self.events = [event.uuid]
        else:
            events.set_open()
            events.set_case(self.uuid)
            self.process_event_observables(events)
            if self.events:
                self.events.append(events.uuid)
            else:
                self.events = [events.uuid]
        self.save()
        return True

    def process_event_observables(self, event):
        '''Takes in an event and processes the observables associated
        with the event by adding them to the case
        
        Parameters:
            event (Event): The event to pull observables for
        '''

        event_observables = system.Observable.get_by_event_uuid(event.uuid)
        case_observables = system.Observable.get_by_case_uuid(self.uuid)
        new_observables = None
        if case_observables:
            new_observables = [
                o for o in event_observables if o.value not in [
                    o.value for o in case_observables
                ]
            ]
        else:
            new_observables = [o for o in event_observables]

        new_observables =[system.Observable(
                tags=o.tags,
                value=o.value,
                data_type=o.data_type,
                ioc=o.ioc,
                spotted=o.spotted,
                tlp=o.tlp,
                case=self.uuid
            ) for o in new_observables]

        if new_observables:
            _ = [o.save() for o in new_observables]


    def remove_event(self, event):
        '''Removes an event from the case
        If this event is the last event with certain observables
        those observables are removed as well.
        
        Parameters:
            event (Event): The event to be removed

        Return:
            bool: True (Success) or False (Fail)
        '''
        if isinstance(event, list):
            self.events.remove([e.uuid for e in event])
        else:
            self.events.remove(event.uuid)

        self.save()

        return True



class CaseTemplateTask(InnerDoc):
    '''
    An action that needs to occur on a Case
    '''

    uuid = Keyword()
    title = Keyword()
    order = Integer()
    description = Text()
    owner = Keyword()  # The user that is assigned to this task by default
    group = Keyword()  # The group that is assigned to this task by default
    case = Keyword()  # The UUID of the case this task belongs to
    from_template = Boolean()  # Indicates if the task came from a template. Default: False
    status = Integer()  # 0 = Open, 1 = Started, 2 = Complete
    start_date = Date()
    finish_date = Date()


class CaseTemplate(base.BaseDocument):
    '''
    A Case Template represents a static format that a case can
    be created from when the work path is clearly defined
    '''

    title = Keyword()
    description = Text()
    severity = Integer()  # The default severity of the case
    owner = Keyword()  # The default owner of the case
    tlp = Integer()  # The default TLP of the case
    tags = Keyword()
    tasks = Nested(CaseTemplateTask)

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-templates'

    @classmethod
    def title_search(self, s):
        '''
        Searches for a title based on a wildcard
        '''
        s = self.search().query('wildcard', title=s+'*')
        results = s.execute()
        if results:
            return [r for r in results]
        else:
            return []

    @classmethod
    def get_by_title(self, title):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', title=title).execute()
        if response:
            document = response[0]
            return document
        return response
