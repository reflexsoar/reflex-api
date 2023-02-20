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
    event,
    UpdateByQuery,
    Float
)
from .utils import _current_user_id_or_none

class CaseHistory(base.BaseDocument):
    '''
    A case history entry that shows what changed on the case
    the message should be stored in markdown format
    so that it can be processed by the UI
    '''

    message = Text(fields={'keyword':Keyword()})
    case_uuid = Keyword()  # The uuid of the case this history belongs to

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-history'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def get_by_case(self, uuid, sort_by="-created_at"):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('term', case__keyword=uuid)
        response = response.sort(sort_by)
        response = response.execute()
        if response:
            return list(response)
        return []


class CaseComment(base.BaseDocument):
    '''
    A case comment that allows analysts to exchange information
    and notes on a case
    '''

    message = Text(fields={'keyword':Keyword()})
    case_uuid = Keyword()  # The uuid of the case this comment belongs to
    is_closure_comment = Boolean()  # Is this comment related to closing the case
    edited = Boolean()  # Should be True when the comment is edited, Default: False
    closure_reason = Object()
    cross_organization = Boolean()
    other_organization = Keyword()
    interal_comment = Boolean() # Is an internal comment that sub tenants can't see

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-comments'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def get_by_case(self, uuid):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case_uuid=uuid).execute()
        if response:
            return list(response)
        return []


class CaseStatus(base.BaseDocument):
    '''
    The status of a case, e.g. New, Closed, In Progress, etc.
    '''

    name = Keyword()
    description = Text(fields={'keyword':Keyword()})
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
            usr = response[0]
            return usr
        return response


class TaskNote(base.BaseDocument):
    '''
    A note on a case task
    '''

    note = Text(fields={'keyword':Keyword()})
    task = Keyword() # The UUID of the associated task

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-task-notes'
        settings = {
            'refresh_interval': '1s'
        }

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
    description = Text(fields={'keyword':Keyword()})
    owner = Nested()  # The user that is assigned to this task by default
    group = Nested()  # The group that is assigned to this task by default
    case = Keyword()  # The UUID of the case this task belongs to
    from_template = Boolean()  # Indicates if the task came from a template. Default: False
    status = Integer()  # 0 = Open, 1 = Started, 2 = Complete
    start_date = Date()
    finish_date = Date()
    notes = Keyword()
    require_previous_step_complete = Boolean()  # Should the previous step be complete before this one can be started

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-tasks'
        settings = {
            'refresh_interval': '1s'
        }

    @property
    def _notes(self):
        notes = TaskNote.get_by_task_uuid(self.uuid)
        return notes

    @_notes.setter
    def observables(self, value):
        self.notes.append(value)
        self.save()

    @classmethod
    def get_by_case(self, uuid, all_results=False):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().sort('order').query('match', case=uuid)
        if all_results:
            response = response[0:response.count()]
        response = response.execute()
        if response:
            return list(response)
        return []

    @classmethod
    def get_by_title(self, title, case_uuid):
        '''
        Fetches a task by the title and case uuid
        '''
        response = self.search().query('match', case=case_uuid).query(
            'term', title=title)
        response = response.execute()
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

        return super().delete(**kwargs)


class CloseReason(base.BaseDocument):
    '''
    A custom sub-status for why a case was closed
    e.g. False Positive, Not Enough Information
    '''

    title = Keyword()
    description = Text(fields={'keyword':Keyword()})
    enabled = Boolean()

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
            usr = response[0]
            return usr
        return response


class CaseMetrics(InnerDoc):
    '''
    Meta information about an event
    '''
    time_to_close = Float()
    sla_breach_time = Date()
    sla_breach_count = Integer()
    sla_breach_clear = Date()
    time_in_sla_breach = Float()


class Case(base.BaseDocument):
    '''
    A case contains all the investigative work related to a
    series of events that were observed in the system
    '''

    title = Keyword(fields={'text':Text()})
    description = Text(fields={'keyword':Keyword()})
    severity = Integer()
    owner = Object()
    #observables = Nested()
    tlp = Integer()
    tags = Keyword()
    status = Object()
    related_cases = Keyword()  # A list of UUIDs related to this case
    closed = Boolean()
    closed_at = Date()
    closed_by = Nested()
    close_reason = Object()
    case_template = Object()
    case_template_uuid = Keyword()
    files = Keyword()  # The UUIDs of case files
    events = Keyword()
    sla_breach_time = Date()
    sla_violated = Boolean()
    escalated = Boolean()
    _open_tasks = 0
    _total_tasks = 0
    watchers = Keyword() # A list of UUIDs of users watching this case
    metrics = Object(CaseMetrics)

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-cases'
        settings = {
            'refresh_interval': '1s'
        }

    def add_watcher(self, watcher_uuid):
        '''
        Adds a watcher to the case
        '''
        if watcher_uuid:
            if self.watchers:
                if watcher_uuid not in self.watchers:
                    self.watchers.append(watcher_uuid)
            else:
                self.watchers = [watcher_uuid]
            self.save()

    def remove_watcher(self, watcher_uuid):
        '''
        Removes a watcher from the case
        '''
        if watcher_uuid:
            if self.watchers:
                if watcher_uuid in self.watchers:
                    self.watchers.remove(watcher_uuid)
            self.save()

    @property
    def observables(self):
        #observables = system.Observable.get_by_case_uuid(self.uuid)
    #    if self.case_observables:
    #        return list(self.case_observables)
        return []

    @observables.setter
    def observables(self, value):
        self.case_observables = value
        self.save()

    @property
    def open_tasks(self):
        return self._open_tasks

    @open_tasks.setter
    def open_tasks(self, value):
        self._open_tasks = value

    @property
    def event_count(self):
        '''
        Returns the total number of events assigned to this case 
        by looking at the Events index and finding all events with this
        cases UUID in their case field
        '''
        response = event.Event.search().query('term', case=self.uuid).count()
        return response

    def add_observables(self, observable, case_uuid=None, organization=None):
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
                        case=case_uuid,
                        organization=organization
                    )
                    _observable.check_threat_list()
                    # REMOVED 2022-02-07 Use Threat List matching instead
                    # _observable.enrich()
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
                # REMOVED 2022-02-07 Use Threat List matching instead
                # _observable.enrich()
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

    def apply_template(self, uuid):
        '''
        Applies a case template

        Parameters:
            uuid(str): The UUID of the case template
        '''

        template = CaseTemplate.get_by_uuid(uuid=uuid)

        if template:

            for tag in template.tags:
                if self.tags:
                    if tag not in self.tags:
                        self.tags.append(tag)
                else:
                    self.tags = [tag]

            for task in template.tasks:
                self.add_task(title=task.title, description=task.description,
                            order=task.order, from_template=True, organization=self.organization)

            self.severity = template.severity
            self.tlp = template.tlp
            self.save()

    def remove_template(self):
        '''
        Removes a case template from a case, but only if no tasks have been
        started

        Return:
            True|False - True if removal was successful, False if it was not
        '''

        if self.case_template_uuid:
            
            tasks_started = False
            template = CaseTemplate.get_by_uuid(self.case_template_uuid)
            tasks = CaseTask.get_by_case(uuid=self.uuid)
            if tasks:
                tasks_started = any([task.status != 0 and task.from_template for task in tasks])

            if not tasks_started:
                [task.delete() for task in tasks if task.from_template]
                if self.tags:
                    self.tags = [t for t in self.tags if t not in template.tags]
                self.case_template_uuid = None
                self.save()
                return True
            return False
        return True


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
        self.closed_by = _current_user_id_or_none()

        # Close all the related events
        # DEPRECATED 2023-02-17 - self.events not longer is populated
        #if self.events:
        #    for _ in self.events:
        #        evt = event.Event.get_by_uuid(_)
        #        evt.set_closed()

        status = event.EventStatus.get_by_name('Closed', organization=self.organization)

        if event.Event.count_by_case(self.uuid) > 0:
            event_bulk_close = UpdateByQuery(index='reflex-events')
            event_bulk_close = event_bulk_close.query('term', case=self.uuid)
            event_bulk_close = event_bulk_close.script(
                source="""
                    ctx._source.status = params.status;
                    ctx._source.closed_at = params.closed_at;
                    ctx._source.closed_by = params.closed_by;
                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy-MM-dd'T'HH:mm:ss.SSSSSS\").withZone(ZoneId.of('UTC'));
                    ZonedDateTime zdt = ZonedDateTime.parse(params.closed_at, dtf);
                    ZonedDateTime zdt2 = ZonedDateTime.parse(ctx._source.created_at, dtf);
                    Instant Currentdate = Instant.ofEpochMilli(zdt.getMillis());
                    Instant Startdate = Instant.ofEpochMilli(zdt2.getMillis());
                    ctx._source.time_to_close = ChronoUnit.SECONDS.between(Startdate, Currentdate);
                """,
                params={
                    'status': status,
                    'closed_at': datetime.datetime.utcnow().isoformat(),
                    'closed_by': self.closed_by
                }
            )
            event_bulk_close.params(slices='auto', wait_for_completion=False)
            event_bulk_close.execute()

        self.save()


    def reopen(self, skip_save=False):
        '''
        Reopens a case
        '''
        self.closed = False
        self.closed_at = None
        self.closed_by = None
        case_status = CaseStatus.get_by_name(name="In Progress")
        if case_status:
            self.status = case_status

        # Reopen all the related events
        # DEPRECATED 2023-02-17 - self.events not longer is populated
        #if self.events:
        #    for _ in self.events:
        #        evt = event.Event.get_by_uuid(_)
        #        evt.set_open()

        status = event.EventStatus.get_by_name('Open', organization=self.organization)

        if event.Event.count_by_case(self.uuid) > 0:
            event_bulk_close = UpdateByQuery(index='reflex-events')
            event_bulk_close = event_bulk_close.query('term', case=self.uuid)
            event_bulk_close = event_bulk_close.script(
                source="""
                    ctx._source.status = params.status;
                    ctx._source.closed_at = params.closed_at;
                    ctx._source.time_to_close = params.time_to_close;
                    ctx._source.closed_by = params.closed_by;
                """,
                params={
                    'status': status,
                    'closed_at': None,
                    'time_to_close': None,
                    'closed_by': self.closed_by
                }
            )
            event_bulk_close.params(slices='auto', wait_for_completion=False)
            event_bulk_close.execute()

        if not skip_save:
            self.save()

    def is_closed(self):
        '''
        Returns True if the case is closed, False if it is not
        '''
        return self.closed

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
            for evt in events:
                evt.set_open()
                evt.set_case(self.uuid)
                self.process_event_observables(evt)
                if self.events:
                    self.events.append(evt.uuid)
                else:
                    self.events = [evt.uuid]
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


    def remove_event(self, events):
        ''' Removes an event from the case

        Parameter:
            events (Events): A list of events
        '''

        #If dealing with many events
        if isinstance(events, list):
            for _event in events:
                _event.set_new()
                _event.set_case(None)
        else:
            events.set_new()
            events.set_case(None)
        self.save()
        return True


    def process_event_observables(self, evt):
        '''Takes in an event and processes the observables associated
        with the event by adding them to the case

        Parameters:
            event (Event): The event to pull observables for
        '''

        event_observables = evt.observables
        case_observables = system.Observable.get_by_case_uuid(self.uuid)
        new_observables = None
        if case_observables:
            new_observables = [
                o for o in event_observables if o.value not in [
                    o.value for o in case_observables
                ]
            ]
        else:
            new_observables = list(event_observables)

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


    def remove_event(self, evt):
        '''Removes an event from the case
        If this event is the last event with certain observables
        those observables are removed as well.

        Parameters:
            event (Event): The event to be removed

        Return:
            bool: True (Success) or False (Fail)
        '''
        if isinstance(evt, list):
            self.events.remove([e.uuid for e in evt])
        else:
            self.events.remove(evt.uuid)

        self.save()

        return True


class CaseTemplateTask(InnerDoc):
    '''
    An action that needs to occur on a Case
    '''

    uuid = Keyword()
    title = Keyword()
    order = Integer()
    description = Text(fields={'keyword':Keyword()})
    owner = Keyword()  # The user that is assigned to this task by default
    group = Keyword()  # The group that is assigned to this task by default
    case = Keyword()  # The UUID of the case this task belongs to
    from_template = Boolean()  # Indicates if the task came from a template. Default: False
    status = Integer()  # 0 = Open, 1 = Started, 2 = Complete
    start_date = Date()
    finish_date = Date()
    require_previous_step_complete = Boolean()  # Should the previous step be complete before this one can be started


class CaseTemplate(base.BaseDocument):
    '''
    A Case Template represents a static format that a case can
    be created from when the work path is clearly defined
    '''

    title = Keyword()
    description = Text(fields={'keyword':Keyword()})
    severity = Integer()  # The default severity of the case
    owner = Keyword()  # The default owner of the case
    tlp = Integer()  # The default TLP of the case
    tags = Keyword()
    tasks = Nested(CaseTemplateTask)

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-case-templates'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def title_search(self, search):
        '''
        Searches for a title based on a wildcard
        '''
        search = self.search().query('wildcard', title=search+'*')
        results = search.execute()
        if results:
            return list(results)
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
