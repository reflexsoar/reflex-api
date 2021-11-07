import json
import pandas as pd

class CustomJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, object):
            return o.__dict__
        return json.JSONEncoder.default(self, o) 

class Event(object):

    def __init__(self, title, description, status, tlp, severity, raw_log, observables):

        self.title = title
        self.description = description
        self.status = status
        self.tlp = tlp
        self.severity = severity
        self.raw_log = raw_log
        self.observables = observables

    def attr(self, attributes, name, default, error=None):
        ''' Fetches an attribute from the passed dictionary '''
        
        is_required = error is not None

        if is_required and name not in attributes:
            ValueError(error)
        else:
            return attributes.get(name, default)

    def jsonify(self):
        ''' Returns a json string of the object '''

        return json.dumps(self, sort_keys=True, indent=4, cls=CustomJsonEncoder)

class Observable(object):

    def __init__(self, data_type, value, source_field, tlp, ioc, spotted, safe, tags):

        self.data_type = data_type
        self.value = value
        self.source_field = source_field
        self.tlp = tlp
        self.spotted = spotted
        self.safe = safe
        self.tags = tags
        self.ioc = ioc

    def attr(self, attributes, name, default, error=None):
        ''' Fetches an attribute from the passed dictionary '''
        
        is_required = error is not None

        if is_required and name not in attributes:
            ValueError(error)
        else:
            return attributes.get(name, default)

    def jsonify(self):
        ''' Returns a json string of the object '''

        return json.dumps(self, sort_keys=True, indent=4, cls=CustomJsonEncoder)

event_1_observables = [
    Observable('host','BRIAN-PC','host.name',1,False,False,False,['source-user']),
    Observable('user','Brian','host.name',1,False,False,False,['source-user'])
]

event_2_observables = [
    Observable('host','BRIAN-PC','host.name',1,False,False,False,['source-user']),
    Observable('user','Dave','host.name',1,False,False,False,['source-user'])
]

events = [
    Event('Test Event', 'Something bad happened', 'New', 1, 2, '', event_1_observables),
    Event('Test Event #2', 'Something bad happened', 'New', 1, 2, '', event_2_observables)
]

print('value in  ["brian","dave"] and data_type == "user"')
df = pd.json_normalize([json.loads(e.jsonify()) for e in events], record_path="observables")
df = df.applymap(lambda s:s.lower() if type(s) == str else s)
print(df.query('value in  ["brian","dave"] and data_type == "user"'))
