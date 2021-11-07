import re
import ast

class Event(object):

    def __init__(self, title, description, status, tlp, severity, raw_log, observables):

        self.title = title
        self.description = description
        self.status = status
        self.tlp = tlp
        self.severity = severity
        self.raw_log = raw_log
        self.observables = observables

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

def get_nested_field(self, message, field):
        '''
        Iterates over nested fields to get the final desired value
        e.g signal.rule.name should return the value of name
        '''

        if isinstance(field, str):
            args = field.split('.')
        else:
            args = field

        if args and message:
            element = args[0]
            if element:
                value = message.get(element)
                return value if len(args) == 1 else self.get_nested_field(value, args[1:])

QUERY = 'event.title = "Test Event"'

def parse_query(query, target_object):

    if 'AND' in query:
        query_parts = query.split(' AND ')

    match = True
    for query_part in query_parts:
        
        ops = ['=','!=','<','>','RegExp','Contains','In']
        expression = None
        for op in ops:
            if op in query_part:

                block = query_part.split(f" {op} ")
                if re.match('^[0-9]*$', block[1]):
                    block[1] = int(block[1])
                elif re.match('\((\".*\",?)+\)', block[1]):
                    block[1] = block[1][1:][:-1].split(',')
                    print(block[1])
                elif not re.match('^[0-9]*$', block[1]):
                    block[1] = block[1][1:][:-1]

                expression = {op: {block[0]: block[1]}}

        if expression:
            print(expression)

            for op in expression:
                for k in expression[op]:
                    if '.' in k:
                        field_parts = k.split('.')
                    else:
                        field_parts = k
                    if op == "=":
                        if hasattr(target_object, str(field_parts[1])):
                            match = getattr(target_object, str(field_parts[1])) == expression[op][k]

                    if op == "!=":
                        print("NOT EQUALS")

                    if op == "<":
                        print("LESS THAN")

                    if op == ">":
                        if hasattr(target_object, str(field_parts[1])):
                            match = getattr(target_object, str(field_parts[1])) > expression[op][k]

                    if op == "RegExp":
                        print("REGEX")
                    if op == "Contains":
                        print("Contains")
                    if op == "In":
                        
                        print("LIST")
    return match

print(parse_query('event.title In ("Test Event","Test Event #2") AND event.tlp > 0', events[0]))
#for event in events:
#    if parse_query('event.title = "Test Event" AND event.tlp = 1', event):
#        print(event.title)
