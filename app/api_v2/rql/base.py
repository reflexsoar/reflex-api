import re
import ipaddress
from app.api_v2.model import ThreatList

from flask_restx import marshal
from .mutators import MUTATOR_MAP, MUTATORS

def get_nested_field(message: dict, field: str):
    '''
    Iterates over nested fields to get the final desired value
    e.g signal.rule.name should return the value of name

    Paramters:
        message (dict): A dictionary of values you want to iterate over
        field (str): The field you want to extract from the message in dotted format

    Return:
        value: The extracted value, may be the response from this function calling itself again
    '''

    if isinstance(field, str):
        args = field.split('.')
    else:
        args = field

    if args and message:
        element = args[0]
        if element:
            if isinstance(message, list):
                values = []
                value = [m for m in message if m is not None]
                if any(isinstance(i, list) for i in value):
                    for l in value:
                        if isinstance(l, list):
                            values += [v for v in l if v is not None]
                else:
                    values += [v for v in value if not isinstance(v, list)]
                value = values                    
            else:
                if isinstance(message, dict):
                    value = message.get(element)
                else:
                    value = message

            if isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    if len(args) > 1:
                        value = [get_nested_field(item, args[1:]) for item in value]

                
            return value if len(args) == 1 else get_nested_field(value, args[1:])

import json

class RQLSearch:

    @classmethod
    def execute(cls, data, query, marshaller=None):
        '''
        Executes the expressions in the RQLSearch class

        :param cls: This class
        :param data: The data to search against
        :param query: The query to run
        '''

        if any(isinstance(x, dict) for x in data):
            return filter(query, data)
        
        if any(hasattr(x, '__class__') for x in data):
            events = []
            for item in data:
                if item.__class__.__name__ == 'Event':
                    response = filter(query, [json.loads(json.dumps(marshal(item, marshaller)))])
                    if len(list(response)) > 0:
                        events.append(item)
            return events
        return filter(query, data)

    class BaseExpression:
        '''
        A base expression that contains a lot of code used by each expression
        '''

        def __init__(self, mutators=[], **target):
            self.has_key = False
            self.mutators = mutators
            self.target_value = None
            self.any_mode = True
            self.all_mode = False
            self.organization = None

            # Setting the allowed_mutators each expression is allowed to run, default to all
            self.allowed_mutators = MUTATORS
            [[self.key, self.value]] = target.items()

        def get_target_value(self, obj):
            '''
            Dives down into the object and gets the target value
            '''

            if self.key in obj:
                self.target_value = obj[self.key]
                self.has_key = True
            else:
                if '.' in self.key:
                    self.target_value = get_nested_field(obj, self.key)
                    if self.target_value is not None:
                        self.has_key = True

        def run_mutators(self):
            '''
            Runs all the mutators defined against the target_value
            '''
            if self.target_value:
                for mutator in self.mutators:
                    if mutator in self.allowed_mutators:
                        if mutator not in ['all', 'any']:
                            self.target_value = MUTATOR_MAP[mutator](self.target_value)
                        elif mutator == 'all':
                            self.all_mode = True
                            self.any_mode = False
                        elif mutator == 'any':
                            self.any_mode = True
                            self.all_mode = False

        def __call__(self, obj):

            self.target_value = None
            self.has_key = False

            self.get_target_value(obj)
            self.run_mutators()


    class StartsWith(BaseExpression):
        '''
        Detects if a string starts with another string
        '''
        
        def __call__(self, obj):

            super().__call__(obj)

            if self.target_value:
                if isinstance(self.target_value, list):
                    return self.has_key and any([s for s in self.target_value if s.startswith(self.value)])
                else:
                    return self.has_key and self.target_value.startswith(self.value)
            return False


    class EndsWith(BaseExpression):
        '''
        Detects if a string starts with another string
        '''
        
        def __call__(self, obj):

            super().__call__(obj)

            if isinstance(self.target_value, list):
                return self.has_key and any([s for s in self.target_value if s.endswith(self.value)])
            else:
                return self.has_key and self.target_value.endswith(self.value)

    class Match(BaseExpression):
        '''
        Detects if a string or list of strings equals a specified value
        '''
        
        def __call__(self, obj):

            super().__call__(obj)

            # Handle number comparisons
            if isinstance(self.value, (int, float)):
                if isinstance(self.target_value, list) and isinstance(self.value, (int, float)):
                    self.target_value = len(self.target_value)

                # REMOVED 2022-03-21 - BC, not sure this is even needed and it was breaking some rules
                # .e.g raw_log.suricata.eve.alert.severity = 1
                #if isinstance(self.target_value, str):
                #    self.target_value = 1

            if isinstance(self.target_value, list):
                return self.has_key and self.value in self.target_value
            else:
                return self.has_key and self.value == self.target_value

    class Contains(BaseExpression):
        '''
        Detects if a string contains a sub-string
        '''

        def __call__(self, obj):

            super().__call__(obj)

            if self.target_value:
                if isinstance(self.target_value, list):
                    if self.all_mode:
                        if isinstance(self.value, list):
                            return self.has_key and all([v in self.target_value for v in self.value])
                        else:
                            return self.has_key and all([v in self.target_value for v in self.value])
                    else:
                        if isinstance(self.value, str):
                            return self.has_key and any([self.value in v for v in self.target_value])
                        else:
                            return self.has_key and any([v in self.target_value for v in self.value])
                else:
                    
                    if isinstance(self.value, list) and isinstance(self.target_value, (list, str)):
                        return any([v in self.target_value for v in self.value])
                        
                    return self.has_key and self.value in self.target_value
            return False


    class ContainsCIS(BaseExpression):
        '''
        Detects if a string contains a case insensitive sub-string
        '''

        def __call__(self, obj):

            super().__call__(obj)

            if isinstance(self.target_value, list):
                self.target_value = [v.lower() for v in self.target_value]
            else:
                self.target_value = self.target_value.lower()

            if isinstance(self.value, list):
                self.value = [v.lower() for v in self.value]
            else:
                self.value = self.value.lower()

            if self.target_value:
                if isinstance(self.target_value, list):
                    if self.all_mode:
                        if isinstance(self.value, list):
                            return self.has_key and all([v in self.target_value for v in self.value])
                            #return self.has_key and sorted(self.value) == sorted(self.target_value)
                        else:
                            return self.has_key and all([v in self.target_value for v in self.value])
                    else:
                        if isinstance(self.value, str):
                            return self.has_key and any([self.value in v for v in self.target_value if isinstance(v, str)])
                        else:
                            return self.has_key and any([v in self.target_value for v in self.value])
                else:
                    
                    if isinstance(self.value, list) and isinstance(self.target_value, (list, str)):
                        return any([v in self.target_value for v in self.value])
                        
                    return self.has_key and self.value in self.target_value
            return False


    class In(BaseExpression):
        def __init__(self, mutators=[], **target):
            
            super().__init__(mutators=mutators, **target)
            self.allowed_mutators = ['any','all','lowercase','uppercase']

        def __call__(self, obj):
            
            super().__call__(obj)
            
            # The target value from a nested field can come back empty in some instances
            # so return False if its empty cuz it definitely doesn't match
            if self.target_value:
                if isinstance(self.target_value, str):
                    return self.has_key and any([a for a in self.value if self.target_value == a])
                if isinstance(self.target_value, list):
                    if self.all_mode:
                        if isinstance(self.value, list):
                            return self.has_key and all([v in self.target_value for v in self.value])
                            #return self.has_key and sorted(self.value) == sorted(self.target_value)
                        else:
                            return self.has_key and all([a == self.value for a in self.target_value])
                    if self.any_mode:
                        return self.has_key and any([a in self.value for a in self.target_value])

    class Or:
        def __init__(self, *predicates):
            self.predicates = predicates

        def __call__(self, record):
            return any(predicate(record) for predicate in self.predicates)


    class And:
        def __init__(self, *predicates):
            self.predicates = predicates

        def __call__(self, record):
            return all(predicate(record) for predicate in self.predicates)


    class Not:
        def __init__(self, *predicates):
            self.predicates = predicates

        def __call__(self, record):
           return all(predicate(record) == False for predicate in self.predicates)

    class Expand(BaseExpression):
        ''' 
        Expands a list of dictionarys allow you two compare two or more values of the target
        dictionary
        '''

        def __init__(self, *predicates, key=''):
            self.predicates = predicates
            self.key = key

            super().__init__(mutators=[], **{self.key: None})
        
        def __call__(self, obj):

            super().__call__(obj)

            # Must be a list of dictionaries
            if isinstance(self.target_value, list):
                results = []
                for v in self.target_value:

                    # Can only target dictionaries with this expand function
                    if isinstance(v, dict):
                        result = [predicate(v) for predicate in self.predicates][0]
                        results.append(result)
                    else:
                        results.append(False)
                return any(results)


    class RegExp(BaseExpression):
        '''
        Returns True if a value matches the defined regular expression
        '''

        def __call__(self, obj):

            super().__call__(obj)

            regex = re.compile(self.value)
            if isinstance(self.target_value, str):
                return self.has_key and regex.match(self.target_value)
            else:
                return False


    class InCIDR(BaseExpression):
        '''
        Returns True if an IP address in the specified CIDR range
        '''

        def __call__(self, obj):

            super().__call__(obj)

            try: 
                network = ipaddress.ip_network(self.value) 
            except ValueError: 
                network = None

            try:
                if isinstance(self.target_value, list):
                    target_values = []
                    for value in self.target_value:
                        try:
                            target_values.append(ipaddress.ip_address(value))
                        except:
                            pass
                    self.target_value = target_values
                else:
                    self.target_value = ipaddress.ip_address(self.target_value)

            except ValueError:
                self.target_value = None

            if not network:
                return False
            if not self.target_value:
                return False

            if isinstance(self.target_value, list) and len(self.target_value) > 0:
                return self.has_key and any([ip for ip in self.target_value if ip in network])
            else:
                return self.has_key and self.target_value in network


    class MathOp(BaseExpression):
        '''
        Returns True if the math expression is true
        '''

        def __init__(self, mutators=[], operator=">", **target):
            
            self.operator = operator
            self.mutators = mutators
            
            self.op_map = {
                '>': self.gt,
                'gt': self.gt,
                '>=': self.gte,
                'gte': self.gte,
                'lt': self.lt,
                '<': self.lt,
                'lte': self.lte,
                '<=': self.lte
            }

            super().__init__(mutators=mutators, **target)

            self.allowed_mutators = ['count','length']

        def lte(self, left, right):
            ''' Returns the result of left <= right '''
            return left <= right

        def lt(self, left, right):
            ''' Returns the result of left < right '''
            return left < right

        def gte(self, left, right):
            ''' Returns the result of left >= right '''
            return left >= right

        def gt(self, left, right):
            ''' Returns the result of left > right '''
            return left > right
        
        def __call__(self, obj):

            super().__call__(obj)

            if self.target_value:
                # If the target value is a list, calculate how many items are in the list
                if isinstance(self.target_value, list):
                    self.target_value = len(self.target_value)

                # If the target value is a string there is only one item
                if isinstance(self.target_value, str):
                    self.target_value = 1

                return self.has_key and self.op_map[self.operator](self.target_value, self.value)
            return False


    class Between(BaseExpression):
        '''
        Returns True if the field is target_value is in a specified range
        '''
        def __init__(self, mutators=[], **target):
            
            super().__init__(mutators=mutators, **target)

            self.allowed_mutators = ['count','length']

            if isinstance(self.value, str):
                self.value.replace('-',',')
                self.value.replace('..',',')
                start, end = self.value.split(',')

                # Add a +1 to the end to include the upper end which is not how
                # python behaves normally
                start, end = int(start), int(end)+1

                self.value = range(start, end)
        
        def __call__(self, obj):

            super().__call__(obj)

            if self.target_value:
                if isinstance(self.target_value, list):
                    self.target_value = len(self.target_value)
                
                if isinstance(self.target_value, str):
                    self.target_value = 1

            return self.has_key and self.target_value in self.value


    class Exists(BaseExpression):
        '''
        Returns True if the item has the dictionary key
        '''
        def __init__(self, field, mutators=[]):
            self.has_key = False
            self.key = field
            self.mutators = mutators

        def __call__(self, obj):

            super().__call__(obj)

            return self.has_key


    class Is(BaseExpression):
        '''
        Returns True if the item has value that matches a boolean
        '''
        def __init__(self, mutators=[], **target):

            super().__init__(mutators=mutators, **target)

            # Convert any representation of booleans to a true boolean type
            self.value = self.to_boolean(self.value)

        def to_boolean(self, value):

            if isinstance(value, bool) and value in [True, False]:
                return value

            if isinstance(value, str):
                if value.lower() in ['true','false']:
                    if value.lower() == 'true':
                        return True
                    return False

        def __call__(self, obj):

            super().__call__(obj)

            # Convert any representation of booleans to a true boolean type
            if self.target_value:
                self.target_value = self.to_boolean(self.target_value)

            if not isinstance(self.target_value, bool):
                return False
            return self.has_key and self.value == self.target_value

    class ThreatLookup(BaseExpression):
        '''
        Returns True if an item matches a defined threat list
        '''

        def __init__(self, organization=None, mutators=[], **target):
            
            super().__init__(mutators=mutators, **target)
            self.allowed_mutators=['lowercase','uppercase']
            self.organization = organization

        def __call__(self, obj):

            super().__call__(obj)

            threat_list = ThreatList.search()
            threat_list = threat_list.filter('term', name=self.value)

            if self.organization:
                threat_list = threat_list.filter('term', organization=self.organization)

            threat_list = threat_list.execute()
            
            if threat_list:
                threat_list = threat_list[0]
                return threat_list.check_value(self.target_value) > 0
            else:
                return False
