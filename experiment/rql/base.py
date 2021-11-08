import re
import base64
import ipaddress
from .mutators import MUTATOR_MAP

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
                value = message.get(element)

            if isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    if len(args) > 1:
                        value = [get_nested_field(item, args[1:]) for item in value]

                
            return value if len(args) == 1 else get_nested_field(value, args[1:])


class RQLSearch:

    @classmethod
    def execute(cls, data, query):
        '''
        Executes the expressions in the RQLSearch class

        :param cls: This class
        :param data: The data to search against
        :param query: The query to run
        '''
        return filter(query, data)

    class StartsWith:
        '''
        Detects if a string starts with another string
        '''

        def __init__(self, mutators=[], **target):
            self.has_key = False
            self.mutators = mutators
            [[self.key, self.value]] = target.items()
        
        def __call__(self, obj):

            target_value = None

            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True

            # Run all the mutators
            if target_value:
                for mutator in self.mutators:
                    target_value = MUTATOR_MAP[mutator](target_value)

            if target_value:
                if isinstance(target_value, list):
                    return self.has_key and any([s for s in target_value if s.startswith(self.value)])
                else:
                    return self.has_key and target_value.startswith(self.value)
            return False


    class EndsWith:
        '''
        Detects if a string starts with another string
        '''

        def __init__(self, mutators=[], **target):
            self.has_key = False
            self.mutators = mutators
            [[self.key, self.value]] = target.items()
        
        def __call__(self, obj):

            target_value = None

            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True

            # Run all the mutators
            if target_value:
                for mutator in self.mutators:
                    target_value = MUTATOR_MAP[mutator](target_value)

            if isinstance(target_value, list):
                return self.has_key and any([s for s in target_value if s.endswith(self.value)])
            else:
                return self.has_key and target_value.endswith(self.value)

    class Match:
        '''
        Detects if a string or list of strings equals a specified value
        '''
        def __init__(self, mutators=[], **target):
            self.has_key = False
            self.mutators = mutators
            [[self.key, self.value]] = target.items()
        
        def __call__(self, obj):

            target_value = None

            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True

            # Run all the mutators
            if target_value:
                for mutator in self.mutators:
                    target_value = MUTATOR_MAP[mutator](target_value)

            # Handle number comparisons
            if isinstance(self.value, (int, float)):
                if isinstance(target_value, list) and isinstance(self.value, (int, float)):
                    target_value = len(target_value)

                if isinstance(target_value, str):
                    target_value = 1

            if isinstance(target_value, list):
                return self.has_key and self.value in target_value
            else:
                return self.has_key and self.value == target_value

    class Contains:        
        def __init__(self, mutators=[], **target):

            self.has_key = False
            self.mutators = mutators

            [[self.key, self.value]] = target.items()

        def __call__(self, obj):

            target_value = None

            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True

            # Run all the mutators
            if target_value:
                for mutator in self.mutators:
                    target_value = MUTATOR_MAP[mutator](target_value)

            if target_value:
                if isinstance(target_value, list):
                    return self.has_key and any([v for v in target_value if self.value in v])
                else:
                    return self.has_key and self.value in target_value
            return False


    class ContainsCIS:
        def __init__(self, **target):
            [[self.key, self.value]] = target.items()

        def __call__(self, obj):
            return self.key in obj and self.value.lower() in obj[self.key].lower()


    class In:
        def __init__(self, **target):
            self.has_key = False
            [[self.key, self.value]] = target.items()

        def __call__(self, obj):
            
            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:            
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True
            
            # The target value from a nested field can come back empty in some instances
            # so return False if its empty cuz it definitely doesn't match
            if target_value:
                return self.has_key and bool(len([i for i in target_value if i in self.value]))
            else:
                return False

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


    class RegExp:
        '''
        Returns True if a value matches the defined regular expression
        '''

        def __init__(self, **target):
            [[self.key, self.value]] = target.items()

        def __call__(self, obj):
            regex = re.compile(self.value)
            return self.key in obj and regex.match(obj[self.key])


    class InCIDR:
        '''
        Returns True if an IP address in the specified CIDR range
        '''

        def __init__(self, **target):
            self.has_key = False
            [[self.key, self.value]] = target.items()

        def __call__(self, obj):

            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:            
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True
                else:
                    target_value = None

            try: 
                network = ipaddress.ip_network(self.value) 
            except ValueError: 
                network = None

            try:
                if isinstance(target_value, list):
                    target_values = []
                    for value in target_value:
                        try:
                            target_values.append(ipaddress.ip_address(value))
                        except:
                            pass
                    target_value = target_values
                else:
                    target_value = ipaddress.ip_address(target_value)

            except ValueError:
                target_value = None

            if not network:
                return False
            if not target_value:
                return False

            if isinstance(target_value, list) and len(target_value) > 0:
                return self.has_key and any([ip for ip in target_value if ip in network])
            else:
                return self.has_key and target_value in network


    class MathOp:
        '''
        Returns True if the math expression is true
        '''

        def __init__(self, mutators=[], operator=">", count=False, length=False, **target):
            
            self.has_key = False
            self.count = count
            self.length = length
            self.operator = operator
            self.mutators = mutators

            [[self.key, self.value]] = target.items()

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

            target_value = None
            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:            
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True
            
            # If a target_value was found
            # Run all the mutators

            print(target_value, self.operator, self.value)
            
            if target_value:
                for mutator in self.mutators:
                    target_value = MUTATOR_MAP[mutator](target_value)

                # If the target value is a list, calculate how many items are in the list
                if isinstance(target_value, list):
                    target_value = len(target_value)

                # If the target value is a string there is only one item
                if isinstance(target_value, str):
                    target_value = 1

                return self.has_key and self.op_map[self.operator](target_value, self.value)
            return False


    class Between:
        '''
        Returns True if the field is target_value is in a specified range
        '''
        def __init__(self, **target):
            [[self.key, self.value]] = target.items()

            if isinstance(self.value, str):
                self.value.replace('-',',')
                self.value.replace('..',',')
                start, end = self.value.split(',')

                # Add a +1 to the end to include the upper end which is not how
                # python behaves normally
                start, end = int(start), int(end)+1

                self.value = range(start, end)
        
        def __call__(self, obj):
            return self.key in obj and obj[self.key] in self.value

    class Exists:
        '''
        Returns True if the item has the dictionary key
        '''
        def __init__(self, field):
            self.has_key = False
            self.key = field

        def __call__(self, obj):

            if self.key in obj:
                return True
            else:            
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True

            return self.has_key

    class Is:
        '''
        Returns True if the item has value that matches a boolean
        '''
        def __init__(self, **target):
            self.has_key = False
            [[self.key, self.value]] = target.items()

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

            target_value = None
            if self.key in obj:
                target_value = obj[self.key]
                self.has_key = True
            else:            
                if '.' in self.key:
                    target_value = get_nested_field(obj, self.key)
                    if target_value is not None:
                        self.has_key = True

            # Convert any representation of booleans to a true boolean type
            if target_value:
                target_value = self.to_boolean(target_value)

            if not isinstance(target_value, bool):
                return False
            return self.has_key and self.value == target_value
            

if __name__ == "__main__":

    import json

    positive_tests = {
        1: '{"tlp": 1}',
        2: '{"tlp": 2}',
        3: '{"tlp": 3}',
        4: '{"tlp": 4}',
        5: '{"tlp": 5}',
        6: '{"tlp": 1, "spotted": 1}',
        7: '{"tlp": 1, "malware": true}',
        8: '{"tlp": 1, "malware": false}'
    }

    search = RQLSearch

    queries = [
        search.MathOp(operator=">", tlp=1),
        search.MathOp(operator=">=", tlp=2),
        search.MathOp(operator="<", tlp=3),
        search.MathOp(operator="<=", tlp=2),
        search.Exists('spotted'),
        search.And(search.Exists('malware'), search.Is(malware=True)),
        search.Between(tlp="1,3")
    ]

    for query in queries:
        result = search.execute([json.loads(positive_tests[i]) for i in positive_tests], query)
        matches = []
        for r in result:
            matches += [i for i in positive_tests if positive_tests[i] == json.dumps(r)]
        
        print(matches)