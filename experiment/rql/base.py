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

    class BaseExpression:
        '''
        A base expression that contains a lot of code used by each expression
        '''

        def __init__(self, mutators=[], **target):
            self.has_key = False
            self.mutators = mutators
            self.target_value = None
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
                    self.target_value = MUTATOR_MAP[mutator](self.target_value)

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

                if isinstance(self.target_value, str):
                    self.target_value = 1

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
                    return self.has_key and any([v for v in self.target_value if self.value in v])
                else:
                    return self.has_key and self.value in self.target_value
            return False


    class ContainsCIS(BaseExpression):
        '''
        Detects if a string contains a case insensitive sub-string
        '''

        def __call__(self, obj):

            super().__call__(obj)
            return self.has_key and self.value.lower() in self.target_value.lower()


    class In:
        def __init__(self, **target):
            self.has_key = False
            [[self.key, self.value]] = target.items()

        def __call__(self, obj):
            
            super().__call__(obj)
            
            # The target value from a nested field can come back empty in some instances
            # so return False if its empty cuz it definitely doesn't match
            if self.target_value:
                return self.has_key and bool(len([i for i in self.target_value if i in self.value]))
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


    class RegExp(BaseExpression):
        '''
        Returns True if a value matches the defined regular expression
        '''

        def __call__(self, obj):

            super().__call__(obj)

            regex = re.compile(self.value)
            return self.key in obj and regex.match(self.target_value)


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