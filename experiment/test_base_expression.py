from rql import MUTATOR_MAP, get_nested_field

class BaseExpression(object):
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

        self.has_key = False
        self.target_value = None


class StartsWith(BaseExpression):
    '''
    Detects if a string starts with another string
    '''

    def __call__(self, obj):

        super().__call__(obj)

        self.get_target_value(obj)
        self.run_mutators()

        if self.target_value:
            if isinstance(self.target_value, list):
                return self.has_key and any([s for s in self.target_value if s.startswith(self.value)])
            else:
                return self.has_key and self.target_value.startswith(self.value)
        return False


if __name__ == "__main__":

    db = [
      {'title':'Test', 'description': 'Amazing', 'test': {'awesome': 'yes'}, 'observables': [{'value':'Brian', 'more': {'data':'okay'}, 'tlp': 1, 'tags': [{'name':'a'},{'name':'b'},{'name':'c'}]},{'value':'Dave', 'tags': [{'name':'foo'},{'name':'bar'},{'name':'deadbeef'}]}]},
      {'title':'Test', 'description': 'Amazing', 'test': {'awesome': 'no'}, 'observables': [{'value':'Brian', 'more': {'data':'okay'}, 'tlp': 1, 'tags': [{'name':'a'},{'name':'b'},{'name':'c'}]},{'value':'Dave', 'tags': [{'name':'foo'},{'name':'bar'},{'name':'deadbeef'}]}]},
      {'title':'Test Event', 'description': 'This is a dangerous event', 'test': {'awesome': 'yes'}, 'observables': [{'value':'Brian', 'more': {'data':'okay'}, 'tlp': 1, 'tags': [{'name':'a'},{'name':'b'},{'name':'c'}]},{'value':'Dave', 'tags': [{'name':'foo'},{'name':'bar'},{'name':'deadbeef'}]}]},
      {'title':'Test Event', 'description': 'This is a dangerous event', 'test': {'awesome': 'yes'}, 'observables': [{'value':'Brian'},{'value':'Dave'}]},
      {'title':'Test Smaller Event', 'test': {'awesome': 'no'}, 'observables': [{'value':'Brian'},{'value':'Dave'}]},
      {'title':'Test Smaller Event', 'test': {'awesome': 'no'}, 'observables': [{'value':'192.168.0.1'},{'value':'Dave'}]},
      {'title':'Test Smaller Event', 'test': {'awesome': 'no'}, 'observables': [{'value':'192.168.0.1'}]},
      {'title':'Test Event from API', 'from_api': True},
      {'title': 'Test with IP in parent', 'ip': '192.168.1.1'},
      {'title': 'Test with IP in parent and malware', 'ip': '192.168.1.1', 'malware': True},
      {'title':'Test Event', 'tlp': 1},
      {'title':'Test Event', 'tlp': 2},
      {'title':'Test Event', 'tlp': 3},
      {'title':'Test Event', 'tlp': 4},
      {'first': 'john', 'last': 'doe', 'likes': ['cookies', 'http']},
      {'url':'hXXp[:]//www[.]google[.]com', 'title':'Suspicious DNS Query'},
      {'url': ['hXXp[:]//www[.]google[.]com', 'HTTP://EVIL.DE']},
      {'url': 'https://www.reflexsoar.com/test?user=%3Cscript%3Ealert(xss);%3C/script%3E'},
      {'url': 'SFRUUFM6Ly9XV1cuUkVGTEVYU09BUi5DT00vVEVTVD9VU0VSPSUzQ1NDUklQVCUzRUFMRVJUKFhTUyk7JTNDL1NDUklQVCUzRQ=='}, # From base64, decode, lower
      {'command':'SW52b2tlLU1pbWlrYXR6'},
      {'first': 'jane', 'last': 'doe', 'likes': ['cookies', 'donuts']},
      {'first': 'danny', 'last': 'foo', 'likes': ['http', 'donuts']},
      {'first': 'john', 'last': 'carroll', 'likes': ['golf','cookies']},
      {'first': 'john', 'last': 'CaRrOll', 'likes': ['golf','cookies']},
      {'ip':'192.168.1.1'}
    ]

    query = StartsWith(**{'observables.value':'Brian'})
    results = filter(query, db)
    for result in results:
        print(result)