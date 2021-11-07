import re
import ast
import ipaddress

import pandas
import ply.lex as lex
import ply.yacc as yacc
from rql import RQLSearch

if __name__ == '__main__':

    event = {
    "title": "This is my event",
    "description": "This is a super awesome event.",
    "venues": [
        {
            "name": "Lincoln Financial Field",
            "address": "One Lincoln Financial Field Way",
            "city": "Philadelphia",
            "tags": ["Eagles"]
        },
        {
            "name": "Wells Fargo Center",
            "address": "3601 S Broad St.",
            "city": "Philadelphia",
            "tags": ["Flyers","Sixers","Concerts"]
        },
        {
            "name": "Prudential Center",
            "address": "25 Lafayette St",
            "city": "Newark",
            "tags": ["Devils","Bad Teams"]
        }
   ],
   "ticket_price": 50.00,
   "status": "New",
}
    db = [
      {'title':'Test', 'description': 'Amazing', 'test': {'awesome': 'yes'}, 'observables': [{'value':'Brian', 'more': {'data':'okay'}, 'tlp': 1, 'tags': [{'name':'a'},{'name':'b'},{'name':'c'}]},{'value':'Dave', 'tags': [{'name':'foo'},{'name':'bar'},{'name':'deadbeef'}]}]},
      {'title':'Test Event', 'description': 'This is a dangerous event', 'test': {'awesome': 'yes'}, 'observables': [{'value':'Brian', 'more': {'data':'okay'}, 'tlp': 1, 'tags': [{'name':'a'},{'name':'b'},{'name':'c'}]},{'value':'Dave', 'tags': [{'name':'foo'},{'name':'bar'},{'name':'deadbeef'}]}]},
      {'title':'Test Event', 'description': 'This is a dangerous event', 'test': {'awesome': 'yes'}, 'observables': [{'value':'Brian'},{'value':'Dave'}]},
      {'title':'Test Smaller Event', 'test': {'awesome': 'no'}, 'observables': [{'value':'Brian'},{'value':'Dave'}]},
      {'title':'Test Smaller Event', 'test': {'awesome': 'no'}, 'observables': [{'value':'192.168.0.1'},{'value':'Dave'}]},
      {'title': 'Test with IP in parent', 'ip': '192.168.1.1'},
      {'title': 'Test with IP in parent and malware', 'ip': '192.168.1.1', 'malware': True},
      {'title':'Test Event', 'tlp': 1},
      {'title':'Test Event', 'tlp': 2},
      {'title':'Test Event', 'tlp': 3},
      {'title':'Test Event', 'tlp': 4},
      {'first': 'john', 'last': 'doe', 'likes': ['cookies', 'http']},
      #{'first': 'jane', 'last': 'doe', 'likes': ['cookies', 'donuts']},
      #{'first': 'danny', 'last': 'foo', 'likes': ['http', 'donuts']},
      #{'first': 'john', 'last': 'carroll', 'likes': ['golf','cookies']},
      #{'first': 'john', 'last': 'CaRrOll', 'likes': ['golf','cookies']},
      #{'ip':'192.168.1.1'},
    ]

    #print(f"Data Set:")
    #for d in db:
    #    print(d)
    
    #print()
    query_string = '(title = "Test Event" AND description contains "dangerous" AND observables.tags.name In ["foo"]) OR title = "Test Smaller Event"'
    #query_string = 'observables.tags.name = "Molly"'
    #query_string = 'title = "Test Event"'
    #query_string = '''
    # This is a comment
    #observables.tags.name In ["foo","bar"]
    #'''
    #print(f'Query: {query_string}')

    #print(Match(title='Test Event'))

    search = RQLSearch()
    
    #query = Or(And(Match(title="Test Event"), Contains(description="dangerous"), In(**{"observables.tags.name": ["foo"]})), Match(title="Test Smaller Event"))
    #query = Match(**{'observables.tags.name': 'foo'})
    #query = Between(tlp=range(5))
    query = search.GreaterThanOrEqual(tlp=1)

    import json
    for r in search.execute(db, query):
        print(json.dumps(r, indent=2))
    
    #tree = ast.parse(query_string)
    #print(tree.body)

    tokens = (
        'NUMBER',
        'FLOAT',
        'LPAREN',
        'RPAREN',
        'EQUALS',
        'STRING',
        'ARRAY',
        'CONTAINS',
        'GT',
        'GTE',
        'LT',
        'LTE',
        'IN',
        'AND',
        'OR',
        'CIDR',
        'target',
        'BOOL',
        'EXISTS',
        'REGEXP'
    )

    precedence = (
        ('left', 'OR'),
        ('left', 'AND'),
        ('nonassoc', 'EQUALS'),
        ('nonassoc', 'IN'),
        ('nonassoc', 'CONTAINS')
    )

    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_EQUALS = r'=|eq'
    t_CIDR = r'cidr|InCIDR'
    t_CONTAINS = r'contains|Contains'
    t_IN = r'In|in'
    t_AND = r'and|AND|And|\&\&'
    t_OR = r'or|OR|Or|\|\|'
    t_GT = r'>|gt'
    t_GTE = r'>=|gte'
    t_LT = r'<|lt'
    t_LTE = r'<=|lte'
    t_BOOL = r'True|true|False|false'
    t_EXISTS = r'Exists|exists'
    t_REGEXP = r'RegExp|regexp|regex|re'
   
    def t_NUMBER(t):
        r'\d+'
        t.value = ast.literal_eval(t.value)
        return t

    def t_FLOAT(t):
        r'\d+\.?\d+$'
        t.value = ast.literal_eval(t.value)
        return t        

    def t_STRING(t):
        r'[\"|\'](.*?)[\"|\']'
        t.value = ast.literal_eval(t.value)
        return t

    def t_comment(t):
        r'\#.*'
        pass

    def t_newline(t):
        r'\n+'
        t.lexer.lineno ++ len(t.value)

    def t_target(t):
        # TODO: Define all the fields a user can access here
        r'observables(\.([^\s]+))?|title|description|test\.awesome|first|tlp|ip'
        return t
    
    def t_ARRAY(t):
        r'\[([\"|\'].*[\"|\'])\]'
        t.value = ast.literal_eval(t.value)
        return t

    t_ignore = ' \t./'

    def t_error(t):
        print("Illegal character '%s'" % t.value[0])

    lexer = lex.lex()
    while True:
        q = input('Query: ')
        if not q:
            break
        lexer.input(q)
        if q == 'exit':
            exit
        if q == 'yacc':
            break
        while True:
            tok = lexer.token()
            if not tok:
                break
            print(tok)

    def p_expression(p):
        'expression : target'
        p[0] = p[1]

    def p_expression_or(p):
        'expression : expression OR expression'
        p[0] = search.Or(p[1], p[3])

    def p_expression_and(p):
        'expression : expression AND expression'
        p[0] = search.And(p[1], p[3])
    
    def p_expression_match(p):
        'expression : target EQUALS STRING'
        p[0] = search.Match(**{p[1]:p[3]})

    def p_expression_contains(p):
        'expression : target CONTAINS STRING'
        p[0] = search.Contains(**{p[1]:p[3]})

    def p_expression_in(p):
        'expression : target IN ARRAY'
        p[0] = search.In(**{p[1]:p[3]})

    def p_expression_greater_than(p):
        '''expression : target GT NUMBER 
                   | target GT FLOAT
        '''
        p[0] = search.GreaterThan(**{p[1]: p[3]})

    def p_expression_greater_than_or_equal(p):
        '''expression : target GTE NUMBER 
                   | target GTE FLOAT
        '''
        p[0] = search.GreaterThanOrEqual(**{p[1]: p[3]})

    def p_expression_less_than(p):
        '''expression : target LT NUMBER 
                   | target LT FLOAT
        '''
        p[0] = search.LessThan(**{p[1]: p[3]})

    def p_expression_less_than_or_equal(p):
        '''expression : target LTE NUMBER 
                   | target LTE FLOAT
        '''
        p[0] = search.LessThanOrEqual(**{p[1]: p[3]})

    def p_expression_in_cidr(p):
        'expression : target CIDR STRING'
        p[0] = search.InCIDR(**{p[1]: p[3]})

    def p_expression_exists(p):
        'expression : target EXISTS'
        p[0] = search.Exists(p[1])

    def p_expression_regexp(p):
        'expression : target REGEXP STRING'
        p[0] = search.RegExp(**{p[1]: p[3]})

    #def p_grouping(p):
    #    'unary_expression : LPAREN expression RPAREN'

    def p_error(p):
        print(p)
        print("Syntax error in input!")

    parser = yacc.yacc()
    while True:
        s = input('query: ')
        if not s:
            break
        if s == 'exit':
            exit()
        result = parser.parse(s)
        for event in search.execute(db, result):
            print(event)
        print()

    
    # NESTED FIELD TESTING
    #print("venues.name", get_nested_field(event, "venues.name"))
    #print("venues.tags", get_nested_field(event, "venues.tags"))

    #print("description:", get_nested_field(db[0],"description"))
    #print("test.awesome:", get_nested_field(db[0],"test.awesome"))
    #print("observables.more.data:", get_nested_field(db[0],"observables.more.data"))
    #print("observables.tags:", get_nested_field(db[0],"observables.tags"))
    #print("observables.tags.name:", get_nested_field(db[0],"observables.tags.name"))
    #print("observables.tlp:", get_nested_field(db[0],"observables.tlp"))
    
    """
    print('(first = "john" OR last = "doe") AND likes Contains "cookies"')
    query = And(Or(Match(first='john'), Match(last='doe')), Contains(likes='cookies'))
    for result in run_query(db, query):
        print(result)

    print()
    print('first RegExp "^jo.*"')
    query = RegExp(first='^jo.*')
    for result in run_query(db, query):
        print(result)

    print()
    print('first = "john" and likes In ["cookies"]')
    query = And(Match(first="john"), In(likes=['cookies']))
    for result in run_query(db, query):
        print(result)

    print()
    print('last ContainsCIS "carroll" AND likes In ["cookies"]')
    query = And(ContainsCIS(last="carroll"), In(likes=['cookies']))
    for result in run_query(db, query):
        print(result)

    print()
    print('ip InCIDR "192.168.0.0/16"')
    query = InCIDR(ip="192.168.0.0/16")
    for result in run_query(db, query):
        print(result)
    """
