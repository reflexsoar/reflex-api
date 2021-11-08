import ast
import ply.lex as lex
import ply.yacc as yacc
from rql import RQLSearch, MUTATORS
from ply.lex import LexError

if __name__ == '__main__':

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
      {'ip':'192.168.1.1'},
      {'ip': '198.199.134.100'}
    ]

    query_string = '(title = "Test Event" AND description contains "dangerous" AND observables.tags.name In ["foo"]) OR title = "Test Smaller Event"'

    search = RQLSearch()

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
        'REGEXP',
        'IS',
        'BETWEEN',
        'MUTATOR',
        'SWITH',
        'EWITH',
        'NOT'
    )

    precedence = (
        ('left', 'OR'),
        ('left', 'AND'),
        ('nonassoc', 'EQUALS'),
        ('nonassoc', 'IN'),
        ('nonassoc', 'CONTAINS'),
        ('right','STRING')
    )

    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_EQUALS = r'=|eq|Eq|EQ'
    t_CIDR = r'cidr|InCIDR'
    t_CONTAINS = r'contains|Contains'
    t_IN = r'In|in|IN'
    t_IS = r'Is|is|IS'
    t_AND = r'and|AND|And'
    t_OR = r'or|OR|Or'
    t_NOT = r'not|NOT|Not'
    t_GT = r'>|gt|GT'
    t_GTE = r'>=|gte|GTE'
    t_LT = r'<|lt|LT'
    t_LTE = r'<=|lte|LTE'
    t_BOOL = r'True|true|False|false'
    t_EXISTS = r'Exists|exists|EXISTS'
    t_REGEXP = r'RegExp|regexp|regex|re'
    t_BETWEEN = r'Between|between|InRange|range'
    t_MUTATOR = r'(\|(count|length|lowercase|b64decode|refang|urldecode|any|all))'
    t_SWITH = r'StartsWith|startswith'
    t_EWITH = r'EndsWith|endswith'
   
    def t_NUMBER(t):
        r'\d+'
        t.value = ast.literal_eval(t.value)
        return t

    def t_FLOAT(t):
        r'\d+\.?\d+$'
        t.value = ast.literal_eval(t.value)
        return t        

    def t_STRING(t):
        r'[\"\'](.*?)[\"\']'
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
        r'observables(\.((?!Count|Length)[^\s]+))?|malware|title|description|test\.awesome|from_api|tlp|ip|url|command|first|last'
        return t
    
    def t_ARRAY(t):
        r'\[([\"|\'].*[\"|\'])\]'
        t.value = ast.literal_eval(t.value)
        return t

    t_ignore = ' \t.'

    def t_error(t):
        print("Illegal character '%s'" % t.value[0])

    lexer = lex.lex()
    while True:
        q = input('[Lex Mode] Query: ')
        if not q:
            break
        if q == 'exit':
            exit()
        if q == 'yacc':
            break

        lexer.input(q)
        while True:
            try:
                tok = lexer.token()
            except LexError as e:
                tok = None
            if not tok:
                break
            print(tok)

    def extract_mutators_and_fields(p):
        mutators = []
        for part in p:

            if isinstance(part, str):
                part = part.replace('|','')

            if part in MUTATORS:
                mutators.append(part)

        field = p[1]
        target = p[-1:][0]
        operator = p[-2:][0]

        return (mutators, field, target, operator)

    def p_expression(p):
        'expression : target'
        p[0] = p[1]

    def p_expression_or(p):
        'expression : expression OR expression'
        p[0] = search.Or(p[1], p[3])

    def p_expression_and(p):
        'expression : expression AND expression'
        p[0] = search.And(p[1], p[3])

    def p_expression_singlet(p):
        'expression : LPAREN expression RPAREN'
        p[0] = p[2]

    def p_expression_and_group(p):
        'expression : LPAREN expression AND expression RPAREN'
        p[0] = search.And(p[2], p[4])

    def p_expression_or_group(p):
        'expression : LPAREN expression OR expression RPAREN'
        p[0] = search.Or(p[2], p[4])
    
    def p_expression_startswith(p):
        """expression : target SWITH STRING
                    | target MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING
        """
        mutators, field, target, op = extract_mutators_and_fields(p)
        p[0] = search.StartsWith(mutators=mutators, **{field: target})

    def p_expression_endswith(p):
        """expression : target EWITH STRING
                    | target MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING
        """
        mutators, field, target, op = extract_mutators_and_fields(p)
        p[0] = search.EndsWith(mutators=mutators, **{field: target})
    
    def p_expression_match(p):
        """expression : target EQUALS STRING
                    | target MUTATOR EQUALS STRING
                    | target MUTATOR MUTATOR EQUALS STRING
                    | target MUTATOR MUTATOR MUTATOR EQUALS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR EQUALS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EQUALS STRING
                    | target EQUALS NUMBER
                    | target NOT EQUALS STRING
                    | target MUTATOR NOT EQUALS STRING
                    | target MUTATOR MUTATOR NOT EQUALS STRING
                    | target MUTATOR MUTATOR MUTATOR NOT EQUALS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR NOT EQUALS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT EQUALS STRING
                    | target NOT EQUALS NUMBER
        """
        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True

        mutators, field, target, op = extract_mutators_and_fields(p)
        if contains_not:
            p[0] = search.Not(search.Match(mutators=mutators, **{field: target}))
        else:
            p[0] = search.Match(mutators=mutators, **{field: target})

    def p_expression_contains(p):
        """expression : target CONTAINS STRING
                    | target MUTATOR CONTAINS STRING
                    | target MUTATOR MUTATOR CONTAINS STRING
                    | target MUTATOR MUTATOR MUTATOR CONTAINS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS STRING
                    | target NOT CONTAINS STRING
                    | target MUTATOR NOT CONTAINS STRING
                    | target MUTATOR MUTATOR NOT CONTAINS STRING
                    | target MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING
                    | target CONTAINS ARRAY
                    | target MUTATOR MUTATOR CONTAINS ARRAY
                    | target MUTATOR MUTATOR MUTATOR CONTAINS ARRAY
                    | target MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS ARRAY
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS ARRAY
                    | target NOT CONTAINS ARRAY
                    | target MUTATOR NOT CONTAINS ARRAY
                    | target MUTATOR MUTATOR NOT CONTAINS ARRAY
                    | target MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY
                    | target MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True

        mutators, field, target, op = extract_mutators_and_fields(p)
        if contains_not:
            p[0] = search.Not(search.Contains(mutators=mutators, **{field: target}))
        else:
            p[0] = search.Contains(mutators=mutators, **{field: target})

    def p_expression_in(p):
        """expression : target IN ARRAY
                   | target MUTATOR IN ARRAY
                   | target NOT IN ARRAY
                   | target MUTATOR NOT IN ARRAY
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True

        mutators, field, target, op = extract_mutators_and_fields(p)
        if contains_not:
            p[0] = search.Not(search.In(mutators=mutators, **{field: target}))
        else:    
            p[0] = search.In(mutators=mutators, **{field: target})

    def p_expression_math_op(p):
        '''expression : target GT NUMBER 
                   | target GTE NUMBER
                   | target LT NUMBER
                   | target LTE NUMBER
                   | target MUTATOR GT NUMBER
                   | target MUTATOR GTE NUMBER
                   | target MUTATOR LT NUMBER
                   | target MUTATOR LTE NUMBER
                   | target GT FLOAT 
                   | target GTE FLOAT
                   | target LT FLOAT
                   | target LTE FLOAT
                   | target MUTATOR GT FLOAT
                   | target MUTATOR GTE FLOAT
                   | target MUTATOR LT FLOAT
                   | target MUTATOR LTE FLOAT
                
        '''
        mutators, field, target, op = extract_mutators_and_fields(p)
    
        p[0] = search.MathOp(mutators=mutators, operator=op, **{field: target})

    def p_expression_in_cidr(p):
        """expression : target CIDR STRING
                    | target NOT CIDR STRING
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True

        mutators, field, target, op = extract_mutators_and_fields(p)
        if contains_not:
            p[0] = search.Not(search.InCIDR(**{field: target}))
        else:    
            p[0] = search.InCIDR(**{field: target})

        

    def p_expression_exists(p):
        """expression : target EXISTS
                    | target NOT EXISTS
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True
        
        if contains_not:
            p[0] = search.Not(search.Exists(p[1]))
        else:
            p[0] = search.Exists(p[1])

    def p_expression_regexp(p):
        """expression : target REGEXP STRING
                    | target NOT REGEXP STRING
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True
        
        mutators, field, target, op = extract_mutators_and_fields(p)
        if contains_not:
            p[0] = search.Not(search.RegExp(**{field: target}))
        else:
            p[0] = search.RegExp(**{field: target})

    def p_expression_is(p):
        'expression : target IS BOOL'
        p[0] = search.Is(**{p[1]: p[3]})

    def p_expression_between(p):
        """expression : target BETWEEN STRING
                    | target NOT BETWEEN STRING
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True
        
        mutators, field, target, op = extract_mutators_and_fields(p)
        if contains_not:
            p[0] = search.Not(search.Between(**{field: target}))
        else:
            p[0] = search.Between(**{field: target})

    def p_error(p):
        print("Syntax error in input!")

    
    parser = yacc.yacc()
    while True:
        s = input('[Yacc Mode] Query: ')
        if not s:
            break
        if s == 'exit':
            exit()
        try:
            result = parser.parse(s)
        except LexError as e:
            print(e)
            result = None
        if not result:
            continue
        for event in search.execute(db, result):
            print(event)
        print()