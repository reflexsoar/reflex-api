import ply.lex as lex
import ply.yacc as yacc
from . import RQLSearch
from . import MUTATORS
import ast

class QueryLexer(object):

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
        'NOT',
        'EXPAND'
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
    t_MUTATOR = r'(\|(count|length|lowercase|extractb64|b64decode|refang|urldecode|any|all|avg|max|min|sum))'
    t_SWITH = r'StartsWith|startswith'
    t_EWITH = r'EndsWith|endswith'
    t_EXPAND = r'Expand|EXPAND|expand'
    t_ignore = ' \t.'
   
    def t_NUMBER(self, t):
        r'\d+'
        t.value = ast.literal_eval(t.value)
        return t

    def t_FLOAT(self, t):
        r'\d+\.?\d+$'
        t.value = ast.literal_eval(t.value)
        return t        

    def t_STRING(self, t):
        r'[\"\'](.*?)[\"\']'
        t.value = ast.literal_eval(t.value)
        return t

    def t_comment(self, t):
        r'\#.*'
        pass

    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno ++ len(t.value)

    def t_target(self, t):
        # TODO: Define all the fields a user can access here
        r'''observables(\.([^\s\|]+))?|value|tlp|tags|spotted|safe|source_field
        |data_type|ioc|original_source_field|title|severity|status|reference|source
        |signature|tags|raw_log(\.([^\s\|]+))?
        '''
        return t
    
    def t_ARRAY(self, t):
        r'\[([\"|\'].*[\"|\'])\]'
        t.value = ast.literal_eval(t.value)
        return t

    def t_error(self, t):
        raise ValueError("Illegal character '%s'" % t.value[0])

    def __init__(self):
        self.lexer = lex.lex(module=self)

class QueryParser(object):

    tokens = QueryLexer.tokens
    search = RQLSearch()

    def extract_mutators_and_fields(self, p):
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

    def p_expression(self, p):
        'expression : target'
        p[0] = p[1]

    def p_expression_or(self, p):
        'expression : expression OR expression'
        p[0] = self.search.Or(p[1], p[3])

    def p_expression_and(self, p):
        'expression : expression AND expression'
        p[0] = self.search.And(p[1], p[3])

    def p_expression_singlet(self, p):
        'expression : LPAREN expression RPAREN'
        p[0] = p[2]

    def p_expression_and_group(self, p):
        'expression : LPAREN expression AND expression RPAREN'
        p[0] = self.search.And(p[2], p[4])

    def p_expression_or_group(self, p):
        'expression : LPAREN expression OR expression RPAREN'
        p[0] = self.search.Or(p[2], p[4])

    def p_expression_each_and_group(self, p):
        'expression : EXPAND target LPAREN expression AND expression RPAREN'
        p[0] = self.search.Expand(self.search.And(p[4], p[6]), key=p[2])
    
    def p_expression_startswith(self, p):
        """expression : target SWITH STRING
                    | target MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING
        """
        mutators, field, target, op = self.extract_mutators_and_fields(p)
        p[0] = self.search.StartsWith(mutators=mutators, **{field: target})

    def p_expression_endswith(self, p):
        """expression : target EWITH STRING
                    | target MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING
                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING
        """
        mutators, field, target, op = self.extract_mutators_and_fields(p)
        p[0] = self.search.EndsWith(mutators=mutators, **{field: target})
    
    def p_expression_match(self, p):
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

        mutators, field, target, op = self.extract_mutators_and_fields(p)

        if contains_not:
            p[0] = self.search.Not(self.search.Match(mutators=mutators, **{field: target}))
        else:
            p[0] = self.search.Match(mutators=mutators, **{field: target})

    def p_expression_contains(self, p):
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
                    | target MUTATOR CONTAINS ARRAY
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

        mutators, field, target, op = self.extract_mutators_and_fields(p)
        if contains_not:
            p[0] = self.search.Not(self.search.Contains(mutators=mutators, **{field: target}))
        else:
            p[0] = self.search.Contains(mutators=mutators, **{field: target})

    def p_expression_in(self, p):
        """expression : target IN ARRAY
                   | target MUTATOR IN ARRAY
                   | target NOT IN ARRAY
                   | target MUTATOR NOT IN ARRAY
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True

        mutators, field, target, op = self.extract_mutators_and_fields(p)
        if contains_not:
            p[0] = self.search.Not(self.search.In(mutators=mutators, **{field: target}))
        else:    
            p[0] = self.search.In(mutators=mutators, **{field: target})

    def p_expression_math_op(self, p):
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
        mutators, field, target, op = self.extract_mutators_and_fields(p)
        
    
        p[0] = self.search.MathOp(mutators=mutators, operator=op, **{field: target})

    def p_expression_in_cidr(self, p):
        """expression : target CIDR STRING
                    | target NOT CIDR STRING
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True

        mutators, field, target, op = self.extract_mutators_and_fields(p)
        if contains_not:
            p[0] = self.search.Not(self.search.InCIDR(**{field: target}))
        else:    
            p[0] = self.search.InCIDR(**{field: target})

        

    def p_expression_exists(self, p):
        """expression : target EXISTS
                    | target NOT EXISTS
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True
        
        if contains_not:
            p[0] = self.search.Not(self.search.Exists(p[1]))
        else:
            p[0] = self.search.Exists(p[1])

    def p_expression_regexp(self, p):
        """expression : target REGEXP STRING
                    | target NOT REGEXP STRING
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True
        
        mutators, field, target, op = self.extract_mutators_and_fields(p)
        if contains_not:
            p[0] = self.search.Not(self.search.RegExp(**{field: target}))
        else:
            p[0] = self.search.RegExp(**{field: target})

    def p_expression_is(self, p):
        'expression : target IS BOOL'
        p[0] = self.search.Is(**{p[1]: p[3]})

    def p_expression_between(self, p):
        """expression : target BETWEEN STRING
                    | target NOT BETWEEN STRING
        """

        contains_not = False
        for _ in p:
            if _  and isinstance(_, str) and _.lower() == 'not':
                contains_not = True
        
        mutators, field, target, op = self.extract_mutators_and_fields(p)
        if contains_not:
            p[0] = self.search.Not(self.search.Between(**{field: target}))
        else:
            p[0] = self.search.Between(**{field: target})

    def p_error(self, p):
        raise ValueError("Syntax error in input")

    def __init__(self):
        self.lexer = QueryLexer()
        self.parser = yacc.yacc(module=self)

    def run_search(self, data, parsed_query):
     
        result = self.search.execute([data], parsed_query)
        return result
