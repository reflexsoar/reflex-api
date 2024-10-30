import unittest
from app.api_v2.rql import QueryParser

class RQLTest(unittest.TestCase):

    def setUp(self):
        self.qp = QueryParser()

    def test_basic_rql_search(self):

        query = 'title eq "test"'

        data = {
            'title': 'test'
        }
        
        parsed_query = self.qp.parser.parse(query)
        result = [r for r in self.qp.run_search([data], parsed_query)]
        
        assert len(result) == 1

    def test_flat_key_at_root(self):

        query = 'raw_log.name eq "test"'

        data = {
            'raw_log.name': 'test'
        }
        
        parsed_query = self.qp.parser.parse(query)
        result = [r for r in self.qp.run_search([data], parsed_query)]
        
        assert len(result) == 1

    def test_flat_key_nested(self):

        query = 'raw_log.user.name eq "test"'

        data = {
            'raw_log': {
                'user.name': 'test'
            }
        }
        
        parsed_query = self.qp.parser.parse(query)
        result = [r for r in self.qp.run_search([data], parsed_query)]
        
        assert len(result) == 1

    def test_normal_nested(self):

        query = 'raw_log.user.name eq "test"'

        data = {
            'raw_log': {
                'user': {
                    'name': 'test'
                }
            }
        }
        
        parsed_query = self.qp.parser.parse(query)
        result = [r for r in self.qp.run_search([data], parsed_query)]
        
        assert len(result) == 1
