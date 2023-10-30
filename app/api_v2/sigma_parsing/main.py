import urllib.parse
import uuid

from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.elasticsearch.zeek import ecs_zeek_beats, ecs_zeek_corelight, zeek_raw
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.backends.elasticsearch import LuceneBackend
from app.api_v2.model.detection import Detection
from app.api_v2.model.inout import Input
from app.api_v2.model.mitre import MITRETactic, MITRETechnique


LEVELS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'informational': 1
}

BACKENDS = {
    'elasticsearch': LuceneBackend,
    'opensearch': OpensearchLuceneBackend
}

PIPELINES = {
    'sysmon': sysmon_pipeline,
    'ecs_windows': ecs_windows,
    'ecs_zeek_beats': ecs_zeek_beats,
    'ecs_zeek_corelight': ecs_zeek_corelight,
    'zeek_raw': zeek_raw
}


class SigmaParser(object):
    '''
    Takes a YAML configuration file and parses it in to a format that 
    Reflex can understand
    '''

    def __init__(self, sigma_rule, source_input=None, organization=None, pipeline=None, backend=None, mapping=None):
        '''Initializes the SigmaParser object'''
        self.raw_rule = urllib.parse.unquote(sigma_rule)
        self.rule = self._parse(self.raw_rule)
        self.input = source_input
        self.organization = organization
        self.pipeline = pipeline
        self.backend = backend
        self.mapping = mapping

    def _parse(self, rule):
        '''
        Unquotes a URL encoded string and parses it in to a dictionary
        '''
        return SigmaRule.from_yaml(self.raw_rule)

    def generate_detection(self):
        '''
        Generates Reflex detection object from a Sigma rule
        '''

        detection_config = {
            'name': getattr(self.rule, 'title', None),
            'query': {
                'query': '',
                'language': ''
            },
            'sigma_rule_id': getattr(self.rule, 'id', uuid.uuid4()),
            'description': getattr(self.rule, 'description', ''),
            'tags': getattr(self.rule, 'tags', []),
            'references': getattr(self.rule, 'references', []),
            'false_positives': getattr(self.rule, 'falsepositives', []),
            'severity': LEVELS[str(getattr(self.rule, 'level', 'low'))],
            'author': getattr(self.rule, 'author', []),
            'from_sigma': True,
            'sigma_rule': self.raw_rule,
            'tactics': [],
            'techniques': []
        }

        if isinstance(detection_config['author'], str):
            detection_config['author'] = detection_config['author'].split(",")

        NO_PIPELINE_ERROR = "No pipeline specified"
        NO_BACKEND_ERROR = "No backend specified"
        UNSUPPORTED_PIPELINE_ERROR = "Pipeline {} not supported"
        UNSUPPORTED_BACKEND_ERROR = "Backend {} not supported"

        if self.input:
            source_input = Input.get_by_uuid(self.input)

            # If no backend is specified, use the default backend for the input
            if not self.backend:
                if hasattr(source_input, 'sigma_backend'):
                    self.backend = source_input.sigma_backend

            # If no pipeline is specified, use the default pipeline for the input
            if not self.pipeline:
                if hasattr(source_input, 'sigma_pipeline'):
                    self.pipeline = source_input.sigma_pipeline

        if not self.backend:
            raise ValueError(NO_BACKEND_ERROR)
        if not self.pipeline:
            raise ValueError(NO_PIPELINE_ERROR)

        if self.backend not in BACKENDS:
            raise ValueError(UNSUPPORTED_BACKEND_ERROR.format(self.backend))
        if self.pipeline not in PIPELINES:
            raise ValueError(UNSUPPORTED_PIPELINE_ERROR.format(self.pipeline))

        pipeline = PIPELINES[self.pipeline]()
        backend = BACKENDS[self.backend](pipeline)
        rules = SigmaCollection([self.rule])

        # TODO: Implement support for multiple pipelines
        # for rule in rules:
        #    for p in [sysmon_pipeline(), ecs_windows()]:
        #        p.apply(rule)

        if rules:
            converted_rules = backend.convert(rules)
            detection_config['query']['query'] = converted_rules[0]
            detection_config['language'] = 'lucene'

        if detection_config['tags']:
            for t in detection_config['tags']:
                tag = t.name
                if t.namespace == 'attack':
                    if tag.lower().startswith('t'):
                        technique = MITRETechnique.get_by_external_id(
                            tag.upper())
                        if technique:
                            detection_config['techniques'].append(technique)
                    else:
                        shortname = tag.lower()
                        if '_' in tag:
                            shortname = tag.lower().replace('_', '-')
                        tactic = MITRETactic.get_by_shortname(shortname)
                        if tactic:
                            detection_config['tactics'].append(tactic)

        return Detection(**detection_config)
