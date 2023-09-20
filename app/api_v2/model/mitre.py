"""app/api_v2/model/mitre.py

Contains the models for sotring MITRE ATT&CK information
"""

import re
import datetime
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Long,
    Float,
    Date,
    Nested,
    system,
    Object
)

class MITREExternalReference(base.InnerDoc):
    '''
    Defines an External Reference that for a MITRE item.  External references 
    are useful resources that are external to the MITRE ATT&CK framework that 
    are related to the Tactic or Techniques (attack-patterns)
    '''

    url = Keyword(fields={'text':Text()})
    external_id = Keyword(fields={'text':Text()})
    source_name = Keyword(fields={'text':Text()})
    description = Keyword(fields={'text':Text()})


class MITREKillChainPhase(base.InnerDoc):
    '''
    Defines a Kill Chain Phase reference that is used to map Techniques back
    to tactics
    '''

    kill_chain_name = Keyword(fields={'text':Text()})
    phase_name = Keyword(fields={'text':Text()})


class MITRETechnique(base.BaseDocument):
    '''
    A MITRE Attack Technique
    '''

    class Index:
        name = "reflex-mitre-techniques"
        settings = {
            "refresh_interval": "1s"
        }
        version = "0.1.5"

    mitre_id = Keyword(fields={'text':Text()}) # Example: x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263
    description = Keyword(fields={'text':Text()})
    name = Keyword(fields={'text':Text()}) # Example: Credential Access
    external_id = Keyword(fields={'text':Text()}) # Example: TA0006
    external_references = Nested(MITREExternalReference)
    kill_chain_phases = Nested(MITREKillChainPhase)
    phase_names = Keyword(fields={'text':Text()}) # Example: defense-evasion
    data_sources = Keyword(fields={'text':Text()}) # Example: Process: OS API Execution
    is_sub_technique = Boolean()
    is_deprecated = Boolean()
    is_revoked = Boolean()

    @property
    def external_id_parent(self):
        ''' Returns just the parent external_id '''
        parts = self.external_id.split('.')
        if len(parts) > 1:
            return parts[0]
        return self.external_id

    def get_external_id(self):
        ''' Pulls the MITRE External ID from external_references '''
        external_id_refs = [ref['external_id'] for ref in self.external_references if self.external_references and 'external_id' in ref]
        if len(external_id_refs) > 0:
            self.external_id = external_id_refs[0]

    def get_kill_chain_phase_names(self):
        '''
        Pulls the kill chain phases out of the kill_chain_phases fields and
        in to an array of just the names to simplify lookup
        '''
        if self.kill_chain_phases and len(self.kill_chain_phases) > 0:
            self.phase_names = [phase['phase_name'] for phase in self.kill_chain_phases]
    
    @classmethod
    def get_by_external_id(cls, external_id):
        ''' Fetches the tactic by its external ID '''
        search = cls.search()
        if isinstance(external_id, list):
            search = search.filter('terms', external_id__keyword=external_id)
        else:
            search = search.filter('match', external_id=external_id)
        result = [r for r in search.scan()]
        if result:
            if isinstance(external_id, list):
                return result
            return result[0]
        else:
            return None


class MITRETactic(base.BaseDocument):
    '''
    A MITRE Tactic 
    '''

    class Index:
        name = "reflex-mitre-tactics"
        settings = {
            "refresh_interval": "1s"
        }

    mitre_id = Keyword(fields={'text':Text()}) # Example: x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263
    description = Keyword(fields={'text':Text()})
    name = Keyword(fields={'text':Text()}) # Example: Credential Access
    shortname = Keyword(fields={'text':Text()}) # Example: credential-access
    external_id = Keyword(fields={'text':Text()}) # Example: TA0006
    external_references = Nested(MITREExternalReference)

    def get_external_id(self):
        ''' Pulls the MITRE External ID from external_references '''
        external_id_refs = [ref['external_id'] for ref in self.external_references if self.external_references and 'external_id' in ref]
        if len(external_id_refs) > 0:
            self.external_id = external_id_refs[0]

    @classmethod
    def get_by_external_id(cls, external_id):
        ''' Fetches the tactic by its external ID '''
        search = cls.search()
        if isinstance(external_id, list):
            search = search.filter('terms', external_id=external_id)
        else:
            search = search.filter('term', external_id=external_id)
        result = [r for r in search.scan()]
        if result:
            if isinstance(external_id, list):
                return result
            return result[0]
        else:
            return None


    @classmethod
    def get_by_shortname(cls, shortname):
        ''' Fetches the tactic by its short_name '''
        search = cls.search()
        search = search.filter('match_phrase', shortname=shortname)
        result = search.execute()
        if result:
            return result[0]
        else:
            return None