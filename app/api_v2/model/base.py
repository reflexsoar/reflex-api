import uuid
import json
import datetime

from fnmatch import fnmatch

from app.api_v2.model.utils import _current_user_id_or_none
from . import (
    Document,
    Keyword,
    Date,
    Nested,
    AttrList,
    utils,
    Search,
    InnerDoc
)

class BaseInnerDoc(InnerDoc):
    """
    Override for InnerDoc that contains Audit fields
    """

    uuid = Keyword()
    created_at = Date()
    updated_at = Date()
    updated_by = Nested()
    created_by = Nested()
    organization = Keyword() # Required on all documents to provide logical isolate of tenants


class BaseDocument(Document):
    """
    Base class for Documents containing common fields
    """

    uuid = Keyword()
    created_at = Date()
    updated_at = Date()
    updated_by = Nested()
    created_by = Nested()
    organization = Keyword() # Required on all documents to provide logical isolate of tenants

    @classmethod
    def _matches(cls, hit):
        return fnmatch(hit["_index"], f'{cls.Index.name}-*')

    @classmethod
    def search(cls, using=None, index=None):
        """
        Creates an :class:`~elasticsearch_dsl.Search` instance that will search 
        over this ``Document``
        """

        # Pull the current user so that the search can be filtered by the 
        # users organization ID
        current_user = _current_user_id_or_none(organization_only=True)

        s = Search(using=cls._get_using(using), index=cls._default_index(index), doc_type=[cls])
        if current_user:
            
            is_default_org = 'default_org' in current_user and current_user['default_org']

            if cls.Index.name != 'reflex-organizations':
                
                if not is_default_org:
                    s = s.filter('term', organization=current_user['organization'])
            
        return s


    @classmethod
    def get_by_uuid(self, uuid, all_results=False, organization=None, **kwargs):
        '''
        Fetches a document by the uuid field
        '''

        documents = None
        if uuid is not None:
            if isinstance(uuid, (AttrList, list)):
                response = self.search()
                if organization:
                    response = response.filter(organization=organization)
                    
                response = response.query('terms', uuid=uuid, **kwargs)
                if all_results:
                    response = response[0:response.count()]

                response = response.execute()
                documents = list(response)
            else:
                response = self.search()
                if organization:
                    response = response.filter(organization=organization)
                response = response.query('term', uuid=uuid, **kwargs).execute()
                if response:
                    documents = response[0]
                else:
                    documents = None
            return documents
        return []

    def save(self, **kwargs):
        '''
        Overrides the default Document save() function and adds
        audit fields created_at, updated_at and a default uuid field
        '''

        if not self.created_at:
            self.created_at = datetime.datetime.utcnow()

        if not self.created_by:
            self.created_by = utils._current_user_id_or_none()

        if not self.uuid:
            self.uuid = uuid.uuid4()

        if self.__class__.__name__ == 'Organization' and not self.organization:
            self.organization = self.uuid

        elif not self.organization:
            current_user = _current_user_id_or_none(organization_only=True)
            if current_user:
                self.organization = current_user['organization']

        self.updated_at = datetime.datetime.utcnow()
        self.updated_by = utils._current_user_id_or_none()
        return super().save(**kwargs)

    def update(self, **kwargs):
        '''
        Overrides the default Document update() function and
        adds an update to updated_at each time the document
        is saved
        '''

        self.updated_at = datetime.datetime.utcnow()
        self.updated_by = utils._current_user_id_or_none()
        return super().update(**kwargs)
