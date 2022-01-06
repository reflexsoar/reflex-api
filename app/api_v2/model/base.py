import uuid
import json
import datetime

from fnmatch import fnmatch
from . import (
    Document,
    Keyword,
    Date,
    Nested,
    AttrList,
    utils
)

class BaseDocument(Document):
    """
    Base class for Documents containing common fields
    """

    uuid = Keyword()
    created_at = Date()
    updated_at = Date()
    updated_by = Nested()
    created_by = Nested()

    @classmethod
    def _matches(cls, hit):
        return fnmatch(hit["_index"], f'{cls.Index.name}-*')

    @classmethod
    def get_by_uuid(self, uuid, all_results=False, **kwargs):
        '''
        Fetches a document by the uuid field
        '''

        documents = None
        if uuid is not None:
            if isinstance(uuid, (AttrList, list)):
                response = self.search()
                response = response.query('terms', uuid=uuid, **kwargs)
                if all_results:
                    response = response[0:response.count()]
                response = response.execute()
                documents = list(response)
            else:
                response = self.search().query('term', uuid=uuid, **kwargs).execute()
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
