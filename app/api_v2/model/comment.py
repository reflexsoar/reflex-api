from . import (
    Keyword,
    Text,
    base,
    Object,
    Nested
)


class CommentMention(base.InnerDoc):

    kind = Keyword() # Is this a case, event, person, task, detection
    target_uuid = Keyword() # The UUID of the mentioned object
    name = Keyword() # The name of the mentioned object (or title in some instances)

class Comment(base.BaseDocument):
    """
    Defines a Comment object that can be used across
    any place in the Reflex platform

    author: The user who created the comment
    message: The actual comment
    parent: The object the comment is attached to, e.g. a Task, Case, Event or another Comment
    reactions: Any reactions to the comment like emojies
    mentions: A list of mentioned objects if using the @mention functionality
    """

    author = Object()
    message = Text(fields={'keyword': Keyword()})
    parent = Keyword() # THe UUID of the parent object e.g. case.uuid, event.uuid
    mentions = Nested(CommentMention)
    tags = Keyword() # Any tags that appeared in the message body 
