
class TaskManger(object):
    """
    TaskManager is responsible for monitoring other background
    tasks and services to make sure they are running effectively.
    """

    def __init__(self, tasks: list = [], services: list = []):
        self.services = services
        self.tasks = tasks

    