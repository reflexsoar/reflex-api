from time import time
from datetime import datetime, timezone

def execution_timer(f):
    '''
    Times the execution of a function
    '''
    def wrapper(*args, **kwargs):
        t1 = time()
        result = f(*args, **kwargs)
        t2 = time()
        print(f'Function {f.__name__!r} executed in {(t2-t1):.4f}s')
        return result
    return wrapper

def iso_utcnow_as_string():
    '''
    Returns the current time in UTC in ISO format
    '''
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")

def iso_utcnow_as_datetime():
    '''
    Returns the current time in UTC in ISO format
    '''
    return datetime.now(timezone.utc)