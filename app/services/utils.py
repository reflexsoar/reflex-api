from time import time

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