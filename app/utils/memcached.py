from multiprocessing import Pool
from pymemcache.client.base import PooledClient


class MemcachedClient:

    def __init__(self, *args, **kwargs):
        '''
        Declares a MemcachedClient with no client set
        '''
        self.client = None

    def init_app(self, app):
        '''
        Initializes the MemcachedClient with a Flask App
        '''
        
        self.client = PooledClient(
            f"{app.config['THREAT_POLLER_MEMCACHED_HOST']}:{app.config['THREAT_POLLER_MEMCACHED_PORT']}",
            max_pool_size=app.config['MEMCACHED_POOL_SIZE'])
