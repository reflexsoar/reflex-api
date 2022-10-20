from pymemcache.client.base import PooledClient

class MemcachedClient:

    def __init__(self, *args, **kwargs):
        '''
        Declares a MemcachedClient with no client set
        '''
        self.client = None

        self.timeout = kwargs.get('timeout', 10)
        self.max_pool_size = kwargs.get('max_pool_size', 4)
        self.host = kwargs.get('host', None)
        self.port = kwargs.get('port', None)

        if self.port and self.host:
            self.client = PooledClient(
                f"{self.host}:{self.port}",
                max_pool_size=self.max_pool_size,
                timeout=self.timeout)

    def init_app(self, app, *args, **kwargs):
        '''
        Initializes the MemcachedClient with a Flask App
        '''        
        if app:
            self.client = PooledClient(
                f"{app.config['THREAT_POLLER_MEMCACHED_HOST']}:{app.config['THREAT_POLLER_MEMCACHED_PORT']}",
                max_pool_size=app.config['MEMCACHED_POOL_SIZE'])
