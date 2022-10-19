from pymemcache.client.base import PooledClient

class MemcachedClient:

    def __init__(self, *args, **kwargs):
        '''
        Declares a MemcachedClient with no client set
        '''
        self.client = None

    def init_app(self, app, host=None, port=None, timeout=None, max_pool_size=4, *args, **kwargs):
        '''
        Initializes the MemcachedClient with a Flask App
        '''

        self.client = None
        
        if app:
            self.client = PooledClient(
                f"{app.config['THREAT_POLLER_MEMCACHED_HOST']}:{app.config['THREAT_POLLER_MEMCACHED_PORT']}",
                max_pool_size=app.config['MEMCACHED_POOL_SIZE'])
        else:
            if host and port:
                self.client = PooledClient(
                    f"{host}:{port}",
                    max_pool_size=max_pool_size)
