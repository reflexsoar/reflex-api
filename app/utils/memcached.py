from multiprocessing import Pool
from pymemcache.client.base import PooledClient

class MemcachedClient:

    def __init__(self, *args, **kwargs):
        self.client = None

    def init_app(self, app):
        self.client = PooledClient(f"{app.config['THREAT_POLLER_MEMCACHED_HOST']}:{app.config['THREAT_POLLER_MEMCACHED_PORT']}", max_pool_size=4)