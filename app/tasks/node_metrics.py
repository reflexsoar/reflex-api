import socket
import psutil
from app.api_v2.model.system import APINodeMetric

def system_ip():
    '''
    Fetches the IP address of the machine
    '''

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def store_system_metrics(app, ep):

    # Get the current disk, cpu and memory usage
    # for the nodes process 
    disk_usage = psutil.disk_usage('/')
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory()

    # Get the ip address of the node using 
    ip_address = system_ip()

    # Get the hostname of the node
    hostname = socket.gethostname()

    # Get the node role
    node_role = app.config.get('NODE_ROLE', 'unknown')

    # Get the event processor metrics
    worker_info = ep.get_worker_info()

    events_processed = sum([w.get('processed_events', 0) for w in worker_info])
    events_in_processing = sum([w.get('events_in_processing', 0) for w in worker_info])
    worker_restarts = ep.worker_respawns,
    dead_workers = len([w for w in worker_info if w.get('alive', False) == False])
    workers = ep.tracked_workers
    event_queue_size = ep.qsize()

    # Store the metrics
    metric = APINodeMetric(
        ip=ip_address,
        hostname=hostname,
        node_role=node_role,
        disk=disk_usage.total,
        disk_free = disk_usage.free,
        cpu=cpu_usage,
        memory=memory_usage.used,
        event_processing={
            'events_processed': events_processed,
            'events_in_processing': events_in_processing,
            'worker_restarts': worker_restarts,
            'dead_workers': dead_workers,
            'workers': workers,
            'event_queue_size': event_queue_size
        }
    )
    metric.save()
