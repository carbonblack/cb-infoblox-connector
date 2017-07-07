import struct
import uuid
import threading
import logging
from collections import defaultdict

from action import Action
from live_response import LiveResponseThread

from cbapi.response import sensor_events, event
from cbapi.event import on_event, registry

import time
import traceback

logger = logging.getLogger(__name__)

logging.getLogger("cbapi.response.event").setLevel(logging.DEBUG)

# Define the "Be On The Lookout For" (bolo) list that we'll use when processing the stream...
bolo = defaultdict(dict)
bolo_lock = threading.Lock()
done = False

"""The StreamingKillProcessAction will use the streaming interface to kill a process that contacts
a domain flagged by Infoblox immediately"""
class StreamingKillProcessAction(Action):
    def __init__(self, cb, streaming_host, streaming_user, streaming_password):
        Action.__init__(self, cb)
        try:

            cb.credentials.rabbitmq_user = streaming_user
            cb.credentials.rabbitmq_host = streaming_host
            cb.credentials.rabbitmq_pass = streaming_password

            event_source = event.RabbitMQEventSource(cb)
            logger.info("Starting event_source loop...")
            event_source.start()

            t2 = threading.Thread(target=self._reap_threads)
            logger.info("Starting reap_thread...")
            t2.start()

            for error in registry.errors:
                logger.info(error["exception"])

        except:
            logger.info(traceback.format_exc())

    def name(self):
        return 'Find process via streaming & kill via API'

    def _reap_threads(self):
        while not done:
            time.sleep(1)
            with bolo_lock:
                for bolo_key in bolo.keys():
                    local_bolo = bolo[bolo_key]
                    if 'killing_thread' in local_bolo and not local_bolo['killing_thread'].is_alive():
                        logger.info("Reaping thread responsible for key %s" % bolo_key)
                        local_bolo['killing_thread'].join()
                        del(local_bolo['killing_thread'])

    def action(self, sensors, domain):
        # only take action on sensors that support CbLR
        for sensor in [sensor for sensor in sensors if sensor.get('supports_cblr', False) is True]:
            sensor_id = sensor.get('id')

            with bolo_lock:
                key = '%d:%s' % (sensor_id, domain)
                bolo[key]['timestamp'] = time.time()
                logger.info("Adding %s to bolo" % key)

def make_guid(sensor_id, hdr):
    if hdr.HasField('process_pid') and hdr.HasField('process_create_time'):
        # new style guid
        pid = int(hdr.process_pid)
        high  = (sensor_id & 0xffffffff) << 32
        high |= (pid & 0xffffffff)
        low = int(hdr.process_create_time)
        b = struct.pack(">QQ", high, low)
        return str(uuid.UUID(bytes=b))
    else:
        # old style guid
        return hdr.process_guid

@on_event("ingress.event.netconn")
def netconn_callback(cb, event_type, event_data):
    try:
        msg = sensor_events.CbEventMsg()
        msg.ParseFromString(event_data)
        if not msg.HasField('env') or not msg.HasField('network'):
            return

        if not msg.network.HasField('utf8_netpath') or not len(msg.network.utf8_netpath):
            return

        sensor_id = msg.env.endpoint.SensorId
        key = '%d:%s' % (sensor_id, msg.network.utf8_netpath)
        process_guid = make_guid(sensor_id, msg.header)

        with bolo_lock:
            logger.info(bolo.keys())
            if key in bolo.keys():
                logger.info("Killing process guid %s" % process_guid)
                if 'killing_thread' not in bolo[key] or not bolo[key]['killing_thread'].add_processes(
                        [process_guid]):
                    new_thread = LiveResponseThread(cb, sensor_id, [process_guid], one_time=True)
                    bolo[key]['killing_thread'] = new_thread
                    new_thread.start()
    except:
        logger.info(traceback.format_exc())
