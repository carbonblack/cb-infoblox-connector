__author__ = 'cb'

import time
import struct
import uuid
import threading
from collections import defaultdict

from google.protobuf.message import DecodeError
from cbapi.util.messaging_helpers import QueuedCbSubscriber
import cbapi.util.sensor_events_pb2 as cpb
from cbinfoblox.action import Action
from live_response import LiveResponseThread

"""The StreamingKillProcessAction will use the streaming interface to kill a process that contacts
a domain flagged by Infoblox immediately"""
class StreamingKillProcessAction(QueuedCbSubscriber, Action):
    def __init__(self, cb, logger, streaming_host, streaming_user, streaming_password):
        Action.__init__(self, cb, logger)
        # Define the "Be On The Lookout For" (bolo) list that we'll use when processing the stream...
        self.bolo = defaultdict(dict)
        self.bolo_lock = threading.Lock()
        QueuedCbSubscriber.__init__(self, streaming_host, streaming_user, streaming_password,
                                    "ingress.event.netconn")

    def _make_guid(self, sensor_id, hdr):
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

    def action(self, sensors, domain):
        # only take action on sensors that support CbLR
        for sensor in [sensor for sensor in sensors if sensor.get('supports_cblr', False) is True]:
            sensor_id = sensor.get('id')

            with self.bolo_lock:
                key = '%d:%s' % (sensor_id, domain)
                self.bolo[key]['timestamp'] = time.time()

    def consume_message(self, channel, method_frame, header_frame, body):
        if "application/protobuf" != header_frame.content_type:
            return

        try:
            msg = cpb.CbEventMsg()
            msg.ParseFromString(body)

            if not msg.HasField('env') or not msg.HasField('network'):
                return

            if not msg.network.HasField('utf8_netpath') or not len(msg.network.utf8_netpath):
                return

            sensor_id = msg.env.endpoint.SensorId
            key = '%d:%s' % (sensor_id, msg.network.utf8_netpath)
            process_guid = self._make_guid(sensor_id, msg.header)

            with self.bolo_lock:
                if key in self.bolo.keys():
                    if 'killing_thread' not in self.bolo[key] or not self.bolo[key]['killing_thread'].add_processes([process_guid]):
                        new_thread = LiveResponseThread(self.cb, self.logger, sensor_id, [process_guid], one_time=True)
                        self.bolo[key]['killing_thread'] = new_thread
                        new_thread.start()

        except DecodeError:
            print "Could not decode message from Cb"
