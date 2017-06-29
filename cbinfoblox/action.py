import time
import logging
from cbapi.response import event, BannedHash, Sensor
from cbapi.event import on_event, registry
from cbapi.example_helpers import get_cb_response_object, build_cli_parser

logger = logging.getLogger(__name__)

class Action(object):
    def __init__(self, cb):
        self.cb = cb

    def name(self):
        return self.__class__.__name__


class FlushAction(Action):
    def __init__(self, cb):
        Action.__init__(self, cb)

    def action(self, sensors, domain):
        for sensor in sensors:
            flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
            self.cb.sensor_flush(sensor.get('id'), flush_time)

    def name(self):
        return 'Flush sensor information'

class IsolateAction(Action):
    def __init__(self, cb):
        Action.__init__(self, cb)

    def isolate_sensor(self, sensor_id):
        sensor = self.cb.select(Sensor, sensor_id)
        sensor.network_isolation_enabled = True
        sensor.save()

    def action(self, sensors, domain):
        for sensor in sensors:
            logger.info("Isolating Sensor Id: {}", sensor.id)
            self.isolate_sensor(sensor.id)

    def name(self):
        return 'Isolate affected sensor'