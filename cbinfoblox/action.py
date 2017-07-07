import logging
import traceback
from cbapi.response import Sensor

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
            try:
                logger.info("Flushing events for Sensor Id: {}", sensor.id)
                sensor.flush_events()
            except Exception as e:
                logger.error(e.message)

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