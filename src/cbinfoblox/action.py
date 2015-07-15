__author__ = 'cb'

import time

class Action(object):
    def __init__(self, cb, logger):
        self.cb = cb
        self.logger = logger


class FlushAction(Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)

    def action(self, sensors, domain):
        for sensor in sensors:
            flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
            self.cb.sensor_flush(sensor.get('id'), flush_time)
#            flush_sensor(self.cb, sensor['id'])


class IsolateAction(Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)

    def action(self, sensors, domain):
        for sensor in sensors:
            if sensor.get('supports_isolation', False):
                self.cb.sensor_toggle_isolation(sensor.get('id'), True)
#                isolate_sensor(self.cb, sensor['id'])