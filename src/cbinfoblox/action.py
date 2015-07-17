__author__ = 'cb'

import time

class Action(object):
    def __init__(self, cb, logger):
        self.cb = cb
        self.logger = logger

    def name(self):
        return self.__class__.__name__


class FlushAction(Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)

    def action(self, sensors, domain):
        for sensor in sensors:
            flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
            self.cb.sensor_flush(sensor.get('id'), flush_time)

    def name(self):
        return 'Flush sensor information'

class IsolateAction(Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)

    def action(self, sensors, domain):
        for sensor in sensors:
            if sensor.get('supports_isolation', False):
                self.cb.sensor_toggle_isolation(sensor.get('id'), True)

    def name(self):
        return 'Isolate affected sensor'