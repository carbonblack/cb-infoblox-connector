__author__ = 'cb'


import threading
import time
import Queue
import logging
import sys

import cbapi
from cbint import CbIntegrationDaemon
from syslog_server import SyslogServer

from action import FlushAction, IsolateAction
from feed import FeedAction
from api_kill_process import ApiKillProcessAction
from streaming_kill_process import StreamingKillProcessAction

logging.getLogger("requests").setLevel(logging.WARNING)


class FanOutMessage(threading.Thread):
    def __init__(self, cb, worker_queue, logger):
        self.cb = cb
        self.worker_queue = worker_queue
        self.logger = logger
        self.actions = []
        # TODO: this should be a proper cache with a timeout...
        self.sensor_cache = {}

        threading.Thread.__init__(self)

    def add_response_action(self, action):
        self.actions.append(action)

    def run(self):
        while True:
            sensor_ip, domain = self.worker_queue.get()
            self.logger.warn('got %s:%s from queue' % (sensor_ip, domain))
            if sensor_ip not in self.sensor_cache:
                sensors = self.cb.sensors(query_parameters={'ip': sensor_ip})
                # ensure that each sensor at least has an ID
                self.sensor_cache[sensor_ip] = [sensor for sensor in sensors if sensor.get('id')]

            for action in self.actions:
                self.logger.warn('Dispatching action %s based on %s:%s' % (action, sensor_ip, domain))
                action(self.sensor_cache[sensor_ip], domain)

            self.worker_queue.task_done()


class InfobloxBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile)
        self.cb = None
        self.bridge_options = {}
        self.debug = False
        self.worker_queue = Queue.Queue(maxsize=10)
        self.config_ready = False

    def run(self):
        self.validate_config()

        try:
            self.logger.warn("CB Infoblox Bridge Starting")
            sslverify = False if self.bridge_options.get('carbonblack_server_sslverify', "0") == "0" else True
            self.cb = cbapi.CbApi(self.bridge_options['carbonblack_server_url'],
                                  token=self.bridge_options['carbonblack_server_token'],
                                  ssl_verify=sslverify)

            self.streaming_host = self.bridge_options.get('carbonblack_streaming_host')
            self.streaming_username = self.bridge_options.get('carbonblack_streaming_username')
            self.streaming_password = self.bridge_options.get('carbonblack_streaming_password')

            syslog_server = SyslogServer(10240, self.worker_queue, self.logger)
            message_broker = FanOutMessage(self.cb, self.worker_queue, self.logger)

            flusher = FlushAction(self.cb, self.logger)
            isolator = IsolateAction(self.cb, self.logger)
            feed_thread = FeedAction(self.cb, self.logger, self.bridge_options)
            feed_thread.start()

            ctx = feed_thread.flask_feed.app.test_request_context()
            ctx.push()
            feed_thread.flask_feed.app.preprocess_request()
            ctx.pop()

            self.logger.info("flask ready")

            feed_thread.get_or_create_feed()

            kill_process_thread = ApiKillProcessAction(self.cb, self.logger)
            kill_process_thread.start()
            kill_streaming_action = StreamingKillProcessAction(self.cb, self.logger, self.streaming_host,
                                                               self.streaming_username, self.streaming_password)
            t1 = threading.Thread(target=kill_streaming_action.process)
            t1.start()

            message_broker.add_response_action(feed_thread.action)
            message_broker.add_response_action(flusher.action)
    #        message_broker.add_response_action(isolator.action)
    #        message_broker.add_response_action(kill_process_thread.action)
            message_broker.add_response_action(kill_streaming_action.action)
            syslog_server.start()
            message_broker.start()

            self.logger.info("Starting event loop")

            try:
                while True:
                    time.sleep(5)
            except KeyboardInterrupt:
                self.logger.warn("Stopping Cb Infoblox Connector due to Control-C")
                sys.exit(1)

            self.logger.warn("Cb Infoblox Connector Stopping")
        except:
            import traceback
            self.logger.error(traceback.format_exc())

    def validate_config(self):
        if self.config_ready:
            return

        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            self.logger.error("configuration does not contain a [bridge] section")
            return False

        config_valid = True
        msgs = []
        if not 'listener_port' in self.bridge_options or not self.bridge_options['listener_port'].isdigit():
            msgs.append('the config option listener_port is required and must be a valid port number')
            config_valid = False
        if not 'carbonblack_server_url' in self.bridge_options:
            msgs.append('the config option carbonblack_server_url is required')
            config_valid = False
        if not 'carbonblack_server_token' in self.bridge_options:
            msgs.append('the config option carbonblack_server_token is required')
            config_valid = False

        if not config_valid:
            for msg in msgs:
                sys.stderr.write("%s\n" % msg)
                self.logger.error(msg)
            return False
        else:
            self.config_ready = True
            return True
