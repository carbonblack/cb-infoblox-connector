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

#
# TODO -- automatically add the FEED?
# TODO -- better logging
# TODO -- send out an alert maybe?

class InfobloxBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile)
        self.cb = None
        self.bridge_options = {}
        self.debug = False
        self.worker_queue = Queue.Queue(maxsize=10)

    def run(self):
        try:
            self.logger.warn("CB Infoblox Bridge Starting")
            sslverify = False if self.bridge_options.get('carbonblack_server_sslverify', "0") == "0" else True
            self.cb = cbapi.CbApi(self.bridge_options['carbonblack_server_url'],
                                  token=self.bridge_options['carbonblack_server_token'],
                                  ssl_verify=sslverify)

            #
            # TODO -- for some reason this (checking version) was failing...
            #
            # self.logger.debug("checking CB server version")
            # if not cbint.utils.cbserver.is_server_at_least(self.cb, "4.1"):
            #     self.logger.error("the configured Carbon Black Enterprise server does not meet the minimum "
            #                       "required version (4.1)")
            #     return

            self.streaming_host = self.bridge_options.get('carbonblack_streaming_host')
            self.streaming_username = self.bridge_options.get('carbonblack_streaming_username')
            self.streaming_password = self.bridge_options.get('carbonblack_streaming_password')

            syslog_server = SyslogServer(10240, self.worker_queue, self.logger)
            message_broker = FanOutMessage(self.cb, self.worker_queue, self.logger)

            flusher = FlushAction(self.cb, self.logger)
            isolator = IsolateAction(self.cb, self.logger)
            feed_thread = FeedAction(self.cb, self.logger, self.bridge_options)
            feed_thread.start()

            self.logger.info("Started feed_thread")
            time.sleep(1.0) # ghetto!

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

            # TODO: just putting this here to make sure we don't exit till the threads do something useful...
            time.sleep(1000)

            self.logger.warn("CB Infoblox Connector Stopping")
        except:
            import traceback
            self.logger.error(traceback.format_exc())

    def validate_config(self):
        # TODO - -clean this up more
        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            self.logger.error("configuration does not contain a [bridge] section")
            return False

        config_valid = True
        msgs = []
        # if not 'cyphort_url' in self.bridge_options:
        #     msgs.append('the config option cyphort_url is required')
        #     config_valid = False
        if not 'listener_port' in self.bridge_options or not self.bridge_options['listener_port'].isdigit():
            msgs.append('the config option listener_port is required and must be a valid port number')
            config_valid = False
        # if not 'cyphort_api_key' in self.bridge_options:
        #     msgs.append('the config option cyphort_api_key is required')
        #     config_valid = False
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
            return True
