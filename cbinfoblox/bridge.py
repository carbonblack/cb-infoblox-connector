import threading
import time
import Queue
import logging
from logging.handlers import RotatingFileHandler
import sys
import traceback

from cbint import CbIntegrationDaemon
from syslog_server import SyslogServer
from restapi_poller import RestPoller
import cbint.utils.json
import cbint.utils.feed
import cbint.utils.flaskfeed
import cbint.utils.cbserver
import cbint.utils.filesystem

from cbapi.response import CbResponseAPI
from cbapi.response.models import Sensor

from action import FlushAction, IsolateAction
from feed import FeedAction
from api_kill_process import ApiKillProcessAction

import version

logging.getLogger("requests").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class FanOutMessage(threading.Thread):
    def __init__(self, cb, worker_queue):
        self.cb = cb
        self.worker_queue = worker_queue
        self.actions = []
        # TODO: this should be a proper cache with a timeout...
        self.sensor_cache = {}

        threading.Thread.__init__(self)

    def add_response_action(self, action):
        logger.info("Adding action: %s" % action.name())
        self.actions.append(action)

    def run(self):
        while True:
            try:
                sensor_ip, domain = self.worker_queue.get()
                logger.info(sensor_ip)
                logger.info(domain)
                if sensor_ip not in self.sensor_cache:
                    sensors = self.cb.select(Sensor).where('ip:{}'.format(sensor_ip))
                    if len(sensors) == 0:
                        logger.error("No sensors found with IP: {}".format(sensor_ip))
                    # ensure that each sensor at least has an ID
                    self.sensor_cache[sensor_ip] = [sensor for sensor in sensors if sensor.id]

                for action in self.actions:
                    logger.info('Dispatching action %s based on %s:%s' % (action.name(), sensor_ip, domain))
                    action.action(self.sensor_cache[sensor_ip], domain)

                self.worker_queue.task_done()
            except Exception as e:
                logger.info(traceback.format_exc())
                continue


class InfobloxBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile, debug=False):
        self.config_ready = False
        CbIntegrationDaemon.__init__(self, name, configfile=configfile, debug=debug)
        self.cb = None
        self.worker_queue = Queue.Queue(maxsize=10)
        self.initialize_logging()
        self.logfile = None

    def initialize_logging(self):

        if not self.logfile:
            log_path = "/var/log/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
        root_logger.addHandler(rlh)

    @property
    def integration_name(self):
        return "Cb InfoBlox Connector " + version.__version__

    def _set_alert_action(self, feed_id):
        actions = self.cb.feed_action_enum(feed_id)
        for action in actions:
            if action['id'] == 3:
                # XXX: "3" is the action id associated with creating an alert
                return

        self.cb.feed_action_add(feed_id, 3, [])

    def run(self):
        self.validate_config()

        try:
            logger.warn("CB Infoblox Bridge Starting")
            sslverify = False if self.bridge_options.get('carbonblack_server_sslverify', "0") == "0" else True

            self.cb = CbResponseAPI(url=self.bridge_options['carbonblack_server_url'],
                                    token=self.bridge_options['carbonblack_server_token'],
                                    ssl_verify=sslverify,
                                    integration_name=self.integration_name)
            self.cb.info()

            self.streaming_host = self.bridge_options.get('carbonblack_streaming_host')
            self.streaming_username = self.bridge_options.get('carbonblack_streaming_username')
            self.streaming_password = self.bridge_options.get('carbonblack_streaming_password')

            self.use_cloud_api = True if int(self.bridge_options.get('use_cloud_api','0')) != 0 else False

            #start the syslog server normally , otherwise start the rest poller
            if not (self.use_cloud_api):
                syslog_server = SyslogServer(10240, self.worker_queue)
            else:
                self.api_token = self.bridge_options.get('api_token',"PASSWORD")
                self.poll_interval = self.bridge_options.get('rest_poll_interval',"5M")
                self.api_route = self.bridge_options.get('api_route',"")
                logger.info("starting rest poller")
                rest_poller = RestPoller(self.api_route,self.api_token,worker_queue=self.worker_queue,time_increment=self.poll_interval)

            message_broker = FanOutMessage(self.cb, self.worker_queue)

            # Set up the built-in feed
            feed_thread = FeedAction(self.cb, self.bridge_options)
            feed_thread.start()

            ctx = feed_thread.flask_feed.app.test_request_context()
            ctx.push()
            feed_thread.flask_feed.app.preprocess_request()
            ctx.pop()

            logger.info("flask ready")

            feed_id = feed_thread.get_or_create_feed()

            #TODO revisit
            #if self.bridge_options.get('do_alert', False):
            #    self._set_alert_action(feed_id)

            # Note: it is important to keep the relative order stable here.
            # we want to make sure that the Cb sensor flush occurs first, before the feed entry is created
            # and before any other actions are taken (isolation or process termination)

            # We will always flush the sensor that triggered the action, so that we get the most up-to-date
            # information into the Cb console.
            flusher = FlushAction(self.cb)

            message_broker.add_response_action(flusher)
            message_broker.add_response_action(feed_thread)

            # Conditionally create a kill-process action based on the configuration file.
            kill_option = self.bridge_options.get('do_kill', None)
            if kill_option == 'api':
                kill_process_thread = ApiKillProcessAction(self.cb)
                kill_process_thread.start()
                message_broker.add_response_action(kill_process_thread)
            elif kill_option == 'streaming':
                #
                # For some reason this must be imported here otherwise the event registry thread does not start
                #
                from streaming_kill_process import StreamingKillProcessAction
                kill_streaming_action = StreamingKillProcessAction(self.cb, self.streaming_host,
                                                                   self.streaming_username, self.streaming_password)
                message_broker.add_response_action(kill_streaming_action)

            if self.bridge_options.get('do_isolate', False):
                isolator = IsolateAction(self.cb)
                message_broker.add_response_action(isolator)

            # once everything is up & running, start the message broker then the syslog server
            message_broker.start()
            if (self.use_cloud_api):
                rest_poller.start()
            else:
                syslog_server.start()

            logger.info("Starting event loop")

            try:
                while True:
                    time.sleep(5)
            except KeyboardInterrupt:
                logger.warn("Stopping Cb Infoblox Connector due to Control-C")

            logger.warn("Cb Infoblox Connector Stopping")
        except:
            logger.error(traceback.format_exc())

        sys.exit(1)

    def validate_config(self):
        if self.config_ready:
            return

        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            logger.error("configuration does not contain a [bridge] section")
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
        if not 'use_cloud_api' in self.bridge_options:
            #default to False
            self.bridge_options['use_cloud_api'] = False

        if not config_valid:
            for msg in msgs:
                sys.stderr.write("%s\n" % msg)
                logger.error(msg)
            return False
        else:
            self.config_ready = True
            return True
