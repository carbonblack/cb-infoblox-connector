__author__ = 'cb'


import socket
import re
import threading
import time
import Queue
import pprint
import copy
import struct
import logging
import uuid
import os
import sys
from collections import defaultdict

from cbapi.util.messaging_helpers import QueuedCbSubscriber
import cbapi.util.sensor_events_pb2 as cpb
from cbint.utils.filesystem import ensure_directory_exists

from google.protobuf.message import DecodeError

import cbapi
import cbint.utils
import cbint.utils.feed
from cbint import CbIntegrationDaemon
from cbint.utils.flaskfeed import FlaskFeed


logging.getLogger("requests").setLevel(logging.WARNING)

worker_queue = Queue.Queue(maxsize=10)

def isolate_sensor(cb, sensor_id):
    cb.sensor_toggle_isolation(sensor_id, True)

def flush_sensor(cb, sensor_id):
    flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
    cb.sensor_flush(sensor_id, flush_time)



class FanOutMessage(threading.Thread):
    def __init__(self, cb, logger):
        self.cb = cb
        self.logger = logger
        self.actions = []
        # TODO: this should be a proper cache with a timeout...
        self.sensor_cache = {}

        threading.Thread.__init__(self)

    def add_response_action(self, action):
        self.actions.append(action)

    def run(self):
        while True:
            sensor_ip, domain = worker_queue.get()
            self.logger.warn('got %s:%s from queue' % (sensor_ip, domain))
            if sensor_ip not in self.sensor_cache:
                sensors = self.cb.sensors(query_parameters={'ip': sensor_ip})
                # ensure that each sensor at least has an ID
                self.sensor_cache[sensor_ip] = [sensor for sensor in sensors if sensor.get('id')]

            for action in self.actions:
                self.logger.warn('Dispatching action %s based on %s:%s' % (action, sensor_ip, domain))
                action(self.sensor_cache[sensor_ip], domain)

            worker_queue.task_done()


class SyslogServer(threading.Thread):
    def __init__(self, syslog_port, logger):
        self.syslog_port = syslog_port
        self.logger = logger
        self.format_string = \
            re.compile('src=(\d+.\d+.\d+.\d+) .*rewrite ([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})')
        threading.Thread.__init__(self)

    def run(self):
        syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        listen_addr = ("", self.syslog_port)
        syslog_socket.bind(listen_addr)

        while True:
            data, addr = syslog_socket.recvfrom(2048)
            data = data.strip()
            self.logger.debug('got data: %s' % data) # TODO -- cleanup
            hit = self.format_string.search(data)
            if hit:
                self.logger.info('adding to queue: %s : %s' % (hit.group(1), hit.group(2)))
                worker_queue.put((hit.group(1), hit.group(2)))

class Action(object):
    def __init__(self, cb, logger):
        self.cb = cb
        self.logger = logger

class FlushAction(Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)

    def action(self, sensors, domain):
        for sensor in sensors:
            flush_sensor(self.cb, sensor['id'])


class IsolateAction(Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)

    def action(self, sensors, domain):
        for sensor in sensors:
            if sensor.get('supports_isolation', False):
                isolate_sensor(self.cb, sensor['id'])


"""The FeedAction will start a web server and create a feed consumable by Carbon Black that
lists all processes flagged by infoblox"""
class FeedAction(threading.Thread, Action):
    def __init__(self, cb, logger, bridge_options):
        Action.__init__(self, cb, logger) # TODO -- maybe a ThreadedAction class?
        threading.Thread.__init__(self)
        self.flask_feed = FlaskFeed(__name__)
        self.bridge_options = bridge_options
        self.sync_needed = False
        self.feed_name = "infoblox"
        self.display_name = "Infoblox"
        self.feed_metadata = {}
        self.feed_domains = defaultdict(dict)
        self.feed_lock = threading.Lock()
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.cb_image_path = "/content/carbonblack.png"
        self.integration_image_path = "/content/infoblox.png"
        self.json_feed_path = "/infoblox/json"
        self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])

        self.data_dir = "/usr/share/cb/integrations/carbonblack_cyphort_bridge/feed_backup"

        self.feed_id = self.get_or_create_feed()

    def run(self):
        self.logger.debug("generating feed metadata")
        self.feed_metadata = cbint.utils.feed.generate_feed(self.feed_name, summary="Infoblox detonation feed",
                    tech_data="There are no requirements to share any data with Carbon Black to use this feed. However, binaries may be shared with Infoblox.",
                    provider_url="http://www.infoblox.com/", icon_path="%s/%s" % (self.directory, self.integration_image_path),
                    display_name=self.display_name, category="Connectors")

        # make data directories as required
        #
        ensure_directory_exists(self.data_dir)

        # restore alerts from disk if so configured
        #
#        if int(self.bridge_options.get('restore_feed_on_restart', 0)):
        self.logger.info("Restoring saved feed...")
        num_restored = self.restore_feed_files()
        self.logger.info("Restored %d alerts from %d on-disk files" % (len(self.feed['reports']), num_restored))

        self.logger.debug("starting flask")
        self.serve()

    def get_or_create_feed(self):
        feed_id = self.cb.feed_get_id_by_name(self.feed_name)
        if not feed_id:
            self.logger.info("Creating %s feed for the first time" % self.feed_name)
            self.cb.feed_add_from_url("http://%s:%d%s" % (self.bridge_options['feed_host'],
                                                          self.bridge_options['listener_port'],
                                                          self.json_feed_path),
                                      True, False, False)

        return feed_id

    def serve(self):
        address = self.bridge_options.get('listener_address', '0.0.0.0')
        port = self.bridge_options['listener_port']
        self.logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=self.debug,
                                host=address, use_reloader=False)

    @property
    def feed(self):
        ret = self.feed_metadata
        with self.feed_lock:
            for domain in self.feed_domains.keys():
                report = {'id': "Domain-%s" % domain, 'link': 'http://infoblox.com', 'score': 100,
                          'timestamp': self.feed_domains[domain]['timestamp'], 'iocs': {'dns': [domain]},
                          'title': "Domain-%s" % domain}

                ret["reports"].append(report)

        return ret

    def handle_json_feed_request(self):
        return self.flask_feed.generate_json_feed(self.feed)

    def handle_html_feed_request(self):
        return self.flask_feed.generate_html_feed(self.feed, self.display_name)

    def handle_index_request(self):
        return self.flask_feed.generate_html_index(self.feed, self.bridge_options, self.display_name,
                                                   self.cb_image_path, self.integration_image_path,
                                                   self.json_feed_path)

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.integration_image_path))

    def restore_feed_files(self):
        """
        restore alerts from disk
        """
        num_restored = 0

        alert_filenames = os.listdir(self.data_dir)
        for alert_filename in alert_filenames:
            try:
                # read the alert file from disk and decode it's contents as JSON
                #
                report = cbint.utils.json.json_decode(open('%s/%s' % (self.data_dir, alert_filename)).read())

                # add the new report to the feed
                #
                self.feed["reports"].append(report)

            except Exception as e:
                self.logger.warn("Failure processing saved alert '%s' [%s]" % (alert_filename, e))
                continue

            num_restored += 1

        return num_restored

    def action(self, sensors, domain):
        """
        add a infoblox domain determination to a feed
        """
        # TODO: we need a timeout feature so domains will age out of the feed over time

        with self.feed_lock:
            if domain not in self.feed_domains:
                self.sync_needed = True
            self.feed_domains[domain]['timestamp'] = time.time()


"""The StreamingKillProcessAction will use the streaming interface to kill a process that contacts
a domain flagged by Infoblox immediately"""
class StreamingKillProcessAction(QueuedCbSubscriber, Action):
    def __init__(self, cb, logger, streaming_host, streaming_user, streaming_password):
        Action.__init__(self, cb, logger)
        # Define the "Be On The Lookout For" (bolo) list that we'll use when processing the stream...
        self.bolo = defaultdict(dict)
        self.bolo_lock = threading.Lock()
        super(StreamingKillProcessAction, self).__init__(streaming_host, streaming_user, streaming_password,
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


# TODO -- could this grow out of control or anything??
"""A LiveResponseThread is created for every sensor that has processes to kill"""
class LiveResponseThread(threading.Thread):
    """ note that timeout is not currently implemented
    """
    def __init__(self, cb, logger, sensor_id, process_ids, one_time=False, timeout=None):
        self.cb = cb
        self.logger = logger
        self.sensor_id = sensor_id
        self.process_list_lock = threading.Lock()
        self.process_ids = set(process_ids)
        self.remaining_process_ids = list(self.process_ids)
        self.killed_process_ids = set()
        self.result_available = False
        self.result = None
        self.done = False
        self.live_response_session = None
        self.newest_time_stamp = time.time()
        self.timeout = timeout
        self.one_time = one_time

        threading.Thread.__init__(self)

    def get_procs_left(self):
        with self.process_list_lock:
            process_ids = copy.copy(self.remaining_process_ids)
        return process_ids

    def killed_procs(self):
        with self.process_list_lock:
            killed_process_ids = copy.copy(self.killed_process_ids)
        return killed_process_ids

    def timed_out(self):
        return not self.is_alive() and not self.done

    def add_processes(self, process_ids):
        with self.process_list_lock:
            if not self.is_alive():
                return False

            self.newest_time_stamp = time.time()

            for process_id in process_ids:
                if process_id not in self.process_ids:
                    self.process_ids.add(process_id)
                    self.remaining_process_ids.append(process_id)
                    self.done = False

            return True

    def stop(self):
        self.done = True

    def _establish_live_response_session(self):
        resp = self.cb.live_response_session_create(self.sensor_id)
        session_id = resp.get('id')

        session_state = 'pending'
        while session_state != 'active':
            time.sleep(5)
            session_state = self.cb.live_response_session_status(session_id).get('status')
            self.logger.debug('LR status=%s' % session_state)

        self.logger.debug('I have a live response session: session_id=%d status=%s' % (session_id, session_state))

        self.live_response_session = session_id

    def _kill_process(self, pid):
        session_id = self.live_response_session
        resp = self.cb.live_response_session_command_post(session_id, "kill", pid)
        command_id = resp.get('id')
        killed = False
        count = 0

        while not killed and count < 5:
            resp = self.cb.live_response_session_command_get(session_id, command_id)
            self.logger.warn("Killing %d" % (pid))
            pprint.pprint(resp)
            if resp.get('status') == 'complete':
                killed = True
            count += 1
            time.sleep(.1)

        return killed

    def _kill_processes(self, target_proc_guids):
        session_id = self.live_response_session
        killed = []

        resp = self.cb.live_response_session_command_post(session_id, "process list")
        command_id = resp.get('id')

        command_state = 'pending'

        while command_state != 'complete':
            resp = self.cb.live_response_session_command_get(session_id, command_id)
            command_state = resp.get('status')
            time.sleep(.1)

        live_procs = resp.get('processes')
        for live_proc in live_procs:
            live_proc_guid = live_proc.get('proc_guid')
            if "iexplore.exe" in live_proc.get('path'):
                print live_proc
                print target_proc_guids

            if live_proc_guid in target_proc_guids:
                live_proc_pid = live_proc.get('pid')
                self.logger.warn("Killing! ----------------------------")
                pprint.pprint(live_proc)
                if self._kill_process(live_proc_pid):
                    self.logger.warn("KILLED %d" % live_proc_pid)
                    killed.append(live_proc_guid)

        return (len(live_procs) > 0), killed

    def run(self):
        self._establish_live_response_session()

        while not self.done:
            with self.process_list_lock:
                remaining_process_ids = copy.copy(self.remaining_process_ids)

            if len(remaining_process_ids):
                self.logger.warn('processes queued for termination: [%s]' % ', '.join(remaining_process_ids))
                success, killed = self._kill_processes(remaining_process_ids)

                with self.process_list_lock:
                    if success:
                        new_process_ids = []
                    else:
                        new_process_ids = self.remaining_process_ids
                    # Assume that if we successfully enumerated processes in _kill_processes, that we were able
                    # to kill any processes of interest that were running. The rest of the processes are already
                    # dead (since we get a lot of historical data from Cb)
                    #   new_process_ids = list(set(remaining_process_ids) - set(killed))
                    self.remaining_process_ids = new_process_ids

                    for proc in killed:
                        self.killed_process_ids.add(proc)

                    if not len(new_process_ids) and self.one_time:
                        self.done = True
            else:
                self.logger.warn('no processes queued for termination, sleeping')
            time.sleep(5)

        self.logger.warn('exiting LiveResponseThread')


"""The ApiKillProcessAction action will wait for the offending process to show up in a process search
then kill it using live response."""
class ApiKillProcessAction(threading.Thread, Action):
    def __init__(self, cb, logger):
        Action.__init__(self, cb, logger)
        self.stopped = False
        self.bolo = {}
        self.bolo_domains = set()
        self.bolo_searches = []
        self.bolo_lock = threading.Lock()
        threading.Thread.__init__(self)

    def stop(self):
        self.stopped = True

    def action(self, sensors, domain):
        # only take action on sensors that support CbLR
        for sensor in [sensor for sensor in sensors if sensor.get('supports_cblr', False) is True]:
            sensor_id = sensor.get('id')

            with self.bolo_lock:
                if sensor_id not in self.bolo:
                    new_thread = LiveResponseThread(self.cb, self.logger, sensor_id, [])
                    new_thread.start()
                    self.bolo[sensor_id] = \
                        {
                            'sensor_id': sensor_id,
                            'sensor': sensor,
                            'added': time.time(),
                            'killing_thread': new_thread,
                        }
                self.bolo_searches.append({
                    'domain': domain,
                    'sensor_id': sensor_id,
                    'timestamp': time.time()
                })

    def _add_processes_to_bolo(self, sensor_id, target_proc_guids):
        with self.bolo_lock:
            t = self.bolo[sensor_id]['killing_thread']
            if not t.add_processes(target_proc_guids):
                # old thread died, start another
                t.join()
                t = LiveResponseThread(self.cb, self.logger, sensor_id, [])
                t.start()
                self.bolo[sensor_id]['killing_thread'] = t
                t.add_processes(target_proc_guids)

    def run(self):
        while not self.stopped:
            with self.bolo_lock:
                # TODO: implement timeout for bolo_searches
                bolo_searches = copy.copy(self.bolo_searches)

            for search_entry in bolo_searches:
                self.logger.info(search_entry)
                query = 'sensor_id:{0:d} domain:{1:s}'.format(search_entry['sensor_id'],
                                                              search_entry['domain'])
                procs = self.cb.process_search_iter(query)
                target_proc_guids = [proc.get('id') for proc in procs]
                self._add_processes_to_bolo(search_entry['sensor_id'], target_proc_guids)

            time.sleep(15)

        for bolo in self.bolo:
            if bolo['killing_thread']:
                bolo['killing_thread'].join()


class InfobloxBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile)
        self.cb = None
        self.bridge_options = {}
        self.debug = False

#        super(InfobloxIntegration, self).__init__(*args, **kwargs)

    def run(self):
        try:
            self.logger.warn("CB Infoblox Bridge Starting")
            sslverify = False if self.bridge_options.get('carbonblack_server_sslverify', "0") == "0" else True
            self.cb = cbapi.CbApi(self.bridge_options['carbonblack_server_url'],
                                  token=self.bridge_options['carbonblack_server_token'],
                                  ssl_verify=sslverify)

            self.logger.debug("checking CB server version")
            if not cbint.utils.cbserver.is_server_at_least(self.cb, "4.1"):
                self.logger.error("the configured Carbon Black Enterprise server does not meet the minimum "
                                  "required version (4.1)")
                return

            self.streaming_host = self.bridge_options.get('carbonblack_streaming_host')
            self.streaming_username = self.bridge_options.get('carbonblack_streaming_username')
            self.streaming_password = self.bridge_options.get('carbonblack_streaming_password')

            syslog_server = SyslogServer(10240, self.logger)
            message_broker = FanOutMessage(self.cb, self.logger)

            flusher = FlushAction(self.cb, self.logger)
            isolator = IsolateAction(self.cb, self.logger)
            feed_thread = FeedAction(self.cb, self.logger, self.bridge_options)
            feed_thread.start()

            kill_process_thread = ApiKillProcessAction(self.cb, self.logger)
            kill_process_thread.start()
            kill_streaming_action = StreamingKillProcessAction(self.cb, self.logger, self.streaming_host, self.streaming_username, self.streaming_password)
            t1 = threading.Thread(target=kill_streaming_action.process)
            t1.start()

            message_broker.add_response_action(feed_thread.action)
            message_broker.add_response_action(flusher.action)
    #        message_broker.add_response_action(isolator.action)
    #        message_broker.add_response_action(kill_process_thread.action)
            message_broker.add_response_action(kill_streaming_action.action)
            syslog_server.start()
            message_broker.start()

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
