__author__ = 'cb'


import socket
import re
import threading
import time
import cbapi
import Queue
import pprint
import copy
import sys

from cbint import CbIntegrationDaemon

worker_queue = Queue.Queue(maxsize=10)

def isolate_sensor(cb, sensor_id):
    cb.sensor_toggle_isolation(sensor_id, True)

def flush_sensor(cb, sensor_id):
    flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
    cb.sensor_flush(sensor_id, flush_time)



class FanOutMessage(threading.Thread):
    def __init__(self, cb):
        self.cb = cb
        self.actions = []
        # TODO: this should be a proper cache with a timeout...
        self.sensor_cache = {}

        threading.Thread.__init__(self)

    def add_response_action(self, action):
        self.actions.append(action)

    def run(self):
        while True:
            sensor_ip, domain = worker_queue.get()
            print 'got %s:%s from queue' % (sensor_ip, domain)
            if sensor_ip not in self.sensor_cache:
                sensors = self.cb.sensors(query_parameters={'ip': sensor_ip})
                # ensure that each sensor at least has an ID
                self.sensor_cache[sensor_ip] = [sensor for sensor in sensors if sensor.get('id')]

            for action in self.actions:
                print 'Dispatching action %s based on %s:%s' % (action, sensor_ip, domain)
                action(self.sensor_cache[sensor_ip], domain)

            worker_queue.task_done()


class SyslogServer(threading.Thread):
    def __init__(self, syslog_port):
        self.syslog_port = syslog_port
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
            print 'got data: %s' % data
            hit = self.format_string.search(data)
            if hit:
                print 'adding to queue: %s : %s' % (hit.group(1), hit.group(2))
                worker_queue.put((hit.group(1), hit.group(2)))


class FlushAction(object):
    def __init__(self, cb):
        self.cb = cb

    def action(self, sensors, domain):
        for sensor in sensors:
            flush_sensor(self.cb, sensor['id'])


class IsolateAction(object):
    def __init__(self, cb):
        self.cb = cb

    def action(self, sensors, domain):
        for sensor in sensors:
            if sensor.get('supports_isolation', False):
                isolate_sensor(self.cb, sensor['id'])


"""The StreamingKillProcessAction will use the streaming interface to kill a process that contacts
a domain flagged by Infoblox immediately"""
class StreamingKillProcessAction(threading.Thread):
    def __init__(self, cb):
        self.cb = cb
        # Define the "Be On The Lookout For" (bolo) list that we'll use when processing the stream...
        self.bolo = []
        threading.Thread.__init__(self)


"""A LiveResponseThread is created for every sensor that has processes to kill"""
class LiveResponseThread(threading.Thread):
    """ note that timeout is not currently implemented
    """
    def __init__(self, cb, sensor_id, process_ids, timeout=None):
        self.cb = cb
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

        threading.Thread.__init__(self)

    def get_procs_left(self):
        with self.process_list_lock:
            process_ids = copy.copy(self.remaining_process_ids)
        return process_ids

    def timed_out(self):
        return not self.is_alive() and not self.done

    def add_processes(self, process_ids):
        if not self.is_alive():
            return False

        with self.process_list_lock:
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
        while session_state != 'complete':
            time.sleep(5)
            session_state = self.cb.live_response_session_status(session_id).get('status')

        print 'I have a live response session: session_id=%d status=%s' % (session_id, session_state)

        self.live_response_session = session_id

    def _kill_process(self, pid):
        session_id = self.live_response_session
        resp = self.cb.live_response_session_command_post(session_id, "kill", pid)
        command_id = resp.get('id')
        killed = False
        count = 0

        while not killed and count < 5:
            resp = self.cb.live_response_session_command_get(session_id, command_id)
            print "Killing %d" % (pid)
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
                print "Killing! ----------------------------"
                pprint.pprint(live_proc)
                if self._kill_process(live_proc_pid):
                    print "KILLED %d" % live_proc_pid
                    killed.append(live_proc_guid)

        return killed

    def run(self):
        self._establish_live_response_session()

        while not self.done:
            with self.process_list_lock:
                remaining_process_ids = copy.copy(self.remaining_process_ids)

            if len(remaining_process_ids):
                print 'processes queued for termination: [%s]' % ', '.join(remaining_process_ids)
                killed = self._kill_processes(remaining_process_ids)

                with self.process_list_lock:
                    new_process_ids = list(set(remaining_process_ids) - set(killed))
                    self.remaining_process_ids = new_process_ids
                    if not len(self.remaining_process_ids):
                        self.done = True
            else:
                print 'no processes queued for termination, sleeping'
            time.sleep(5)


"""The ApiKillProcessAction action will wait for the offending process to show up in a process search
then kill it using live response."""
class ApiKillProcessAction(threading.Thread):
    def __init__(self, cb):
        self.cb = cb
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
                    new_thread = LiveResponseThread(self.cb, sensor_id, [])
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
            t.add_processes(target_proc_guids)

    def run(self):
        while not self.stopped:
            with self.bolo_lock:
                # TODO: implement timeout for bolo_searches
                bolo_searches = copy.copy(self.bolo_searches)

            for search_entry in bolo_searches:
                print search_entry
                query = 'sensor_id:{0:d} domain:{1:s}'.format(search_entry['sensor_id'],
                                                              search_entry['domain'])
                procs = self.cb.process_search_iter(query)
                target_proc_guids = [proc.get('id') for proc in procs]
                self._add_processes_to_bolo(search_entry['sensor_id'], target_proc_guids)

            time.sleep(15)


class InfobloxIntegration(CbIntegrationDaemon):
    def __init__(self, *args, **kwargs):
        cb_url = kwargs.pop('cb_url', None)
        cb_token = kwargs.pop('cb_token', None)

        if not cb_url or not cb_token:
            raise Exception("Need Cb URL & token")

        super(InfobloxIntegration, self).__init__(*args, **kwargs)

        self.cb = cbapi.CbApi(cb_url, token=cb_token, ssl_verify=False)

    def run(self):
        syslog_server = SyslogServer(10240)
        message_broker = FanOutMessage(self.cb)

        flusher = FlushAction(self.cb)
        isolator = IsolateAction(self.cb)

        kill_process_thread = ApiKillProcessAction(self.cb)
        kill_process_thread.start()

        message_broker.add_response_action(flusher.action)
        message_broker.add_response_action(isolator.action)
        message_broker.add_response_action(kill_process_thread.action)
        syslog_server.start()
        message_broker.start()

if __name__ == '__main__':
    # debugging, call .run() directly (rather than .start())
    i = InfobloxIntegration('infoblox', debug=True, cb_url=sys.argv[1], cb_token=sys.argv[2])
    i.run()

