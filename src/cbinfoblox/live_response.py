__author__ = 'cb'

import threading
import time
import copy
import pprint

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

