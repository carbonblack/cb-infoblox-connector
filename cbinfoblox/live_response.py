import threading
import time
import copy
import logging
import traceback

from cbapi.response.models import Sensor
from cbapi.response.live_response_api import LiveResponseSession

logger = logging.getLogger(__name__)

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
        sensor = self.cb.select(Sensor, self.sensor_id)
        self.lr_session = sensor.lr_session()

    def _kill_process(self, pid):

        self.logger.warn("Killing %d" % pid)
        self.lr_session.kill_process(pid)

        return True #TODO

    def _kill_processes(self, target_proc_guids):
        killed = []

        live_procs = self.lr_session.list_processes()

        for live_proc in live_procs:
            live_proc_guid = live_proc.get('proc_guid')
            if live_proc_guid in target_proc_guids:
                live_proc_pid = live_proc.get('pid')
                if self._kill_process(live_proc_pid):
                    self.logger.warn("KILLED %d" % live_proc_pid)
                    killed.append(live_proc_guid)

        return (len(live_procs) > 0), killed

    def run(self):
        try:
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
        except:
            logger.error(traceback.format_exc())

