import threading
import copy
import time
from action import Action
from live_response import LiveResponseThread
import logging
import traceback

logger = logging.getLogger(__name__)

"""The ApiKillProcessAction action will wait for the offending process to show up in a process search
then kill it using live response."""
class ApiKillProcessAction(threading.Thread, Action):
    def __init__(self, cb):
        Action.__init__(self, cb)
        self.stopped = False
        self.bolo = {}
        self.bolo_domains = set()
        self.bolo_searches = []
        self.bolo_lock = threading.Lock()
        threading.Thread.__init__(self)

    def name(self):
        return 'Find & Kill process via API'

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
            if not t.add_processes(target_proc_guids):
                # old thread died, start another
                t.join()
                t = LiveResponseThread(self.cb, sensor_id, [])
                t.start()
                self.bolo[sensor_id]['killing_thread'] = t
                t.add_processes(target_proc_guids)

    def run(self):
        try:
            while not self.stopped:
                with self.bolo_lock:
                    # TODO: implement timeout for bolo_searches
                    bolo_searches = copy.copy(self.bolo_searches)

                for search_entry in bolo_searches:
                    logger.info('%s' % search_entry)
                    query = 'sensor_id:{0:d} domain:{1:s}'.format(search_entry['sensor_id'],
                                                                  search_entry['domain'])
                    procs = self.cb.process_search_iter(query)
                    target_proc_guids = [proc.get('id') for proc in procs]
                    self._add_processes_to_bolo(search_entry['sensor_id'], target_proc_guids)

                time.sleep(60)

            for bolo in self.bolo:
                if bolo['killing_thread']:
                    bolo['killing_thread'].join()
        except:
            logger.error(traceback.format_exc())
