import threading
import socket
import re
import traceback
import logging
import infoblox_api
import time
import sys
from datetime import datetime,timedelta


logger = logging.getLogger(__name__)

class RestPoller(threading.Thread):
    def __init__(self,route, auth_token, worker_queue=None,time_increment=None):
        global logger
        if not time_increment:
            time_increment = "5M"
        self.route = route
        self.auth_token = auth_token
        self.worker_queue = worker_queue
        threading.Thread.__init__(self)
        specs = {"M": "minutes", "W": "weeks", "D": "days", "S": "seconds", "H": "hours"}
        arg = time_increment[:-1]
        spec = time_increment[-1:]
        self.TIME_INCREMENT = timedelta(**{specs[spec.upper()]: int(arg)})

    def run(self):
        global logger
        try:
            last_check = 0
            while (True):
                # do cool stuff
                utc_now = int(time.time())

                res = infoblox_api.dns_event_request(self.route, t0=last_check, t1=utc_now, auth_token=self.auth_token)
                last_check = utc_now

                logger.info(res)

                parsed_result = infoblox_api.parse_infoblox_dns_event(res)
                if parsed_result:
                    for r in parsed_result:
                        logger.info(r)
                        self.worker_queue.put((r['device'], r['qname']))

                # go to sleep till we another increment passes

                logger.info("Sleeping for time increment + {}".format(self.TIME_INCREMENT))
                time.sleep(self.TIME_INCREMENT.total_seconds())
                logger.info("Done sleeping!")

        except:
            logger.error('%s' % traceback.format_exc())
            logger.info("%s" % traceback.format_exc())
        logger.info("Rest api poller existing")


class printingQueue():
    def put(self,object):
        print (str(object))

if __name__=="__main__":

    rp = RestPoller("https://csp.infoblox.com/api/threats/v1/dns_event",sys.argv[1],worker_queue=printingQueue(),time_increment="30S")
    rp.run()
