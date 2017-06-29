__author__ = 'cb'

import threading
import socket
import re
import traceback
import logging

logger = logging.getLogger(__name__)

class SyslogServer(threading.Thread):
    def __init__(self, syslog_port, worker_queue):
        self.syslog_port = syslog_port
        self.worker_queue = worker_queue
        self.format_string = \
            re.compile('src=(\d+.\d+.\d+.\d+) .*rewrite (?=.{1,254}$)((?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,}))')
        threading.Thread.__init__(self)

    def run(self):
        try:
            syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            listen_addr = ("", self.syslog_port)
            syslog_socket.bind(listen_addr)

            while True:
                data, addr = syslog_socket.recvfrom(2048)
                data = data.strip()
                hit = self.format_string.search(data)
                if hit:
                    self.worker_queue.put((hit.group(1), hit.group(2)))
        except:
            logger.error('%s' % traceback.format_exc())


class TestSyslogServer(threading.Thread):
    def __init__(self, syslog_port, worker_queue):
        self.syslog_port = syslog_port
        self.worker_queue = worker_queue
        threading.Thread.__init__(self)

    def run(self):
        try:
            syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            listen_addr = ("", self.syslog_port)
            syslog_socket.bind(listen_addr)

            while True:
                data, addr = syslog_socket.recvfrom(2048)
                data = data.strip()
                hit = self.format_string.search(data)
                if hit:
                    self.worker_queue.put((hit.group(1), hit.group(2)))
        except:
            logger.error('%s' % traceback.format_exc())
