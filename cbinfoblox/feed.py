import json
import threading
import os
import time
from collections import defaultdict
from action import Action
from cbint.utils.flaskfeed import FlaskFeed
from cbint.utils.filesystem import ensure_directory_exists
import cbint.utils.feed
from cbapi.response import CbResponseAPI, Feed
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.errors import ServerError

import logging
import traceback

logger = logging.getLogger(__name__)

"""The FeedAction will start a web server and create a feed consumable by Carbon Black that
lists all processes flagged by infoblox"""
class FeedAction(threading.Thread, Action):
    def __init__(self, cb, bridge_options):
        try:
            Action.__init__(self, cb) # TODO -- maybe a ThreadedAction class?
            threading.Thread.__init__(self)
            self.flask_feed = FlaskFeed(__name__)
            self.bridge_options = bridge_options
            self.data_dir = "/usr/share/cb/integrations/infoblox"

            self.sync_needed = False
            self.feed_name = "infoblox"
            self.display_name = "Infoblox"
            self.feed = {}
            self.feed_domains = defaultdict(dict)
            self.feed_lock = threading.Lock()
            self.directory = self.data_dir
            self.cb_image_path = "/carbonblack.png"
            self.integration_image_path = "/infoblox.png"
            self.json_feed_path = "/infoblox/json"
            self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
            self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
            self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
            self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
            self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])
        except:
            logger.error('%s' % traceback.format_exc())

    def name(self):
        return 'Add results to feed'

    def run(self):
        try:
            # make data directories as required
            #
            ensure_directory_exists(self.data_dir)

            # restore alerts from disk if so configured
            #
            num_restored = 0
            if int(self.bridge_options.get('restore_feed_on_restart', 1)):
                logger.info("Restoring saved feed...")
                num_restored = self.restore_feed_files()

            self.feed = self.generate_feed()

            logger.info("Restored %d alerts" % num_restored)
            logger.info("starting feed server")

            self.serve()
        except:
            logger.error('%s' % traceback.format_exc())

    def get_or_create_feed(self):

        feed = None

        try:
            feeds = get_object_by_name_or_id(self.cb, Feed, name=self.feed_name)
        except Exception as e:
            logger.error(e.message)
            feeds = None

        if not feeds:
            logger.info("Feed {} was not found, so we are going to create it".format(self.feed_name))
            f = self.cb.create(Feed)
            f.feed_url = "http://%s:%d%s" % (self.bridge_options.get('feed_host', '127.0.0.1'),
                                             int(self.bridge_options['listener_port']),
                                             self.json_feed_path)
            f.enabled = True
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    logger.info("Could not add feed:")
                    logger.info(
                        " Received error code 500 from server. This is usually because the server cannot retrieve the feed.")
                    logger.info(
                        " Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    logger.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                logger.info("Could not add feed: {0:s}".format(str(e)))
            else:
                logger.info("Feed data: {0:s}".format(str(f)))
                logger.info("Added feed. New feed ID is {0:d}".format(f.id))
                f.synchronize(False)
                self.feed_object = f


        elif len(feeds) > 1:
            logger.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))

        elif feeds:
            feed_id = feeds[0].id
            logger.info("Feed {} was found as Feed ID {}".format(self.feed_name, feed_id))
            feeds[0].synchronize(False)
            feed = feeds[0]

        self.feed_object = feed

    def serve(self):
        address = self.bridge_options.get('listener_address', '0.0.0.0')
        port = int(self.bridge_options['listener_port'])
        logger.info("starting flask server: %s:%d" % (address, port))
        self.flask_feed.app.run(port=port, debug=True,
                                host=address, use_reloader=False)

    def generate_feed(self):
        logger.info("Generating feed")
        icon_path="%s/%s" % (self.directory, self.integration_image_path)
        logger.info("icon_path: %s" % icon_path)

        ret = cbint.utils.feed.generate_feed(self.feed_name, summary="Infoblox secure DNS domain connector",
                        tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                        provider_url="http://www.infoblox.com/", icon_path=icon_path,
                        display_name=self.display_name, category="Connectors")

        ret['reports'] = []

        with self.feed_lock:
            for domain in self.feed_domains.keys():
                report = {'id': "Domain-%s" % domain, 'link': 'http://www.infoblox.com', 'score': 100,
                          'timestamp': self.feed_domains[domain]['timestamp'], 'iocs': {'dns': [domain]},
                          'title': "Domain-%s" % domain}
                logger.info("Adding domain %s to feed" % domain)
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
        fn = '%s/%s' % (self.data_dir, 'infoblox_domains.json')
        new_domains = {}
        if os.path.isfile(fn):
            try:
                new_domains = json.load(open('%s/%s' % (self.data_dir, 'infoblox_domains.json')))
                self.feed_domains.update(new_domains)
            except:
                pass

        return len(new_domains)

    def action(self, sensors, domain):
        """
        add a infoblox domain determination to a feed
        """
        # TODO: we need a timeout feature so domains will age out of the feed over time
        try:
            logger.warn("Adding domain: %s" % domain)
            with self.feed_lock:
                if domain not in self.feed_domains:
                    self.sync_needed = True
                self.feed_domains[domain]['timestamp'] = time.time()
                json.dump(self.feed_domains, open('%s/%s' % (self.data_dir, 'infoblox_domains.json'), 'w'))

            self.feed = self.generate_feed()

            if self.sync_needed and self.feed:
                self.feed_object.synchronize(False)
                self.sync_needed = False
        except:
            logger.error('%s' % traceback.format_exc())
