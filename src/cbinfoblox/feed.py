__author__ = 'cb'

import simplejson as json
import threading
import os
import time
from collections import defaultdict
from action import Action
from cbint.utils.flaskfeed import FlaskFeed
from cbint.utils.filesystem import ensure_directory_exists
import cbint.utils.feed



"""The FeedAction will start a web server and create a feed consumable by Carbon Black that
lists all processes flagged by infoblox"""
class FeedAction(threading.Thread, Action):
    def __init__(self, cb, logger, bridge_options):
        try:
            Action.__init__(self, cb, logger) # TODO -- maybe a ThreadedAction class?
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
            self.directory = os.path.dirname(os.path.realpath(__file__))
            self.cb_image_path = "/content/carbonblack.png"
            self.integration_image_path = "/content/infoblox.png"
            self.json_feed_path = "/infoblox/json"
            self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
            self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
            self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
            self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
            self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])
        except:
            import traceback
            self.logger.error(traceback.format_exc())

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
                self.logger.info("Restoring saved feed...")
                num_restored = self.restore_feed_files()

            self.feed = self.generate_feed()
            feed_id = self.get_or_create_feed()

            self.logger.info("Restored %d alerts" % num_restored)
            self.logger.info("starting feed server")

            self.serve()
        except:
            import traceback
            self.logger.error(traceback.format_exc())

    def get_or_create_feed(self):
        feed_id = self.cb.feed_get_id_by_name(self.feed_name)
        if not feed_id:
            self.logger.info("Creating %s feed for the first time" % self.feed_name)
            self.cb.feed_add_from_url("http://%s:%d%s" % (self.bridge_options['feed_host'],
                                                          int(self.bridge_options['listener_port']),
                                                          self.json_feed_path),
                                      True, False, False)

        return feed_id

    def serve(self):
        address = self.bridge_options.get('listener_address', '0.0.0.0')
        port = self.bridge_options['listener_port']
        self.logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=True,
                                host=address, use_reloader=False)

    def generate_feed(self):
        self.logger.info("Generating feed")
        icon_path="%s/%s" % (self.directory, self.integration_image_path)
        self.logger.info("icon_path: %s" % icon_path)

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
                self.logger.info("Adding domain %s to feed" % domain)
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
            self.logger.warn("Adding domain: %s" % domain)
            with self.feed_lock:
                if domain not in self.feed_domains:
                    self.sync_needed = True
                self.feed_domains[domain]['timestamp'] = time.time()
                json.dump(self.feed_domains, open('%s/%s' % (self.data_dir, 'infoblox_domains.json'), 'w'))

            self.feed = self.generate_feed()

            if self.sync_needed:
                self.cb.feed_synchronize(self.feed_name)
                self.sync_needed = False
        except:
            import traceback
            self.logger.error(traceback.format_exc())
