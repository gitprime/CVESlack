import datetime
import re

import requests
import yaml

from cveparser import CVEParser
from query import Query


def get_cve_generator(config):
    cve_feed_gen = CVEParser(config)
    strip_spaces = config.get('strip_spaces')
    pattern_file = config.get('pattern_file')

    with open(pattern_file) as f:
        requirements_contents = re.split('\r?\n', f.read())
        # Generates required version string
        requirements_output = []
        for requirement in requirements_contents:
            if len(requirement.strip()) == 0:
                continue
            if '==' in requirement:
                requirements_output.append(requirement.split('=='))
            else:
                requirements_output.append([requirement])

        for requirement in requirements_output:
            if not requirement or len(requirement) == 0:
                continue
            left_padding = requirement[0].startswith('__')
            right_padding = requirement[0].endswith('__')
            if len(requirement) > 1:
                cve_feed_gen.add_desired_string(Query(requirement[0], required_tags=requirement[1:],
                                                      left_padded=left_padding, right_padded=right_padding,
                                                      strip_padding=strip_spaces))
            else:
                cve_feed_gen.add_desired_string(
                    Query(requirement[0], left_padded=left_padding, right_padded=right_padding,
                          strip_padding=strip_spaces))

    return cve_feed_gen


class CVEPoster:

    def __init__(self, config_file):
        self.config_file = config_file
        self.last_update = None
        self.cve_list = None
        self.old_cve_list = None
        self.post_to_feed_if_needed()
        self.slack_webhook = None

    def post_to_feed_if_needed(self):
        now = datetime.datetime.now()
        if self.last_update is None or (now - self.last_update).total_seconds() > 10:
            with open(self.config_file, 'r') as stream:
                try:
                    config = yaml.safe_load(stream)
                    self.slack_webhook = config.get('slack_webhook')

                except yaml.YAMLError as exc:
                    print(exc)
                    return

                self.cve_list = list(cve for cve in get_cve_generator(config).generate_feed())

                print('Reloaded CVE feeds and patterns. Posting messages if necessary.')
                if self.old_cve_list:
                    diffed_list = list(set(self.cve_list) - set(self.old_cve_list))
                    for item in diffed_list:
                        response = requests.post(self.slack_webhook, item)
                        response.raise_for_status()
                else:
                    for item in self.cve_list:
                        response = requests.post(self.slack_webhook, item)
                        response.raise_for_status()

                if self.cve_list:
                    self.old_cve_list = self.cve_list
            self.last_update = now
