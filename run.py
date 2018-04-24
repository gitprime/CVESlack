import argparse
from time import sleep

import yaml

from slackposter import CVEPoster

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Parse a vulnerability feed and look for specific vendors')
    argparser.add_argument('--config-file', '-f', default='config.yml', dest='config_file',
                           help='Sets the file to pull patterns from (defaults to ".dependencies.txt")')
    args = argparser.parse_args()
    slack_post_interval = 5


    while True:
        with open(args.config_file, 'r') as stream:
            try:
                config = yaml.safe_load(stream)
                cve_poster = CVEPoster(config)
                slack_post_interval = config.get('slack_post_interval')
                cve_poster.post_to_feed_if_needed(config)
            except:
                pass
        sleep(slack_post_interval * 60)
