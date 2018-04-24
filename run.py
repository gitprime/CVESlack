import argparse
from time import sleep

import yaml

from slackposter import CVEPoster

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Parse a vulnerability feed and look for specific vendors')
    argparser.add_argument('--config-file', '-f', default='config.yml', dest='config_file',
                           help='Sets the file to pull patterns from (defaults to ".dependencies.txt")')
    args = argparser.parse_args()
    cve_poster = CVEPoster(args.config_file)
    while True:
        cve_poster.post_to_feed_if_needed()
        sleep(10)
