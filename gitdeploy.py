#!/usr/bin/env python
# encoding: utf-8
#
# gitdeploy provides a way to automatically deploy git repositories
#
# Copyright (C) 2015        Raphaël Beamonte <raphael.beamonte@gmail.com>
#
# This file is part of gitdeploy.  gitdeploy is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
# or see <http://www.gnu.org/licenses/>.

# Python lib
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
import os.path
import pwd
import re
import urlparse
import yaml
import shlex
import subprocess
import sys

CURRENT_DIR = os.path.realpath('.')
LOG_FORMAT = "%(asctime)s::%(name)s::%(levelname)s::%(message)s"
LOG_LEVEL = logging.DEBUG
MANDATORY_RULE_ARG = ['url', 'path']


def setenv(uid=None, gid=None):
    """
    Allows to change the effective uid and gid
    """
    if uid is None and gid is None:
        os.setegid(os.getgid())
        os.seteuid(os.getuid())
    else:
        os.setegid(gid)
        os.seteuid(uid)


class GitDeployHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def __user_log(self, user, lvl, msg, *args, **kwargs):
        # Get local logger
        log = logging.getLogger(user.pw_name)

        # Set local logfile
        logfile = os.path.join(user.pw_dir, 'gitdeploy.log')

        # Prepare log handler
        handler = logging.FileHandler(logfile, mode='a+')
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        log.addHandler(handler)

        # Write log
        log.log(lvl, msg, *args, **kwargs)

        # Remove then closes handler
        log.removeHandler(handler)
        handler.close()

    # HTTP handling
    def do_POST(self):
        """
        Method to run when receiving a POST request: we need to
        analyze the hook and to treat the deployment rules if
        there is any.
        """
        repositories = self.__parse_request()
        self.__send_answer()

        self.server.log.debug("Repositories in the request: %s", repositories)

        if repositories:
            work = self.__search_hooks(repositories)

            if work:
                self.server.log.debug("Rules found: %s", work)

                for repo, users in work.items():

                    for repos in repositories:
                        if repo in repos[0]:
                            repo = repos
                            break

                    for user, rules in users.items():
                        u = pwd.getpwnam(user)

                        setenv(u.pw_uid, u.pw_gid)
                        os.environ['HOME'] = u.pw_dir

                        for rule in rules:
                            os.chdir(u.pw_dir)

                            if 'name' not in rule:
                                rule['name'] = rule['url']

                            try:
                                self.__deploy_worker(u, repo, rule)
                            except Exception as e:
                                self.__user_log(
                                    u,
                                    logging.ERROR,
                                    'Error when running rule %s',
                                    rule['name'],
                                    exc_info=sys.exc_info()
                                )

                        # Reset uid and gid
                        setenv()

                os.environ['HOME'] = pwd.getpwuid(os.getuid()).pw_dir

    def __parse_request(self):
        # Verify that the request was of the right type
        ctype = self.headers.getheader('content-type')
        if ctype not in [
                'application/json',
                'application/x-www-form-urlencoded']:
            self.server.log.debug(
                'Request \'Content-Type\' is invalid: %s' % ctype)
            return False

        # Get the content
        try:
            rq_length = int(self.headers.getheader('content-length'))
            rq_content = self.rfile.read(rq_length)
            content = urlparse.parse_qs(rq_content)
            if 'repository' not in content and 'payload' not in content:
                content = json.loads(rq_content)
        except Exception as e:
            self.server.log.debug('Error while getting content',
                                  exc_info=sys.exc_info())
            return False

        if not content:
            return False

        self.server.log.debug("Received request: %s", content)

        repos = []

        def get_repos(entry):
            if 'repository' in entry:
                # Get the URL list
                ulist = []
                if ('absolute_url' in entry['repository']
                        and 'scm' in entry['repository']
                        and entry['repository']['scm'] == 'git'):
                    ulist.append('git@bitbucket.org' +
                                 item['repository']['absolute_url'][0:-1])
                else:
                    for u in ['clone_url',
                              'git_http_url',
                              'ssh_url',
                              'git_ssh_url',
                              'git_url',
                              'url']:
                        if u in entry['repository']:
                            ulist.append(entry['repository'][u])

                if not ulist:
                    return

                # Get the branch
                ref = ()
                if 'ref' in entry:
                    if 'ref_type' in entry:
                        ref = (entry['ref_type'], entry['ref'])
                    else:
                        r, rpath, rname = entry['ref'].split('/', 3)
                        if r == 'refs':
                            if rpath == 'tags':
                                rtype = 'tag'
                            else:
                                rtype = 'branch'
                            ref = (rtype, rname)
                        else:
                            ref = ('', entry['ref'])

                # Get the commit
                commit = ''
                if 'after' in entry:
                    commit = entry['after']

                # Finally, add to the repos list
                if ulist:
                    repos.append((ulist, ref, commit))

        if 'payload' in content:
            for item in content['payload']:
                entry = json.loads(item)
                get_repos(entry)
        else:
            get_repos(content)

        return repos

    def __send_answer(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    # DEPLOY handling
    def __search_hooks(self, repositories):
        hooks = {}

        # Load users' deploy rules
        for u in pwd.getpwall():
            try:
                # Work as user
                setenv(u.pw_uid, u.pw_gid)
            except Exception as e:
                self.server.log.debug("Can't switch to user %s (%d, %d)" % (
                    u.pw_name,
                    u.pw_uid,
                    u.pw_gid,
                ))
                continue

            # Check if we have a .gitdeploy.yml file for the user
            fname = os.path.join(u.pw_dir, '.gitdeploy.yml')
            if os.path.isfile(fname):
                rules = []
                try:
                    with open(fname, 'r') as f:
                        rules = yaml.load(f)
                except (IOError, yaml.parser.ParserError) as e:
                    self.__user_log(
                        u,
                        logging.ERROR,
                        'Error when parsing file %s',
                        fname,
                        exc_info=sys.exc_info()
                    )

                if rules and 'git' in rules:
                    for rule in rules['git']:
                        for arg in MANDATORY_RULE_ARG:
                            if arg not in rule:
                                self.__user_log(
                                    u,
                                    logging.WARNING,
                                    "Missing mandatory argument"
                                    "'%s' in rule: %s",
                                    arg,
                                    yaml.dump(rule))
                                continue

                        for repo in repositories:
                            if rule['url'] not in repo[0]:
                                continue

                            rtype, rname = repo[1]
                            if rtype in rule:
                                if 'only' in rule[rtype]:
                                    if rname not in rule[rtype]['only']:
                                        continue
                                elif 'except' in rule[rtype]:
                                    if rname in rule[rtype]['except']:
                                        continue

                            if repo[0][0] not in hooks:
                                hooks[repo[0][0]] = {u.pw_name: [rule, ]}
                            else:
                                hooks[repo[0][0]][u.pw_name].append(rule)

            # Get back as us
            setenv()

        return hooks

    def __callstack(self, user, commands, returns=False):
        if returns:
            results = []

        for command in commands:
            args = shlex.split(command)

            run = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            out = run.communicate()[0].rstrip()

            if run.returncode != 0:
                self.__user_log(
                    user,
                    logging.ERROR,
                    "Error (%d) while running command: %s",
                    run.returncode,
                    command)
                return (run.returncode, command)

            if returns:
                results.append(out)
            else:
                self.__user_log(
                    user,
                    logging.INFO,
                    "%s",
                    out)

        if returns:
            return results
        else:
            return True

    def __pull_git(self, user, repo, rule):
        os.chdir(rule['path'])

        rtype, rname = repo[1]
        commit = repo[2]

        commands = [
            "git fetch --all",
            "git update-index --refresh"
        ]

        if rtype == 'branch':
            commands += [
                "git branch -r --contains %s" % commit,
                "git branch -lvv",
            ]
            run = self.__callstack(user, commands, True)
            if isinstance(run, tuple):
                return False

            rbranch = run[-2].split('\n', 2)[0].strip()

            m = re.search(
                "(?P<selected>\*)?\s+(?P<branch>[^ ]+)\s+"
                "(?P<commit>[a-z0-9]*)\s+\[(?P<remote>" +
                re.escape(rbranch) +
                ")(?:\: behind (?P<behind>[0-9]+))?\]",
                run[-1]
            )
            commands = []
            if not m:
                commands.append("git checkout -b %s %s" % (rname, rbranch))
            elif m.group('selected') == '':
                commands.append("git checkout %s" % m.group('branch'))

            commands.append("git reset --hard %s" % rbranch)
            run = self.__callstack(user, commands, True)
            if isinstance(run, tuple):
                return False

            m = re.search("HEAD is now at (?P<commit>[a-z0-9]+) ", run[-1])
            if not m:
                return False

            if commit.startswith(m.group('commit')):
                return True

            commands = [
                "git checkout %s" % commit,
            ]
        else:
            commands += [
                "git checkout %s" % rname,
            ]

        run = self.__callstack(user, commands, True)
        if isinstance(run, tuple):
            return False
        else:
            return True

    def __deploy_worker(self, user, repo, rule):
        if 'deploy' in rule:
            if 'before' in rule['deploy']:
                run = self.__callstack(user, rule['deploy']['before'])
                if not run:
                    return False

        run = self.__pull_git(user, repo, rule)
        if not run:
            return False

        if 'deploy' in rule:
            if 'after' in rule['deploy']:
                run = self.__callstack(user, rule['deploy']['after'])
                if not run:
                    return False

        return True


class GitDeployServer(HTTPServer):
    def __init__(self, server_address, config):
        HTTPServer.__init__(self, server_address, GitDeployHandler)

        # Save configuration for global use
        self.config = config

        # Get local logger
        self.log = logging.getLogger(__name__)

        # Set the log in the right place
        if 'files' in self.config and 'log' in self.config['files']:
            logfile = self.config['files']['log']
        else:
            logfile = os.path.join(CURRENT_DIR, 'gitdeploy.log')

        handler = logging.FileHandler(logfile, mode='a+')
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        self.log.addHandler(handler)

        self.log.info('GitDeployServer started on port %d' % server_address[1])


def run(config):
    server_address = ('', config['server']['port'])
    httpd = GitDeployServer(server_address, config)
    httpd.serve_forever()

if __name__ == "__main__":
    logging.basicConfig(
        format=LOG_FORMAT,
        level=LOG_LEVEL)
    log = logging.getLogger(__name__)

    # Load configuration
    confpath = [
        './gitdeploy.yml',
        '/etc/gitdeploy.yml',
    ]
    CONF = False
    for path in confpath:
        fname = os.path.realpath(os.path.expanduser(path))
        if os.path.isfile(fname):
            with open(fname, 'r') as f:
                CONF = yaml.load(f)
                if CONF:
                    CONFFILE = fname
                    log.info("Using %s as configuration file" % fname)
                    break

    if not CONF:
        if CONF is None:
            log.error("Configuration file empty.")
        else:
            log.error("No configuration file found.")
        sys.exit(1)

    run(CONF)
    sys.exit(0)
