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
import hashlib
import hmac
import inspect
import json
import logging
import os
import os.path
import pwd
import re
import shlex
import signal
import subprocess
from ssl import wrap_socket as ssl_wrap_socket, PROTOCOL_SSLv23, SSLError
import sys
import urlparse
import yaml

CURRENT_DIR = os.path.realpath('.')
GNRL_LOG_FORMAT = ("%(asctime)s::%(name)s::"
                   "%(function)s::%(levelname)s::%(message)s")
USER_LOG_FORMAT = "%(asctime)s::%(name)s::%(levelname)s::%(message)s"
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

try:
    compare_digest = hmac.compare_digest
except:
    def compare_digest(x, y):
        if len(x) != len(y):
            return False
        result = 0
        for a, b in zip(bytearray(x), bytearray(y)):
            result |= a ^ b
        return result == 0


class SecureHash:
    AVAILABLE_HASH = {
        'md5':      hashlib.md5,
        'sha1':     hashlib.sha1,
        'sha224':   hashlib.sha224,
        'sha256':   hashlib.sha256,
        'sha384':   hashlib.sha384,
        'sha512':   hashlib.sha512,
    }

    @classmethod
    def hmac_hash(cls, hashtype, key, content):
        if hashtype not in SecureHash.AVAILABLE_HASH:
            return None

        hashtype = SecureHash.AVAILABLE_HASH[hashtype]
        return hmac.new(
            key=key,
            msg=content,
            digestmod=hashtype).hexdigest()

    def __init__(self, hashtype, secret, content):
        self.__hashtype = hashtype
        self.__secret = secret
        self.__content = content

    def trykey(self, key):
        rhash = SecureHash.hmac_hash(
            self.__hashtype,
            key,
            self.__content)

        ret = compare_digest(
            self.__secret,
            rhash
        )

        return ret


class ContextFilter(logging.Filter):
    """
    This is a filter which injects contextual information into the log.
    """
    def filter(self, record):
        callingfunction = []

        # Get the frame of the calling function
        callerframe = inspect.currentframe().f_back
        while callerframe.f_code.co_name != '_log':
            callerframe = callerframe.f_back
        callerframe = callerframe.f_back.f_back

        # If the calling function is __user_log, we need
        # to go one step further!
        if callerframe.f_code.co_name == '__user_log':
            callerframe = callerframe.f_back

        # Get the module name if any
        module = inspect.getmodule(callerframe)
        if module:
            callingfunction.append(module.__name__)

        # Get the class name if any
        if 'self' in callerframe.f_locals:
            callingfunction.append(
                callerframe.f_locals['self'].__class__.__name__)

        # Finally get the function name
        codename = callerframe.f_code.co_name
        if codename != '<module>':
            callingfunction.append(codename)

        record.function = '.'.join(callingfunction)
        return True


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
        handler.setFormatter(logging.Formatter(USER_LOG_FORMAT))
        log.addHandler(handler)

        # Prepare the server log handler
        log.addHandler(self.server.handler)

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

        self.server.log.debug(
            "Repositories in the request: %s",
            [{k: v for k, v in r.items() if k != 'request'}
             for r in repositories])

        if repositories:
            work = self.__search_hooks(repositories)

            if work:
                self.server.log.debug("Rules found: %s", work)

                for repo, users in work.items():
                    repo = repositories[repo]

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

    def __filter_event_type(self, event_type):
        replace = {
            # Convert GitLab header event to a more
            # straightforward event slug
            'Push Hook':            'push',
            'Tag Push Hook':        'tag_push',
            'Issue Hook':           'issue',
            'Merge Request Hook':   'merge_request',
        }

        if event_type in replace:
            event_type = replace[event_type]

        return event_type

    def __parse_request(self):
        # Verify that the request was of the right type
        ctype = self.headers.gettype()
        if ctype not in [
                'application/json',
                'application/x-www-form-urlencoded']:
            self.server.log.debug(
                'Request \'Content-Type\' is invalid: %s' % ctype)
            return False

        self.server.log.debug(
            "Received request headers: %s",
            self.headers.items())

        # Search for a key in the query string
        key = urlparse.parse_qs(
            urlparse.urlparse(self.path).query).get('key', None)

        if key is not None:
            key = key[-1]
            self.server.log.debug("Found key: %s", key)

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

        # Search for a secret token in the header
        secret = None
        for header, value in self.headers.items():
            if re.match('^X-([^ ]+)-Signature$', header, re.IGNORECASE):
                secret = re.match(
                    '^(?:(?P<method>[a-z0-9+]+)=)?(?P<hash>.+)$',
                    value).groupdict()
                break

        if secret is not None:
            self.server.log.debug("Found secret: %s", secret)

            if not secret['method']:
                secret['method'] = 'sha1'
            secret = SecureHash(secret['method'], secret['hash'], rq_content)

        repos = []

        def get_repos(entry):
            if event_type is None and 'object_kind' in entry:
                l_event_type = self.__filter_event_type(entry['object_kind'])
            else:
                l_event_type = event_type

            self.server.log.debug("Event type: %s", l_event_type)

            if 'repository' in entry:
                # Get the URL list
                ulist = []
                # This part is kind of only for bitbucket.org...
                if ('canon_url' in entry
                        and 'absolute_url' in entry['repository']
                        and 'scm' in entry['repository']
                        and entry['repository']['scm'] == 'git'):
                    p = re.compile(ur'^[^:]+://(?P<host>[^ ]+)$')
                    m = p.search(entry['canon_url'])

                    if m:
                        hosturl = m.group('host')
                        relurl = entry['repository']['absolute_url'][0:-1]

                        ulist.append('git@' +
                                     hosturl +
                                     relurl +
                                     '.git')

                        if 'owner' in entry['repository']:
                            ulist.append("https://" +
                                         entry['repository']['owner'] +
                                         "@" +
                                         hosturl +
                                         relurl +
                                         ".git")

                # Works for both github and gitlab using their
                # different key names for the different cloning
                # urls
                if not ulist:
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
                ref = None
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
                            ref = (None, entry['ref'])

                # Get the commit
                commit = None
                if 'after' in entry:
                    commit = entry['after']

                # Almost only for bitbucket again, as refs and
                # last commit are not clear at all for it!
                if (not ref or not commit) and 'commits' in entry:
                    if isinstance(entry['commits'], list):
                        c = entry['commits'][-1]
                    else:
                        c = entry['commits']

                    if not ref and 'branch' in c:
                        if c['branch'] is None:
                            ref = ('tag', None)
                        else:
                            ref = ('branch', c['branch'])

                    if commit is None and 'raw_node' in c:
                        commit = c['raw_node']

                # Finally, add to the repos list
                if ulist:
                    data = {
                        'urls': ulist,
                        'ref': ref,
                        'commit': commit,
                        'event': l_event_type,
                        'secret': secret,
                        'key': key,
                        'request': entry,
                    }
                    repos.append(data)

        # Search for the type of event we received, first in the
        # header, then in the body if we didn't find it (will be
        # done in get_repos())
        event_type = None
        for header, value in self.headers.items():
            if re.search('^X-([^ ]+)-Event$', header, re.IGNORECASE):
                event_type = self.__filter_event_type(value)
                break

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
    def __check_only_except(self, search, hierarchy):
        ret = True

        if (isinstance(list, hierarchy)
                or isinstance(tuple, hierarchy)):
            hierarchy = {'only': list(hierarchy)}

        if isinstance(dict, hierarchy):
            if 'only' in hierarchy:
                if search not in hierarchy['only']:
                    ret = False
            elif 'except' in hierarchy:
                if search in hierarchy['except']:
                    ret = False
        elif search == str(hierarchy):
            ret = True

        return ret

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
                self.server.log.debug(
                    "Found config file for user %s (%s, %s)" % (
                        u.pw_name,
                        u.pw_uid,
                        u.pw_gid,
                    ))

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
                                    "Missing mandatory argument "
                                    "'%s' in rule: %s",
                                    arg,
                                    yaml.dump(rule))
                                continue

                        for repo in repositories:
                            if rule['url'] not in repo['urls']:
                                self.server.log.debug(
                                    "Rule out because url "
                                    "is not matching (%s not in %s)" % (
                                        rule['url'],
                                        repo['urls'],
                                    ))
                                continue

                            if ('event' in rule
                                    and not self.__check_only_except(
                                        'event', rule['event'])):
                                self.server.log.debug(
                                    "Rule out because event "
                                    "is not aimed (%s)" % (
                                        rule['event'],
                                    ))
                                continue

                            rtype, rname = repo['ref']
                            if (rtype in rule
                                    and not self.__check_only_except(
                                        rname, rule[rtype])):
                                self.server.log.debug(
                                    "Rule out because %s "
                                    "is not aimed (%s)" % (
                                        rtype,
                                        rname,
                                    ))
                                continue

                            if ((repo['key'] is None
                                 and 'key' in rule and rule['key'] is not None)
                                or (repo['key'] is not None and (
                                    'key' not in rule
                                    or str(rule['key']) != repo['key']))):
                                self.server.log.debug(
                                    "Rule out because key "
                                    "is not matching (%s != %s)" % (
                                        rule['key'],
                                        repo['key'],
                                    ))
                                continue

                            if ((repo['secret'] is None
                                 and 'secret' in rule
                                 and rule['secret'] is not None)
                                or (repo['secret'] is not None and (
                                    'secret' not in rule
                                    or not repo['secret'].trykey(
                                        rule['secret'])))):
                                self.server.log.debug(
                                    "Rule out because secret key "
                                    "is not matching (%s)" % (
                                        rule['secret'],
                                    ))
                                continue

                            i = repositories.index(repo)
                            if i not in hooks:
                                hooks[i] = {u.pw_name: [rule, ]}
                            else:
                                hooks[i][u.pw_name].append(rule)

            # Get back as us
            setenv()

        return hooks

    def __callstack(self, user, commands, env=None, returns=False):
        if isinstance(commands, str):
            result = self.__callstack(user, [commands, ], env, returns)
            if returns and not isinstance(result, tuple):
                return result[0]
            else:
                return result

        if returns:
            results = []

        call_env = {
            'HOME': user.pw_dir,
            'UID': str(user.pw_uid),
            'GID': str(user.pw_gid),
            'USER': user.pw_name,
            'PWD': os.getcwd(),
        }
        if isinstance(env, dict):
            call_env.update(env)

        self.server.log.debug("Environment: %s", call_env)

        for command in commands:
            args = shlex.split(command)

            run = subprocess.Popen(
                args,
                env=call_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            out = run.communicate()[0].rstrip()

            self.server.log.debug("Command: %s; Output:\n%s",
                                  command,
                                  out)

            if run.returncode != 0:
                self.__user_log(
                    user,
                    logging.ERROR,
                    "Error (%d) while running command: %s\n%s",
                    run.returncode,
                    command,
                    out)
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

    def __sort_branches(self, bname):
        """
        Allow to return a function to sort two
        branches following this order:
        - a branch with the same name as the given branch name
          will be before another
        - a branch which is not behind nor ahead will be before
          one which is
        - a branch which is behind will be before one which is
          ahead
        - a branch which has less distance from the remote will
          be before one that has more distance from it
        """
        def f(x, y):
            x = x.groupdict()
            y = y.groupdict()

            ret = 0
            if x['branch'] == bname and y['branch'] != bname:
                ret = -1
            elif y['branch'] == bname and x['branch'] != bname:
                ret = 1
            elif (x['ahead'] and y['ahead']
                  and x['behind'] and y['behind']):
                ret = cmp(int(x['dista']) + int(x['distb']),
                          int(y['dista']) + int(y['distb']))
            elif (x['ahead'] and y['ahead']
                  and not (x['behind'] or y['behind'])):
                ret = cmp(int(x['dista']), int(y['dista']))
            elif (x['behind'] and y['behind']
                  and not (x['ahead'] or y['ahead'])):
                ret = cmp(int(x['distb']), int(y['distb']))
            elif (x['ahead'] is None
                  and x['behind'] is None):
                ret = -1
            elif (y['ahead'] is None
                  and y['behind'] is None):
                ret = 1
            elif x['ahead'] and not y['ahead']:
                ret = 1
            elif y['ahead'] and not x['ahead']:
                ret = -1
            elif x['behind'] and not y['behind']:
                ret = 1
            else:
                ret = -1

            return ret

        return f

    def __pull_git(self, user, repo, rule):
        # Move to path given in the rule
        os.chdir(rule['path'])

        # Get repo information
        urls = repo['urls']
        rtype, rname = repo['ref']
        commit = repo['commit']

        # Get remote repository name
        run = self.__callstack(user, "git remote -v", returns=True)
        if isinstance(run, tuple):
            return False

        p = re.compile(ur'^(?P<remote>[^\s]+)\s+(?P<url>' +
                       '|'.join([re.escape(url) for url in urls]) +
                       ur')\s+\(fetch\)$',
                       re.IGNORECASE | re.MULTILINE)
        m = p.search(run)
        if not m:
            # No remote is linked to the repo we are at: error!
            self.__user_log(
                user,
                logging.ERROR,
                "Repository '%s' not found at '%s'",
                rule['url'],
                rule['path'])

            return False

        # We got the remote name, we can thus use it to fetch
        # the last commits and tags from it
        remote = m.group('remote')
        self.server.log.debug(
            "Remote found: %s",
            remote)

        commands = [
            ("git fetch -fp %(r)s refs/heads/*:refs/remotes/%(r)s/*"
             % {'r': remote} + " +refs/tags/*:refs/tags/*"),
            "git update-index --refresh"
        ]

        if rtype == 'branch':
            # In case we're working on a branch, we also want to
            # be sure of the branch we have to update
            commands += [
                "git branch -r --contains %s" % commit,
                "git branch -lvv",
            ]
            run = self.__callstack(user, commands, returns=True)
            if isinstance(run, tuple):
                return False

            # We thus search for the remote branch that contains
            # our given commit, and that should have the name we
            # received in the request
            p = re.compile(
                ur'^\s+(?P<rbranch>(?P<remote>' +
                re.escape(remote) +
                ')/(?P<branch>' +
                re.escape(rname) +
                '))$',
                re.IGNORECASE | re.MULTILINE)
            m = p.search(run[-2])
            if not m:
                # No remote is linked to the repo we are at: error!
                self.__user_log(
                    user,
                    logging.ERROR,
                    "The remote branch '%s' with commit '%s' was not found",
                    '%s/%s' % (remote, rname),
                    commit)

                return False

            rbranch = m.group('rbranch')
            self.server.log.debug(
                "Remote branch found: %s",
                rbranch)

            # We then search for a local branch pointing towards that
            # remote branch. If we find more than one, we'll sort them
            # using the __sort_branches function. We also don't need
            # to checkout the branch if we're already on it.
            p = re.compile(
                '^(?P<selected>\*)?\s+(?P<branch>[^ ]+)\s+'
                '(?P<commit>[a-z0-9]*)\s+\[(?P<remote>' +
                re.escape(rbranch) +
                ')(?:\: (?P<ahead>ahead) (?P<dista>[0-9]+))?'
                '(?:(?:\:|,) (?P<behind>behind) (?P<distb>[0-9]+))?\]',
                re.IGNORECASE | re.MULTILINE)

            matches = [m for m in p.finditer(run[-1])]
            self.server.log.debug(
                "Matching local branches: %s",
                [m.groupdict() for m in matches])

            commands = []
            if not matches:
                commands.append("git checkout -b %s %s" % (rname, rbranch))
            else:
                matches.sort(self.__sort_branches(rname))
                m = matches[0]
                self.server.log.debug(
                    "Best matching local branch: %s",
                    m.groupdict())

                if m.group('selected') != '*':
                    commands.append("git checkout %s" % m.group('branch'))

            # We finally reset everything in the directory to be sure
            # We're at the same level as the git repository
            commands.append("git reset --hard %s" % rbranch)
            run = self.__callstack(user, commands, returns=True)
            if isinstance(run, tuple):
                return False

            # We verify that the commit we're at is the one we received as
            # parameter, or we'll need to checkout again
            m = re.search("HEAD is now at (?P<commit>[a-z0-9]+) ", run[-1])
            if not m:
                self.server.log.error(
                    "Unexpected error when verifying the commit after reset."
                    "Command was '%s'. The string we got is: %s",
                    commands[-1],
                    run[-1])
                return False

            if commit.startswith(m.group('commit')):
                return True

            # We only arrive here if the commit was different: we thus
            # need to checkout it using the commit ID.
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

    def __deploy_comands(self, period, rule, user, env):
        if 'deploy' in rule:
            if period in rule['deploy']:
                run = self.__callstack(
                    user,
                    rule['deploy'][period],
                    env=env)
                if not run:
                    return False
        return True

    def __deploy_worker(self, user, repo, rule):
        # Create a new environment variable to pass
        # the request to the commands as an environment
        # variable
        env = {'DEPLOY_REQUEST': json.dumps(repo['request'])}

        # Run deploy commands that the rule asks to run
        # 'before' pulling
        run = self.__deploy_commands(
            'before',
            rule,
            user,
            env
        )
        if not run:
            return False

        # Check if we need to run the pull workflow
        if 'pull' in rule:
            if isinstance(bool, rule['pull']):
                pull = rule['pull']
            else:
                pull = self.__check_only_except(repo['event'],
                                                rule['pull'])
        else:
            pull = (repo['event'] in ['push', 'create'])

        # Run pull workflow if needed
        if pull:
            run = self.__pull_git(user, repo, rule)
            if not run:
                return False

        # Run deploy commands that the rule asks to run
        # 'after' pulling
        run = self.__deploy_commands(
            'after',
            rule,
            user,
            env
        )
        if not run:
            return False

        return True


class GitDeployServer(HTTPServer):
    def __init__(self, server_address, config):
        HTTPServer.__init__(self, server_address, GitDeployHandler)

        # Save configuration for global use
        self.config = config

        # Get local logger
        self.log = logging.getLogger("HTTPServer")

        # Set the log in the right place
        if 'files' in self.config and 'log' in self.config['files']:
            logfile = self.config['files']['log']
        else:
            logfile = os.path.join(CURRENT_DIR, 'gitdeploy.log')

        self.handler = logging.FileHandler(logfile, mode='a+')
        self.handler.setFormatter(logging.Formatter(GNRL_LOG_FORMAT))
        self.handler.addFilter(ContextFilter())
        self.log.addHandler(self.handler)

        self.log.info('GitDeployServer started on port %d' % server_address[1])

        # Check if ssl is required
        if 'ssl' in self.config['server'] and self.config['server']['ssl']:
            if ('files' not in self.config
                    or 'sslkey' not in self.config['files']
                    or 'sslcrt' not in self.config['files']):
                self.log.error("Missing parameters for SSL server "
                               "(have you set up 'sslkey' and 'sslcrt'?)")
                sys.exit(1)

            self.orig_socket = self.socket
            try:
                self.socket = ssl_wrap_socket(
                    self.orig_socket,
                    keyfile=self.config['files']['sslkey'],
                    certfile=self.config['files']['sslcrt'],
                    server_side=True,
                    ssl_version=PROTOCOL_SSLv23,
                    do_handshake_on_connect=True)
            except SSLError as e:
                self.log.error("Error when setting up SSL server",
                               exc_info=sys.exc_info())

    def signal_handler_exit(self, signum, frame):
        self.log.info(
            'Shutting down after receiving signal %s',
            SIGNALS_TO_NAMES_DICT.get(
                signum,
                "%d (unnamed)" % signum)
        )

        from threading import Thread
        shutdown_thread = Thread(target=self.shutdown)
        shutdown_thread.daemon = True
        shutdown_thread.start()


# Dictionnary allowing to search a signal name from its number
SIGNALS_TO_NAMES_DICT = dict(
    (getattr(signal, n), n)
    for n in dir(signal)
    if n.startswith('SIG') and '_' not in n)


def run(config):
    # Prepare the server according to the configuration
    server_address = ('', config['server']['port'])
    httpd = GitDeployServer(server_address, config)

    # Handle signals to exit gracefully
    signal.signal(signal.SIGINT, httpd.signal_handler_exit)
    signal.signal(signal.SIGTERM, httpd.signal_handler_exit)
    signal.signal(signal.SIGALRM, httpd.signal_handler_exit)

    # Start running the server
    httpd.serve_forever()

if __name__ == "__main__":
    logging.basicConfig(
        format=GNRL_LOG_FORMAT,
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
                    print("Using %s as configuration file" % fname)
                    break

    if not CONF:
        if CONF is None:
            print("Configuration file empty.")
        else:
            print("No configuration file found.")
        sys.exit(1)

    run(CONF)
    sys.exit(0)
