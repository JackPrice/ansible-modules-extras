#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015 Jack Price <jackprice@outlook.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: ulimit
short_description: Manage Linux ulimits
description:
 - Manage Linux ulimits.
author: Jack Price <jackprice@outlook.com>
options:
  domain:
    description:
     - The domain to apply this limit to
     - A username applies this limit to a specific user
     - The wildcard * can be used for the default entry
     - A group can be specified with the @group syntax
    required: false
  type:
    description:
    - C(soft) enforces a soft limit
    - C(hard) enforces a hard limit
    required: true
    choices: ['soft', 'hard', '-']
  item:
    description:
     - C(core) limits the core file size (KB)
     - C(data) max data size (KB)
     - C(fsize) maximum filesize (KB)
     - C(memlock) max locked-in-memory address space (KB)
     - C(nofile) max number of open file descriptors
     - C(rss) max resident set size (KB)
     - C(stack) max stack size (KB)
     - C(cpu) max CPU time (MIN)
     - C(nproc) max number of processes
     - C(as) address space limit (KB)
     - C(maxlogins) max number of logins for this user
     - C(maxsyslogins) max number of logins on the system
     - C(priority) the priority to run user process with
     - C(locks) max number of file locks the user can hold
     - C(sigpending) max number of pending signals
     - C(msgqueue) max memory used by POSIX message queues (bytes)
     - C(nice) max nice priority allowed to raise to values
     - C(rtprio) max realtime priority
    required: true
  value:
    description:
     - The value to set the limit to
    required: false
  state:
    description:
     - C(present) ensures this rule is set
     - C(absent) ensures this rule is not set
    required: false
    choices: ['present', 'absent']
  user:
    description:
     - If the domain is omitted, this may be used to specify the user to apply
       this limit to
    required: false
  group:
    description:
     - If the domain is omitted, this may be used to specify the group to apply
       this limit to
    required: false
  path:
    description:
     - If specified, this contains the path to the limits.conf file, otherwise
       this defaults to /etc/security/limits.conf
    required: false
'''

EXAMPLES='''
# Set the maximum number of open file descriptors to 1024 for all users
ulimit: domain=* type=hard item=nofile value=1024

# Set the maximum number of logins for the user john to 4
ulimit: domain=john item=maxlogins value=4

# You can also use the user= or group= syntax instead of domains. Note that 
# these are mutually exclusive
ulimit: user=alice item=nproc value=9

# You can also use this module to remove limits
# The following command will remove the hard limit on the maximum number of
# processes the ftp group can run
ulimit: group=ftp type=hard item=nproc state=absent

# On a nonstandard system, you can specify the path to the limits.conf file
ulimit: domain=* type=hard item=rss value=10000 path=/etc/security/limits.conf
'''

# ==============================================================================

import re

# Create a regular expression for parsing entries in a limits.conf file
REGEX=re.compile('^\s*(?P<domain>\*|((%|@)?)\w+)\s+(?P<type>soft|hard|-)\s+(?P<item>core|data|fsize|memlock|nofile|rss|stack|cpu|nproc|as|maxlogins|maxsyslogins|priority|locks|sigpending|msgqueue|nice|rtprio)\s+(?P<value>\d+)')

# This function takes a dictionary definition of a limit, and returns the string
# that corresponds to it
# Note that no newlines are added, so these must be added accordingly if 
# necessary
def limit_to_str(limit):
    return limit['domain'] + ' ' \
        + limit['type'] + ' ' \
        + limit['item'] + ' ' \
        + str(limit['value']) \
        + ' # added by Ansible'

# Build a regular expression that matches only the given limit
# Note that this ignores the value of the limit, and will match only on the 
# other parameters
# It also matches the entire line greedily!
def limit_to_regex(limit):
    # Do some regex escaping first
    domain = re.escape(limit['domain'])
    type   = re.escape(limit['type'])
    item   = re.escape(limit['item'])

    return re.compile('^\s*' + domain + '\s+' + type + '\s+' + item + '\s+[0-9]+.*$', re.MULTILINE)

# Parse the given limits.conf file, returning a list of all the rules found 
# therein
# Returns a tuple, with the first element being a list if successful, and the
# second being an error message if not
def get_current_limits(path):
    try:
        file = open(path, 'r')
    except IOError as e:
        return (None, 'Could not open limits.conf')

    # Read the file line-by-line, matching against our regular expression as we
    # go, and parsing appropriately
    limits = []
    lines = file.read().splitlines()

    for line in lines:
        match = REGEX.match(line)
        if match:
            limits.append(dict(
                domain = match.group('domain'),
                type   = match.group('type'),
                item   = match.group('item'),
                value  = int(match.group('value'))
            ))

    return (limits, None)

# Given a list of limits, and a limit, return whether the limit exists in the
# list, and if its value is equal
# Returns a tuple, with the first value being true if the limit exists, and the
# second if its value is equal
def contains_limit(limits, limit):
    for it in limits:
        if it['domain'] == limit['domain'] and it['type'] == limit['type'] and it['item'] == limit['item']:
            if it['value'] == limit['value']:
                return (True, True)
            return (True, False)
    return (False, False)

# Add a limit to limits.conf file
def add_limit(path, limit):
    with open(path, 'a') as file:
        file.write("\n" + limit_to_str(limit))

# Update a limit in the limits.conf file
def update_limit(path, limit):
    # First read the file into memory
    # This shouldn't be a problem as the limits.conf file will never be huge
    with open(path, 'r') as file:
        contents = file.read()

    # Now do a regular expression replace on the limit
    string   = limit_to_str(limit)
    regex    = limit_to_regex(limit)
    contents = re.sub(regex, string, contents, 1)

    with open(path, 'w') as file:
        file.write(contents)

# Remove a limit from the limits.conf file
def remove_limit(path, limit):
    # First read the file line-by-line into memory
    # This shouldn't be a problem as the limits.conf file will never be huge
    with open(path, 'r') as file:
        contents = file.readlines()

    regex = limit_to_regex(limit)

    # Now write back, removing the offending lines
    with open(path, 'w') as file:
        for line in contents:
            if not regex.match(line):
                file.write(line)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            domain = dict(default=None,      required=False),
            type   = dict(default='-',       choices=['soft', 'hard', '-']),
            item   = dict(required=True),
            value  = dict(default=None,      required=False, type='int'),
            state  = dict(default='present', required=False),
            user   = dict(default=None,      required=False),
            group  = dict(default=None,      required=False),
            path   = dict(required=False,    default='/etc/security/limits.conf')
        ),
        supports_check_mode = False,
        mutually_exclusive = [['domain', 'user', 'group']]
    )

    params = module.params

    # Ensure that one of domain, user or group are supplied
    domains = dict((key, params[key]) for key in ['domain', 'user', 'group'] if params[key])

    if len(domains) == 0:
        module.fail_json(msg='One of domain, user or group must be specified')
    if len(domains) > 1:
        module.fail_json(msg='Only one of domain, user and group may be specified')

    # Ensure that a value is specified if the state is present
    if params['state'] == 'present' and not isinstance(params['value'], int):
        module.fail_json(msg='A value must be specified')

    # Construct our limit specification from all the given parameters
    # First construct the domain if necessary
    domain = str(params['domain'])

    if params['user']:
        domain = str(params['user'])
    if params['group']:
        domain = '@' + str(params['group'])

    limit = dict(
        domain = domain,
        type   = params['type'],
        item   = params['item'],
        value  = params['value']
    )

    # Load existing limits
    (limits, error) = get_current_limits(path=params['path'])
    if error:
        module.fail_json(msg=error)

    # Check whether this limit exists, and if its value is equal
    (exists, exact) = contains_limit(limits=limits, limit=limit)

    # Figure out what to do
    if params['state'] == 'present':
        if exists and exact:
            module.exit_json(changed=False)
        if exists and not exact:
            update_limit(path=params['path'], limit=limit)
        if not exists and not exact:
            add_limit(path=params['path'], limit=limit)
    else:
        if exists:
            remove_limit(path=params['path'], limit=limit)
        else:
            module.exit_json(changed=False)

    module.exit_json(changed=True, limit=limit)

# import module snippets
from ansible.module_utils.basic import *

main()
