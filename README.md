gitdeploy
=========

## Presentation

```gitdeploy``` is a small HTTP server written in Python. Listening
to a given port, ```gitdeploy``` can receive requests from popular
git repositories such as [GitHub] [github], [GitLab] [gitlab] or
[Bitbucket] [bitbucket] and automatically update local git
repositories. It can further follow a set of user-defined rules
to deploy the given repositories.

```gitdeploy``` aims to be usable by the different users of the
system it is running on, and not only by the administrators or
that system. Each user can thus define its set of rules that
will be analyzed by ```gitdeploy``` and ran as this user,
preventing any unauthorized commands to run.

```gitdeploy``` is currently a work in progress. It can be used
with caution. More installation and usage information should be
added in the near future.


## Licence

Copyright (C) 2015       Raphaël Beamonte <<raphael.beamonte@gmail.com>>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  [See the
GNU General Public License for more details] [GPLv2].

## Issues
Please use the [GitHub integrated issue tracker] [issues] for
every problem you may encounter. Please **DO NOT** use my email
for issues or walkthrough.


[github]: https://github.com/
[gitlab]: https://gitlab.com/
[bitbucket]: https://bitbucket.org/
[GPLv2]: https://www.gnu.org/licenses/gpl-2.0.html
[issues]: https://github.com/XaF/gitdeploy/issues
