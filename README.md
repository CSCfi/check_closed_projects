# check_closed_projects

Compare closed projects in LDAP with a list of projects or with closed projects in OpenStack.

## Requirements

See requirements.txt

## Installation

### Linux

```bash
sudo python3 setup.py install
```

### Windows (from PowerShell)

```powershell
& $(where.exe python).split()[0] setup.py install
```

## Usage

```bash
Usage: check_closed_projects.py [OPTIONS]

Options:
  -d, --debug-level [CRITICAL|ERROR|WARNING|INFO|DEBUG|NOTSET]
                                  Set the debug level for the standard output.
  -l, --log-file TEXT             File to store all debug messages.
  -s, --os-source-file TEXT       Source file from OpenStack with credentials.
  -h, --ldap-host TEXT            LDAP server hostname or IP  [required].
  -p, --ldap-port INTEGER         LDAP server port.
  -u, --ldap-user TEXT            LDAP user.
  -P, --ldap-password TEXT        Warning! Avoid passing the password in the
                                  command line and use a configuration file
                                  for this LDAP user password.
  -d, --ldap-base-dn TEXT         LDAP base DN  [required].
  -f, --ldap-search-filter TEXT   LDAP search filter to use.
  -a, --ldap-state-attribute TEXT
                                  LDAP attribute that indicate the closed
                                  state.
  -o, --projects-file TEXT        File with a list of project names as shown
                                  in LDAP.
  --config FILE                   Read configuration from FILE.
  --help                          Show this message and exit.
```
