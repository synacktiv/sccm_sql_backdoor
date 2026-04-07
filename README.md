# sccm_sql_backdoor

## Installation
You can install by cloning the repository and installing the dependencies.

```sh
$ git clone --recurse-submodules https://github.com/synacktiv/sccm_sql_backdoor
$ cd sccm_sql_backdoor
$ python3 -m venv .venv && source .venv/bin/activate
$ python3 -m pip install -r requirements.txt

```

## Usage

```sh
$ python3 sccm_sql_backdoor.py -h 
usage: sccm_sql_backdoor.py [-h] -t TARGET [-debug] {CVE-2024-43468,CVE-2025-59213,revert} ...

SCCM SQL Backdoor

positional arguments:
  {CVE-2024-43468,CVE-2025-59213,revert}
    CVE-2024-43468      Use CVE-2024-43468 to inject the SPO backdoor
    CVE-2025-59213      Use CVE-2025-59213 to inject the SPO backdoor
    revert              Revert the changes to the original SPO

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target (http://sccm-mp.local/)
  -debug                Turn DEBUG output ON
```



### CVE-2025-59213
```sh
$ python3 sccm_sql_backdoor.py CVE-2025-59213 -h                
usage: sccm_sql_backdoor.py CVE-2025-59213 [-h] [-a] [-m MARKER] [-k KEY] [-c CERT] [-sk SIGKEY] [-v] -cn CLIENT_NAME [-rs REGISTRATION_SLEEP]

options:
  -h, --help            show this help message and exit
  -a, --altauth         Use the MP's alternate authentication endpoint (Default: False)
  -m, --marker MARKER   Override marker to trigger the backdoor (Default: ABC)
  -k, --key KEY         Private key file for mTLS
  -c, --cert CERT       Certificate file
  -sk, --sigkey SIGKEY  SMS signature key
  -v, --verbose         Verbose output, print requests
  -cn, --client-name CLIENT_NAME
                        Name of the client that will be created in SCCM
  -rs, --registration-sleep REGISTRATION_SLEEP
                        The amount of time, in seconds, that should be waited after registrating a new device (2 seconds by default)
```

### CVE-2024-43468

```sh
$ python3 sccm_sql_backdoor.py CVE-2024-43468 -h                  
usage: sccm_sql_backdoor.py CVE-2024-43468 [-h] [-a] [-m MARKER] [-k KEY] [-c CERT]

options:
  -h, --help           show this help message and exit
  -a, --altauth        Use the MP's alternate authentication endpoint (Default: False)
  -m, --marker MARKER  Override marker to trigger the backdoor (Default: ABC)
  -k, --key KEY        Private key file for mTLS
  -c, --cert CERT      Certificate file
```

### revert

```sh
$ python3 sccm_sql_backdoor.py revert -h         
usage: sccm_sql_backdoor.py revert [-h] [-m MARKER]

options:
  -h, --help           show this help message and exit
  -m, --marker MARKER  Override marker to trigger the backdoor (Default: ABC)
```