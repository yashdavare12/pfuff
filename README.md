# pfuff

## About
`pfuff` is a Python based knockoff of the original DirBuster.

`pfuff` is a multi threaded Python application designed to brute force directories
 and files names on web/application servers. Often is the case now of what looks
 like a web server in a state of default installation is actually not,
 and has pages and applications hidden within.



## Usage

`BirDuster` has the following flags and options (which you can see with the `-h`
flag):

* `-h`/`--help`: Show help and exit.
* `-v`,`-vv`,`-vvv`/`--verbosity`: Verbosity level.
* `-p`/`--port`: Port to use while dirbusting. Default 80/443.
* `-P`/`--pfile`: If you want to test several ports just write them to a file with newlines.
* `-t`/`--threads`: Amount of concurrent threads. Default is 15.
* `-o`/`--output`: Output CSV of responses. Default is `domain_output.csv`.
* `-l`/`--dlist`: Directory list file. Default is `dir_list.txt`.
* `-w`/`--writereponse`: Will write HTTP/S responses to files. Default is False.
* `-u`/`--useragent`: User-Agent to use. Default is random user-agent.
* `--timeout`: Change default socket timeout. Default is 3 seconds.

```bash
usage: dirbus.py [-h] [-v] [-p PORT] [-P PFILE] [-t THREADS] [-o OUTPUT]
                 [-l DLIST] [-w] [-i] [-u USERAGENT] [--ssl]
                 [--timeout TIMEOUT]
                 domain

positional arguments:
  domain                domain or host to buster
```
