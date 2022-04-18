# pfuff

## About
`pfuff` is a Python based knockoff of the original DirBuster.

`pfuff` is a multi threaded Python application designed to brute force directories
 and files names on web/application servers. Often is the case now of what looks
 like a web server in a state of default installation is actually not,
 and has pages and applications hidden within.



## Usage

`pfuff` has the following flags and options (which you can see with the `-h`
flag):

* `-h`/`--help`: Show help and exit.
* `-t`/`--threads`: Amount of concurrent threads. Default is 15.
* `-l`/`--dlist`: Directory list file. Default is `dir_list.txt`.
* `-w`/`--writereponse`: Will write HTTP/S responses to files. Default is False.
* `-mr`/`--matchs`: Regex match in reponse.
* `-ms`/`--matchstatus`: Match status and allow only that ones.
* `-fs`/`--filterstatus`: Filter status by blocking that ones.
* `-d`/`--data`: POST data to be send in request.
* `-H`/`--headers`: Headers to be send in request.
* `-X`/`--X`: Specify which request to use POST
* `-fred`/`--followredirect`: Set this to `True` to follow ridirect from the response
* `--ssl`: Use SSL or not. `-i` flag will automatically turn on SSL.
* `-i`/`--ignorecertificate`: Ignore SSL certificate errors. Default is TRUE.
* `-ex`/`--fileext`: file extensions to match `eg: php,html,js` (should be seperated be ,)


```bash
usage: pfuff.py [-h] [-v] [-t THREADS] [-t THREADS]
                 [-l DLIST] [-w] [-i] 
                 domain

positional arguments:
  domain                domain or host to buster
```
```bash
Example:
GET request:
     python .\pfuff.py -l .\dir_list2.txt -t 10 http://192.168.43.38/mutillidae/index.php?page=fuzz -mr "logged"        
POST request:
     python .\pfuff.py -l .\dir_list2.txt -t 40 -X POST http://192.168.43.38/mutillidae/index.php?page=login.php -d "{'username':'sdsd','password':'fuzz','login-php-submit-button':'Login'}" -mr "logged"
GET Headers:
     python .\pfuff.py -l .\dir_list2.txt -t 40 http://192.168.43.38/mutillidae/index.php?page=login.php -H "{'username':'sdsd','password':'fuzz','login-php-submit-button':'Login'}" -ms 200 -fs 401 -mr "Logged"
POST Header:
     python .\pfuff.py -l .\dir_list2.txt -t 40 -X POST http://192.168.43.38/mutillidae/index.php?page=login.php -H "{'username':'sdsd','password':'fuzz','login-php-submit-button':'Login'}" -ms 200 -fs 401 -mr "Logged"
```
