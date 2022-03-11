from tokenize import Token
from numpy import argsort
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time
import argparse
import json


def parse_arguemnts():
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--data", help="POST data")
	args = parser.parse_args();return args

args = parse_arguemnts()
print(args.data)
url_list = [
    "https://httpbin.org/post"
    
]
tokens = "{'foo': 'bar'}"

def download_file(url):
    html = requests.post(url,stream=True, data=Token)
    print(type(html.request.body))
    return (json.load((html.content).decode('ascii')))

start = time()

processes = []
with ThreadPoolExecutor(max_workers=200) as executor:
    for url in url_list:
        processes.append(executor.submit(download_file, url))

for task in as_completed(processes):
    print(task.result())


print(f'Time taken: {time() - start}')