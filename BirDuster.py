#!/usr/bin/env python3

import os
import csv
import sys
import base64
import socket
import pycurl
from urllib.parse import urlencode
import random
import argparse
import colorama
import requests
import asyncio
import re
import json
from requests.sessions import Session
import aiohttp
import threading
import concurrent
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time
import ast

import urllib3
urllib3.disable_warnings()

from builtins import input # compatibility, python2/3
from datetime import datetime
from colorama import Fore, Style
from user_agent import generate_user_agent, generate_navigator
from threading import Thread,local


# Default configurations
MAX_WORKERS = 13
DEF_TIMEOUT = 3
DEFAULT_DIR_LIST_FILE = 'dir_list.txt'
#sys.stdout.write(DEFAULT_DIR_LIST_FILE)
FOUND = []
thread_local = local()


def _print_banner():
	banner = Fore.RED + "\n######           ######                                    \n" + Style.RESET_ALL
	banner += Fore.RED + "#     # # #####  #     # #    #  ####  ##### ###### #####  \n" + Style.RESET_ALL
	banner += Fore.RED + "#     # # #    # #     # #    # #        #   #      #    # \n" + Style.RESET_ALL
	banner += Fore.RED + "######  # #    # #     # #    #  ####    #   #####  #    # \n" + Style.RESET_ALL
	banner += Fore.RED + "#     # # #####  #     # #    #      #   #   #      #####  \n" + Style.RESET_ALL
	banner += Fore.RED + "#     # # #   #  #     # #    # #    #   #   #      #   #  \n" + Style.RESET_ALL
	banner += Fore.RED + "######  # #    # ######   ####   ####    #   ###### #    # \n" + Style.RESET_ALL
	banner += Fore.RED + "                                                           \n" + Style.RESET_ALL
	banner += Fore.BLUE + "\tA DirBuster KnockOff for Python2+3\n" + Style.RESET_ALL
	banner += Fore.GREEN + "\tVersion 1.0.\n" + Style.RESET_ALL
	banner += Fore.WHITE + "\tHosted on https://www.github.com/ytisf/BitDuster.\n\n" + Style.RESET_ALL
	print(banner)

def _print_err(message):
	sys.stderr.write(Fore.RED + "[X]"+Style.RESET_ALL+"\t%s\n" % message)

def _print_succ(message):
	sys.stdout.write(Fore.GREEN + "[+]"+Style.RESET_ALL+"\t%s\n" % message)

def _print_info(message):
	sys.stdout.write(Fore.BLUE + "[+]" + Style.RESET_ALL + "\t%s\n" % message)

def get_session() -> Session:
    if not hasattr(thread_local,'session'):
        thread_local.session = requests.Session()
    return thread_local.session

def _fetch_url(url, headers, ssl_verify=True, write_response=False, timeout=DEF_TIMEOUT):
	global FOUND
	flag1=False
	flag2=False
	flag3=False
	args = parse_arguemnts()
	domain = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
	
	socket.setdefaulttimeout = timeout
	now = datetime.now()
	dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
	try:
		site_request = requests.get(url, headers=headers, verify=ssl_verify)
		#print(site_request.content)
		FOUND.append([dt_string, url, site_request.status_code, len(site_request.content)])
		try:
			if args.matchs and (args.matchstatus or args.filterstatus):
					#print('flag1 set')
				flag1=True
		except:
			if args.matchstatus and args.filterstatus:
					#print('flag2 set')
				flag2=True
		try:
			if args.matchstatus and flag1==False and flag2==False:
					#print('flag3 set')
					flag3=True
		except:
				pass
		try:
				if args.filterstatus and flag1==False and flag2==False:
					#print('flag3 set')
					flag3=True
		except:
				pass
		if flag1:         #all three present
        #if int(args.filterstatus)==int(site_request.status_code): print('hiii')
			flagin1=False
			flagin2=False
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					regexprint(args.matchs,site_request,url)
					flagin1=True
				
			except:
				pass
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and flagin1==False:
					regexprint(args.matchs,site_request,url)
					flagin2=True
			except:
				pass
			try:
				if int(site_request.status_code)==int(args.matchstatus) and flagin1==False and flagin2==False:
					regexprint(args.matchs,site_request,url)
			except:
				pass
		if flag2:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					print(f'Read {len(site_request.content)} and {url}')
		if flag3:
				try:
					if int(site_request.status_code)!=int(args.filterstatus):
						print(f'Read {len(site_request.content)} and {url}')
				except:
					if int(site_request.status_code)==int(args.matchstatus):
						print(f'Read {len(site_request.content)} and {url}')
		try:
				#print( str(flag1) +str(flag2) +str(flag3))
			if flag1==False and flag2==False and flag3==False:
					if args.matchs:
						regexprint(args.matchs,site_request,url)
		except:
				pass
		return 1

		
		#print(url+" ==> "+site_request.status_code, flush=True)
		
			#print(url+" ==> "+site_request.status_code, flush=True)
			
	except Exception as e:
		FOUND.append([dt_string, url, "Error: %s" % e, 0])
	
	fulldesc=str(url+" ==> "+str(site_request.status_code)+"\n")
	sys.stdout.write(fulldesc)
	sys.stdout.flush()

def _fetch_post(url, ssl_verify=False, write_response=False,stream=True, timeout=DEF_TIMEOUT):
	global FOUND
	#domain = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
	socket.setdefaulttimeout = timeout
	now = datetime.now()
	dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
	try:
		print(url)
		
		site_request = requests.post(url,data={'Token': '326729'})
		#site_request = await session.post(url,data={'y':'value'}, headers=headers, verify=False)
		#site_request =requests.api.request('post', url, data={'bar':'baz'}, json=None, verify=False)
		fulldesc= str(url+" ==> \n"+site_request.body+" = "+site_request.status_code)
		return fulldesc
		sys.stdout.write('ss')
		print('hii')
		""" FOUND.append([dt_string, url, site_request.status_code, len(site_request.content)])
			if write_response:
				file_name_string = "".join(x for x in url if x.isalnum())
				f = open(os.path.join(domain,file_name_string), 'wb')
				f.write(site_request.content)
				f.close()
				print(url+" ==> \n"+site_request.body+" = "+site_request.status_code, flush=True)	 """	
	except Exception as e:
		FOUND.append([dt_string, url, "Error: %s" % e, 0])
	
	sys.stdout.write('jiii')


	
	
	

def parse_arguemnts():
	parser = argparse.ArgumentParser()
	parser.add_argument("domain", help="domain or host to buster")
	parser.add_argument("-v", "--verbosity", action="count", default=0, help="Increase output verbosity")
	parser.add_argument("-p", "--port", help="Which port?", type=int)
	parser.add_argument("-P", "--pfile", help="Port file to iterate")
	parser.add_argument("-t", "--threads", type=int, help="Concurrent threads to run [15]", default=MAX_WORKERS)
	parser.add_argument("-o", "--output", help="Output file to write to")
	parser.add_argument("-l", "--dlist", help="Directory list file")
	parser.add_argument("-d", "--data", help="POST data")
	parser.add_argument("-X", "--X", help="POST requests,Put requests")
	parser.add_argument("-w", "--writeresponse", help="Write response to file", action="store_true", default=False)
	parser.add_argument("-i", "--ignorecertificate", help="Ignore certificate errors", action="store_true", default=False)
	parser.add_argument("-u", "--useragent", help="User agent to use.", default=generate_user_agent())
	parser.add_argument("-mr","--matchs", help="regex match")
	parser.add_argument("-ms","--matchstatus", help="match status and allow only that ones")
	parser.add_argument("-fs","--filterstatus", help="filter status and allow only that ones")
	parser.add_argument("--ssl", help="Should i use SSL?", action="store_true")
	parser.add_argument('--timeout', help="Socket timeout [3]", default=3, type=int)
	args = parser.parse_args()
	if args.port and args.pfile:
		_print_err("Can't have both port file [pfile] and port [port] specified.")
		_print_err("Kindly choose one.")
		exit()
	if args.dlist:
		if not os.path.exists(args.dlist):
			_print_err("Can't find file '%s'." % args.dlist)
			exit()
	if args.pfile:
		if not os.path.exists(args.pfile):
			_print_err("Can't find file '%s'." % args.pfile)
			exit()
	if args.ignorecertificate and not args.ssl:
		_print_info("Since ignore-certificate flag is on but SSL is not, will attempt SSL connection.")
	if not args.output:
		args.output = "%s_output.csv" % args.domain
	if args.verbosity:
		_print_info("Will write output to %s." % args.output)
	if args.verbosity and not args.useragent:
		_print_info("No user-agent was supplied so using '%s'." % args.useragent)

	if os.path.exists(args.output):
		i = input(Fore.RED + "[!]"+Style.RESET_ALL+"\tOutput file exists. Should i overwrite it?[no]:") or False
		if i == False:
			args.output = "%s_%s.csv" % (args.domain, random.randint(111,999))
			_print_info("Set output file to be '%s'." % args.output)
		else:
			_print_info("Original file will be overwritten.")
	return args

def regexprint(argsmatch,response,datas):
	pattern = re.compile(argsmatch)
	match = re.search(pattern, str(response.text))
	print(f'Read {len(response.content)} and {datas}')
	if match:
			print("gotiiiiin")

def download_file(url,datas, ssl_verify=True, write_response=False, timeout=DEF_TIMEOUT):
	args = parse_arguemnts()
	flag1=False
	flag2=False
	flag3=False
	try:
		session = get_session()
		with session.post(url, data=datas) as response:
			try:
				if args.matchs and (args.matchstatus or args.filterstatus):
					#print('flag1 set')
					flag1=True
			except:
				if args.matchstatus and args.filterstatus:
					#print('flag2 set')
					flag2=True
			try:
				if args.matchstatus and flag1==False and flag2==False:
					#print('flag3 set')
					flag3=True
			except:
				pass
			try:
				if args.filterstatus and flag1==False and flag2==False:
					#print('flag3 set')
					flag3=True
			except:
				pass
			#print(args.filterstatus + str(flag1) +str(flag2))
			if flag1:					#all three present
				#if int(args.filterstatus)==int(response.status_code): print('hiii')
				flagin1=False
				flagin2=False
				try:
					if int(response.status_code)!=int(args.filterstatus) and int(response.status_code)==int(args.matchstatus):
						regexprint(args.matchs,response,datas)
						flagin1=True
						
				except:
					pass
				try:
					if int(response.status_code)!=int(args.filterstatus) and flagin1==False:
						regexprint(args.matchs,response,datas)
						flagin2=True
				except:
					pass
				try:
					if int(response.status_code)==int(args.matchstatus) and flagin1==False and flagin2==False:
						regexprint(args.matchs,response,datas)
				except:
					pass
			if flag2:
				if int(response.status_code)!=int(args.filterstatus) and int(response.status_code)==int(args.matchstatus):
					print(f'Read {len(response.content)} and {datas}')
			if flag3:
				try:
					if int(response.status_code)!=int(args.filterstatus):
						print(f'Read {len(response.content)} and {datas}')
				except:
					if int(response.status_code)==int(args.matchstatus):
						print(f'Read {len(response.content)} and {datas}')
			try:
				#print( str(flag1) +str(flag2) +str(flag3))
				if flag1==False and flag2==False and flag3==False:
					if args.matchs:
						regexprint(args.matchs,response,datas)
			except:
				pass
		return 1
	except Exception as e:
		print(e)
		return 'error'

def main():
	_print_banner()
	args = parse_arguemnts()

	# Read relevant files
	# Parse ports file.
	if args.pfile:
		ports = []
		ports_raw = open(args.pfile, 'r', encoding='latin-1').readlines()
		for port in ports_raw:
			try:
				dis = port.strip()
				if len(dis) != 0:
					thisport = int()
					ports.append(thisport)
				else:
					# Probably empty line.
					pass
			except:
				_print_err("Error parsing ports file. One of the lines in not an integer.")
				exit()
	elif args.port:
		ports = [args.port]
	elif args.ssl:
		ports = [443]
	else:
		ports = [80]

	# Parse Directory file
	dirs = []
	if args.dlist:
		dirs_raw = open(args.dlist, 'r', encoding='latin-1').readlines()
		for i in dirs_raw:
			thisDir = i.strip()
			print(thisDir)
			if len(thisDir) == 0:
				continue
			dirs.append(thisDir)
	else:
		dirs_raw = open(DEFAULT_DIR_LIST_FILE, 'r').readlines()
		for i in dirs_raw:
			thisDir = i.strip()
			if len(thisDir) == 0:
				continue
			dirs.append(thisDir)

	# Make output directory incase of writing
	if args.writeresponse:
		try:
			os.mkdir(args.domain)
		except:
			# Directory exists
			pass

	# Start threading
	headers = {'User-Agent': args.useragent}
	thread_local = threading.local()
	URLs_to_check = []
	DATA_to_check = []
	#urls="https://%s" % (args.domain, port)
	print(args.domain)
	
	
	print("hii")
	for port in ports:
		for dir in dirs:
			url=args.domain.replace("fuzz", dir)
			URLs_to_check.append(url)
	print(args.X)
	if args.X == "POST":
		if "fuzz" in args.data:
			print("POSt")
			for port in ports:
				for dir in dirs:
					data=args.data.replace("fuzz", dir)
					DATA_to_check.append(ast.literal_eval(data))
					print(ast.literal_eval(str(data)))
					_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
					_print_info("Execution starting with %s threads..." % args.threads)
			processes = []
			thread_args = []
			
			tokens = {'Token': '326729'}
			print((DATA_to_check[0]))
			#for i in DATA_to_check:
			#	print(i)
			#NEW_DATA_CHECK= DATA_to_check.items()


			for i in DATA_to_check:
				thread_args.append((args.domain,i,args.ignorecertificate,args.writeresponse, args.timeout))

			with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
				executor.map(download_file, *zip(*thread_args))

			for task in as_completed(processes):
				try:
					print(task.result().status_code)
				#print('s')
				except:
					pass
			exit()
	else:
		processes = []
		_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
		_print_info("Execution starting with %s threads..." % args.threads)

		thread_args = []
		
		for i in URLs_to_check:
			thread_args.append((i,headers,args.ignorecertificate,args.writeresponse, args.timeout))

		with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
			executor.map(_fetch_url, *zip(*thread_args))

	_print_succ("Completed exection on %s items." % len(URLs_to_check))

	# Write output to file
	with open(args.output, 'w', newline='') as csvfile:
		fieldnames = ['Datetime', 'URL', 'StatusCode', 'ResponseSize']
		writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

		writer.writeheader()
		for item in FOUND:
			thisItem = {'Datetime': item[0], 'URL':item[1], 'StatusCode':item[2], 'ResponseSize': item[3]}
			writer.writerow(thisItem)

	_print_succ("Wrote all items to file '%s'." % args.output)

	exit()

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		_print_err("Got keyboard interrupt. Byebye now.")
		exit()


# python .\BirDuster.py -l .\dir_list2.txt -X POST http://192.168.43.38/mutillidae/index.php?page=login.php -d "{'username':'sdsd','password':'fuzz','login-php-submit-button':'Login'}"

