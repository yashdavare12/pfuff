#!/usr/bin/env python3

import os
import sys
import pyfiglet
from urllib import request
from rich.table import Table
from rich.console import Console
from rich.columns import Columns
from rich import segment
from rich import print as rprint
import socket
from urllib.parse import urlencode
import random
import argparse
import requests
import re
import json
from requests.sessions import Session
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
FOUND = []
thread_local = local()

def _print_err(message):
	sys.stderr.write(Fore.RED + "[X]"+Style.RESET_ALL+"\t%s\n" % message)

def _print_succ(message):
	sys.stdout.write(Fore.GREEN + "[+]"+Style.RESET_ALL+"\t%s\n" % message)

def _print_info(message):
	console = Console()
	console.print("[blue][+][/]\t[bold]" + message+"[/]")

def get_session() -> Session:
    if not hasattr(thread_local,'session'):
        thread_local.session = requests.Session()
    return thread_local.session

def _fetch_header(url, headers,unfuzzdata,count,datas=False, ssl_verify=True, timeout=DEF_TIMEOUT):
	global FOUND
	console = Console()
	flag1=False
	flag2=False
	flag3=False
	args = parse_arguemnts()
	domain = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
	
	socket.setdefaulttimeout = timeout
	now = datetime.now()
	dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
	try:
		ispost=False
		if args.X!=None:
			ispost=True
		if ispost:
			if args.followredirect != None:
				site_request = requests.post(url,datas, headers=headers, verify=ssl_verify,allow_redirects=False,timeout=timeout)
			else:
				site_request = requests.post(url,datas, headers=headers, verify=ssl_verify,timeout=timeout)
		else:
			if args.followredirect != None:
				site_request = requests.get(url, headers=headers, verify=ssl_verify,allow_redirects=False)
			else:
				site_request = requests.get(url, headers=headers, verify=ssl_verify)
		FOUND.append([dt_string, url, site_request.status_code, len(site_request.content)])
		try:
			if args.matchs and (args.matchstatus or args.filterstatus):
				flag1=True
		except:
			pass
		try:
			if args.matchstatus and args.filterstatus and flag1==False:
				flag2=True
		except:
			pass
		try:
			if args.matchstatus and flag1==False and flag2==False:
					flag3=True
		except:
				pass
		try:
				if args.filterstatus and flag1==False and flag2==False:
					flag3=True
		except:
				pass
		if flag1:         #all three present
			flagin1=False
			flagin2=False
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					regexprint(args.matchs,site_request,headers,unfuzzdata)
					flagin1=True
			except:
				pass
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and flagin1==False and args.matchstatus==None:
					regexprint(args.matchs,site_request,headers,unfuzzdata)
					flagin2=True
			except:
				pass
			try:
				if int(site_request.status_code)==int(args.matchstatus) and flagin1==False and flagin2==False and args.filterstatus==None:
					regexprint(args.matchs,site_request,headers,unfuzzdata)
			except:
				pass
		if flag2:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					nonregexprint(site_request,headers,unfuzzdata)
		if flag3:
				try:
					if int(site_request.status_code)!=int(args.filterstatus):
						nonregexprint(site_request,headers,unfuzzdata)
				except:
					if int(site_request.status_code)==int(args.matchstatus):
						nonregexprint(site_request,headers,unfuzzdata)
		try:
			if flag1==False and flag2==False and flag3==False:
					if args.matchs!=None:
						regexprint(args.matchs,site_request,headers,unfuzzdata)
					else:
						nonregexprint(site_request,headers,unfuzzdata)
		except:
				pass
		console.print(f"[bold green] :: Progress: [{count} / {ast.Global.max}",end='\r',style="bold")
		if ispost:
			ast.Global.outputjson['fuzzed'].append(dict(URL=url,TYPE='POST HEADER',Status=site_request.status_code,Length=str(len(site_request.content)),Fuzzdata=unfuzzdata))
		else:
			ast.Global.outputjson['fuzzed'].append(dict(URL=url,TYPE='GET HEADER',Status=site_request.status_code,Length=str(len(site_request.content)),Fuzzdata=unfuzzdata))
		return 1
	except Exception as e:
		FOUND.append([dt_string, url, "Error: %s" % e, 0])
	
def _fetch_url(url,unfuzzdata,count, headers=None, ssl_verify=True, timeout=DEF_TIMEOUT):
	global FOUND
	console = Console()
	flag1=False
	flag2=False
	flag3=False
	#print(port)
	args = parse_arguemnts()
	domain = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
	socket.setdefaulttimeout = timeout
	now = datetime.now()
	dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
	try:
		if args.followredirect != None:
			site_request = requests.get(url, headers=headers, verify=ssl_verify,allow_redirects=False,timeout=timeout)
		else:
			site_request = requests.get(url, headers=headers, verify=ssl_verify,timeout=timeout)
		FOUND.append([dt_string, url, site_request.status_code, len(site_request.content)])
		try:
			if args.matchs and (args.matchstatus or args.filterstatus):
				flag1=True
		except:
			if args.matchstatus and args.filterstatus:
				flag2=True
		try:
			if args.matchstatus and flag1==False and flag2==False:
					flag3=True
		except:
				pass
		try:
				if args.filterstatus and flag1==False and flag2==False:
					flag3=True
		except:
				pass
		if flag1:         #all three present
			flagin1=False
			flagin2=False
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					regexprint(args.matchs,site_request,url,unfuzzdata)
					flagin1=True
				
			except:
				pass
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and flagin1==False and args.matchstatus==None:
					regexprint(args.matchs,site_request,url,unfuzzdata)
					flagin2=True
			except:
				pass
			try:
				if int(site_request.status_code)==int(args.matchstatus) and flagin1==False and flagin2==False and args.filterstatus==None:
					regexprint(args.matchs,site_request,url,unfuzzdata)
			except:
				pass
		if flag2:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					nonregexprint(site_request,url,unfuzzdata)
		if flag3:
				try:
					if int(site_request.status_code)!=int(args.filterstatus):
						nonregexprint(site_request,url,unfuzzdata)
				except:
					if int(site_request.status_code)==int(args.matchstatus):
						nonregexprint(site_request,url,unfuzzdata)
		try:
			if flag1==False and flag2==False and flag3==False:
					if args.matchs!=None:
						
						regexprint(args.matchs,site_request,url,unfuzzdata)
					else:
						nonregexprint(site_request,url,unfuzzdata)
		except:
				pass
		data_dict={}
		console.print(f"[bold green] :: Progress: [{count} / {ast.Global.max}]",end='\r',style="bold")
		ast.Global.outputjson['fuzzed'].append(dict(URL=url,TYPE='GET',Status=site_request.status_code,Length=str(len(site_request.content)),Fuzzdata=unfuzzdata))
		return 1
	except Exception as e:
		FOUND.append([dt_string, url, "Error: %s" % e, 0])
	
	

def parse_arguemnts():
	parser = argparse.ArgumentParser()
	parser.add_argument("domain", help="domain or host to buster")
	parser.add_argument("-t", "--threads", type=int, help="Concurrent threads to run [15]", default=MAX_WORKERS)
	parser.add_argument("-o", "--output", help="Output file to write to")
	parser.add_argument("-l", "--dlist", help="Directory list file")
	parser.add_argument("-d", "--data", help="POST data")
	parser.add_argument("-X", "--X", help="POST requests,Put requests")
	parser.add_argument("-H", "--headers", help="Headers in a request")
	parser.add_argument("-i", "--ignorecertificate", help="Ignore certificate errors", action="store_true", default=False)
	parser.add_argument("-u", "--useragent", help="User agent to use.", default=generate_user_agent())
	parser.add_argument("-mr","--matchs", help="regex match")
	parser.add_argument("-fred","--followredirect", help="follow ridirect from the response")
	parser.add_argument("-ex","--fileext", help="file extensions to match")
	parser.add_argument("-ms","--matchstatus", help="match status and allow only that ones")
	parser.add_argument("-fs","--filterstatus", help="filter status and allow only that ones")
	parser.add_argument("--ssl", help="Should i use SSL?", action="store_true")
	parser.add_argument('--timeout', help="Socket timeout [3]", default=3, type=float)
	args = parser.parse_args()
	if args.dlist:
		if not os.path.exists(args.dlist):
			_print_err("Can't find file '%s'." % args.dlist)
			exit()
	if args.ignorecertificate and not args.ssl:
		_print_info("Since ignore-certificate flag is on but SSL is not, will attempt SSL connection.")
	return args

def respcolor(response):
	try:
		if response.status_code >=400 and  response.status_code<=499:			#404 resp
			return 'red'
		if response.status_code >=200 and  response.status_code<=299:			#200 resp
			return 'green'
		if response.status_code >=500 and  response.status_code<=599:			#501 errors
			return 'violet'
		if response.status_code >=300 and  response.status_code<=399:			#301 errors
			return 'yellow'
	except:
		if response >=400 and  response<=499:			#404 resp
			return 'red'
		if response >=200 and  response<=299:			#200 resp
			return 'green'
		if response >=500 and  response<=599:			#501 errors
			return 'violet'
		if response >=300 and  response<=399:			#301 errors
			return 'yellow'

def nonregexprint(response,datas,unfuzzdata):
	console = Console()
	console.print(f"[white  bold]{str(len(response.content)): <{20}}{str(unfuzzdata): <{20}}[/][{respcolor(response)}]{str(response.status_code): >{20}}[/]")

def regexprint(argsmatch,response,datas,unfuzzdata):
	console = Console()
	pattern = re.compile(argsmatch)
	match = re.search(pattern, str(response.text))
	if match:
			console.print(f"[white bold]{str(len(response.content)): <{20}}{str(unfuzzdata): <{20}}[/][{respcolor(response)}]{str(response.status_code): >{20}}[/]")
			pass

def _do_post(url,unfuzzdata,datas,count, ssl_verify=True, timeout=DEF_TIMEOUT):
	args = parse_arguemnts()
	console = Console()
	flag1=False
	flag2=False
	flag3=False
	try:
		session = get_session()
		with session.post(url, data=datas, verify=ssl_verify) as response:
			try:
				if args.matchs and (args.matchstatus or args.filterstatus):
					flag1=True
			except:
				if args.matchstatus and args.filterstatus:
					flag2=True
			try:
				if args.matchstatus and flag1==False and flag2==False:
					flag3=True
			except:
				pass
			try:
				if args.filterstatus and flag1==False and flag2==False:
					flag3=True
			except:
				pass
			if flag1:					#all three present
				flagin1=False
				flagin2=False
				try:
					if int(response.status_code)!=int(args.filterstatus) and int(response.status_code)==int(args.matchstatus):
						regexprint(args.matchs,response,datas,unfuzzdata)
						flagin1=True
				except:
					pass
				try:
					if int(response.status_code)!=int(args.filterstatus) and flagin1==False  and args.matchstatus==None:
						regexprint(args.matchs,response,datas,unfuzzdata)
						flagin2=True
				except:
					pass
				try:
					if int(response.status_code)==int(args.matchstatus) and flagin1==False and flagin2==False  and args.filterstatus==None:
						regexprint(args.matchs,response,datas,unfuzzdata)
				except:
					pass
			if flag2:
				if int(response.status_code)!=int(args.filterstatus) and int(response.status_code)==int(args.matchstatus):
					nonregexprint(response,datas,unfuzzdata)
			if flag3:
				try:
					if int(response.status_code)!=int(args.filterstatus):
						nonregexprint(response,datas,unfuzzdata)
				except:
					if int(response.status_code)==int(args.matchstatus):
						nonregexprint(response,datas,unfuzzdata)
			try:
				if flag1==False and flag2==False and flag3==False:
					if args.matchs:	
						regexprint(args.matchs,response,datas,unfuzzdata)
					else:
						nonregexprint(response,datas,unfuzzdata)
			except:
				pass
		console.print(f"[bold green] :: Progress: [{count} / {ast.Global.max}]",end='\r',style="bold")
		ast.Global.outputjson['fuzzed'].append(dict(URL=url,TYPE='POST',Status=response.status_code,Length=str(len(response.content)),Fuzzdata=unfuzzdata))
		
		return 1
	except Exception as e:
		print(e)
		return 'error'

def addtojson(filename):
    if os.path.exists(filename):
        i = input(Fore.RED + "[!]"+Style.RESET_ALL+"\tOutput file exists. Should i overwrite it?[no]:") or False
        if i == False:
            filename = "%s_%s.json" % (filename, random.randint(111,999))
            _print_info("Set output file to be '%s'." % filename)
        else:
            _print_info("Original file will be not overwritten.")
    with open(filename, 'r+') as file:
        (ast.Global.outputjson['fuzzed']).pop(0)
        json_object = json.dumps(ast.Global.outputjson, indent = 4)
        file.write(json_object)

def get_Method():
	args = parse_arguemnts()
	try:
		if(args.X):
			return 'POST'
		raise 'not a post type'
	except:
		return 'GET'
	pass

def show_headers():
	console = Console()
	args = parse_arguemnts()
	console.print(f" ::  {str('Methods'): <{20}}[violet]{str(get_Method()): <{20}}[/]",style="bold")
	console.print(f" ::  {str('Url'): <{20}}[not underline bold]{str(args.domain): <{20}}[/]",style="bold")
	try:
		console.print(f" ::  {str('Redirect'): <{20}}[blue bold]{str( ('True' if args.followredirect else 'False')): <{20}}",style="bold")
	except:
		pass
	try:

		console.print(f" ::  {str('Matcher'): <{20}}[{respcolor(int(args.matchstatus))}]{str(args.matchstatus): <{20}}[/]",style="bold")
	except:
		pass
	try:
		console.print(f" ::  {str('Filter'): <{20}}[{respcolor(int(args.filterstatus))}]{str(args.filterstatus): <{20}}",style="bold")
	except:
		pass
	pass

def main():
	result = pyfiglet.figlet_format("pffuf", font = "slant"  )
	console = Console()
	console.status("[bold green]Working on tasks...")
	console.print(result ,style="bold blue")
	
	rprint(u'\u2500' * 50)
	show_headers()
	rprint(u'\u2500' * 50)
	print("")
	commandstring = '';

	for arg in sys.argv:
		if ' ' in arg:
			commandstring += '"{}"  '.format(arg);
		else:
			commandstring+="{}  ".format(arg);
	
	
	ast.Global.outputjson=(dict(req=dict(Command=commandstring),fuzzed=[{"none":"none"}]))
	args = parse_arguemnts()
	
	# Read relevant files
	
	
	
	ports = [80]
	# Parse Directory file
	dirs = []
	if args.dlist:
		dirs_raw = open(args.dlist, 'r', encoding='latin-1').readlines()
		for i in dirs_raw:
			thisDir = i.strip()
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


	# Start threading
	headers = {'User-Agent': args.useragent}
	thread_local = threading.local()
	URLs_to_check = []
	DATA_to_check = []
	

	if args.fileext!=None:
		extlist=(args.fileext).split(',')
	for port in ports:
		for dir in dirs:
			url=args.domain.replace("FUZZ", dir)
			tempurl=url
			tempdir=dir
			if args.fileext!=None:
				for ext in extlist:
					url=tempurl
					dir=tempdir
					url=url+"."+ext
					dir=dir+"."+ext
					l=[dir,url]
					URLs_to_check.append(tuple(l))
			else:
				l=[dir,url]
				URLs_to_check.append(tuple(l))
	try:
		if "FUZZ" in args.headers:
			print('in headers')
			for port in ports:
					for dir in dirs:
						data=args.headers.replace("FUZZ", dir)
						l=[dir,ast.literal_eval(data)]
						DATA_to_check.append(tuple(l))
			_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
			_print_info("Execution starting with %s threads..." % args.threads)
			print()
			console.print(f"[violet]{str('Size'): <{20}}{str('Payload'): <{23}}{str('Status Code'): >{20}}[/]" ,style="bold violet")
			processes = []
			thread_args = []
			count=0
			if args.X!=None:
				for i in DATA_to_check:
					count+=1
					thread_args.append((args.domain,i[1],i[0],count,args.data,args.ignorecertificate, args.timeout))
			else:
				for i in DATA_to_check:
					thread_args.append((args.domain,i[1],i[0],count,args.ignorecertificate, args.timeout))
			max = thread_args[-1][2]
			ast.Global.max=max
			with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
				executor.map(_fetch_header, *zip(*thread_args))
	except Exception:
		pass
	argspresent=True
	try:
		if "FUZZ" not in args.headers:
			argspresent=True
		else:
			argspresent=False
	except:
		argspresent=True
	if args.X == "POST" and argspresent:
		if "FUZZ" in args.data:
			print("POSt")
			for port in ports:
				for dir in dirs:
					data=args.data.replace("FUZZ", dir)
					l=[dir,ast.literal_eval(data)]
					DATA_to_check.append(tuple(l))
			_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
			_print_info("Execution starting with %s threads..." % args.threads)
			print()
			console.print(f"[violet]{str('Size'): <{20}}{str('Payload'): <{23}}{str('Status Code'): >{20}}[/]" ,style="bold violet")
			processes = []
			thread_args = []
			tokens = {'Token': '326729'}
			count=0
			for i in DATA_to_check:
				count+=1
				thread_args.append((args.domain,i[0],i[1],count,args.ignorecertificate, args.timeout))
			max = thread_args[-1][2]
			ast.Global.max=max
			with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
				executor.map(_do_post, *zip(*thread_args))
	elif argspresent==True:
		processes = []
		_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
		_print_info("Execution starting with %s threads..." % args.threads)
		print()
		console.print(f"[violet]{str('Size'): <{20}}{str('Payload'): <{23}}{str('Status Code'): >{20}}[/]" ,style="bold violet")
		thread_args = []
		count=0
		for i in URLs_to_check:
			count+=1
			thread_args.append((i[1],i[0],count,headers,args.ignorecertificate, args.timeout))
		max = thread_args[-1][2]
		ast.Global.max=max
		with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
			executor.map(_fetch_url, *zip(*thread_args))
	else:
		pass
	_print_succ("Completed exection on %s items." % len(URLs_to_check))
	
	exp = r'\bhttps?://(?:www\.|ww2\.)?((?:[\w-]+\.){1,}\w+)\b'
	r = re.compile(exp, re.M)
	domain_name=str((r.findall(args.domain))[0])
	file_name=domain_name+".json"
	try:
		addtojson(file_name)
	except FileNotFoundError:
		with open(file_name, 'w+') as file:
			pass
		with open(file_name, 'r+') as file:
			(ast.Global.outputjson['fuzzed']).pop(0)
			json_object = json.dumps(ast.Global.outputjson, indent = 4)
			file.write(json_object)
	exit()


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		_print_err("Got keyboard interrupt. Byebye now.")
		exit()


