#!/usr/bin/env python3

import os
import csv
import sys
import base64
import pyfiglet
import time
from urllib import request
from rich.table import Table
from rich.console import Console
from rich.columns import Columns
from rich import segment
from rich import print as rprint
import socket
import traceback
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
	console = Console()
	console.print("[blue][+][/]\t[bold]" + message+"[/]")

def get_session() -> Session:
    if not hasattr(thread_local,'session'):
        thread_local.session = requests.Session()
    return thread_local.session

def _fetch_get_header(url, headers,unfuzzdata,datas=False, ssl_verify=True, write_response=False, timeout=DEF_TIMEOUT):
	global FOUND
	flag1=False
	
	flag2=False
	flag3=False
	#print("real headers are"+str(headers))
	args = parse_arguemnts()
	domain = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
	
	socket.setdefaulttimeout = timeout
	now = datetime.now()
	dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
	try:
		if args.X!=None:
			if args.followredirect != None:
				site_request = requests.post(url,datas, headers=headers, verify=ssl_verify,allow_redirects=False)
			else:
				site_request = requests.post(url,datas, headers=headers, verify=ssl_verify)
		else:
			site_request = requests.get(url, headers=headers, verify=ssl_verify)
		#print('requesr '+site_request.request.body)
		FOUND.append([dt_string, url, site_request.status_code, len(site_request.content)])
		try:
			if args.matchs and (args.matchstatus or args.filterstatus):
				#print('flag1 set')
				flag1=True
		except:
			pass
		try:
			if args.matchstatus and args.filterstatus and flag1==False:
				
				#print('flag2 set')
				flag2=True
		except:
			pass
		try:
			if args.matchstatus and flag1==False and flag2==False:
					#print('flag3 set')
					#print(args.matchstatus)
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
					
					#print('hiii')
					#regexprint(table,args.matchs,site_request,headers)
					regexprint(args.matchs,site_request,headers,unfuzzdata)
					flagin1=True
				
			except:
				pass
			try:
				if int(site_request.status_code)!=int(args.filterstatus) and flagin1==False and args.matchstatus==None:
					#print('hii two')
					#regexprint(args.matchs,site_request,headers)
					regexprint(args.matchs,site_request,headers,unfuzzdata)
					flagin2=True
			except:
				pass
			try:
				
				if int(site_request.status_code)==int(args.matchstatus) and flagin1==False and flagin2==False and args.filterstatus==None:
					#print('hii three')
					#regexprint(args.matchs,site_request,headers)
					regexprint(args.matchs,site_request,headers,unfuzzdata)
			except:
				pass
		if flag2:
				if int(site_request.status_code)!=int(args.filterstatus) and int(site_request.status_code)==int(args.matchstatus):
					#print('hii')
					nonregexprint(site_request,headers,unfuzzdata)
		if flag3:
				try:
					if int(site_request.status_code)!=int(args.filterstatus):
						nonregexprint(site_request,headers,unfuzzdata)
				except:
					
					if int(site_request.status_code)==int(args.matchstatus):
						nonregexprint(site_request,headers,unfuzzdata)
		try:
				#print( str(flag1) +str(flag2) +str(flag3))
			if flag1==False and flag2==False and flag3==False:
					if args.matchs!=None:
						#print('hiiiiii')
						regexprint(args.matchs,site_request,headers,unfuzzdata)
						
					else:
						#print(site_request.request.headers)
						#print('hxxx')
						nonregexprint(site_request,headers,unfuzzdata)
						#print(f'Read {len(site_request.content)} in is and {headers}')
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

def _fetch_url(url,unfuzzdata,count, headers=None, ssl_verify=True, write_response=False, timeout=DEF_TIMEOUT):
	global FOUND
	console = Console()
	
	#print(count)
	flag1=False
	flag2=False
	flag3=False
	args = parse_arguemnts()
	domain = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
	
	socket.setdefaulttimeout = timeout
	now = datetime.now()
	dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
	try:
		if args.followredirect != None:
			site_request = requests.get(url, headers=headers, verify=ssl_verify,allow_redirects=False)
		else:
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
					#print(f'Read {len(site_request.content)} and {url}')
					nonregexprint(site_request,url,unfuzzdata)
		if flag3:
				try:
					if int(site_request.status_code)!=int(args.filterstatus):
						#print(f'Read {len(site_request.content)} and {url}')
						nonregexprint(site_request,url,unfuzzdata)
				except:
					if int(site_request.status_code)==int(args.matchstatus):
						#print(f'Read {len(site_request.content)} and {url}')
						nonregexprint(site_request,url,unfuzzdata)
		try:
				#print( str(flag1) +str(flag2) +str(flag3))
			if flag1==False and flag2==False and flag3==False:
					if args.matchs!=None:
						
						regexprint(args.matchs,site_request,url,unfuzzdata)
					else:
						nonregexprint(site_request,url,unfuzzdata)
						#print(f'Read {len(site_request.content)} and {url}')
		except:
				pass
		#print(f"number{count}",end="\r")
		#sys.stdout.write(f"\r :: Progress: [{count} / {ast.Global.max}]")
		#sys.stdout.flush()'
		data_dict={}
		console.print(f"[bold green] :: Progress: [{count} / {ast.Global.max}]",end='\r',style="bold")
		'''with open('maybe.json','a+') as file:
			data_dict[count]=dict(FUZZ=url,Status=site_request.status_code,Length=str(len(site_request.content)),Fuzzdata=unfuzzdata)
			
			
			#print(file.read())
			#print('file is')
			file_data = json.load(file)
			#print(file_data)
			file_data["req"].append(data_dict)
			# Sets file's current position at offset.
			# 
			file.seek(0)
			# convert back to json.
			json.dump(file_data, file, indent = 4)
			#json.dump(data_dict,ast.Global.outfile,ensure_ascii=False)
			ast.Global.outfile.close()'''
		#print(f"Progress: [{count} / {ast.Global.max}]",end='\r')
		return 1

		
		#print(url+" ==> "+site_request.status_code, flush=True)
		
			#print(url+" ==> "+site_request.status_code, flush=True)
			
	except Exception as e:
		FOUND.append([dt_string, url, "Error: %s" % e, 0])
	
	fulldesc=str(url+" ==> "+str(site_request.status_code)+"\n")
	sys.stdout.write(fulldesc)
	sys.stdout.flush()
	
	
	

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
	parser.add_argument("-H", "--headers", help="Headers in a request")
	parser.add_argument("-w", "--writeresponse", help="Write response to file", action="store_true", default=False)
	parser.add_argument("-i", "--ignorecertificate", help="Ignore certificate errors", action="store_true", default=False)
	parser.add_argument("-u", "--useragent", help="User agent to use.", default=generate_user_agent())
	parser.add_argument("-mr","--matchs", help="regex match")
	parser.add_argument("-fred","--followredirect", help="follow ridirect from the response")
	parser.add_argument("-ex","--fileext", help="file extensions to match")
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
	#print('lmao')
	console = Console()
	#print(response.status_code)
	#print(response.status_code)
	#table.add_row(str(len(response.content)), str(datas),str(response.status_code))
	#for i in lists:
		#print(i)
	#print(f'Read {len(response.content)} and {datas}')
	
	console.print(f"[white  bold]{str(len(response.content)): <{20}}{str(unfuzzdata): <{20}}[/][{respcolor(response)}]{str(response.status_code): >{20}}[/]")

	#print(str(len(response.content))+"  "+str(unfuzzdata)+"  "+str(response.status_code))
	#rprint(f"{str(len(response.content)): <{20}}{str(unfuzzdata): <{20}}{str(response.status_code): >{20}}")
	

def regexprint(argsmatch,response,datas,unfuzzdata):
	#print('lmao')
	console = Console()
	pattern = re.compile(argsmatch)
	match = re.search(pattern, str(response.text))
	#print(response.status_code)
	#table.add_row(str(len(response.content)), str(datas),str(response.status_code))
	
	#for i in lists:
		#print(i)
	#print(f'Read {len(response.content)} and {datas}')
	
	#print(str(len(response.content))+"  "+str(unfuzzdata)+"  "+str(response.status_code))
	
	#console.print(table)
	if match:
			#print(str(len(response.content))+"  "+str(unfuzzdata)+"  "+str(response.status_code))
			console.print(f"[white bold]{str(len(response.content)): <{20}}{str(unfuzzdata): <{20}}[/][{respcolor(response)}]{str(response.status_code): >{20}}[/]")

			#print("gotiiiiin")
			pass

def download_file(url,unfuzzdata,datas, ssl_verify=True, write_response=False, timeout=DEF_TIMEOUT):
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
						regexprint(args.matchs,response,datas,unfuzzdata)
						flagin1=True
						
				except:
					pass
				try:
					if int(response.status_code)!=int(args.filterstatus) and flagin1==False  and args.matchstatus==None:
						#print('dydyyd')
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
					#print(f'Read {len(response.content)} and {datas}')
					nonregexprint(response,datas,unfuzzdata)
			if flag3:
				try:
					if int(response.status_code)!=int(args.filterstatus):
						#print(f'Read {len(response.content)} and {datas}')
						nonregexprint(response,datas,unfuzzdata)
				except:
					if int(response.status_code)==int(args.matchstatus):
						#print('kali')
						nonregexprint(response,datas,unfuzzdata)
						#print(f'Read {len(response.content)} and {datas}')
			try:
				#print( str(flag1) +str(flag2) +str(flag3))
				if flag1==False and flag2==False and flag3==False:
					if args.matchs:
						#print('kalis')
						regexprint(args.matchs,response,datas,unfuzzdata)
					else:
						
						nonregexprint(response,datas,unfuzzdata)
			except:
				pass
		return 1
	except Exception as e:
		print(e)
		return 'error'
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
	#print({respcolor(args.matchstatus)})
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
	#_print_banner()
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
	ast.Global.outfile = open("maybe.json","a+",encoding="utf-8")
	#print(json.dumps(dict(req=dict(Command=commandstring))));
	json.dump(dict(req=dict(Command=commandstring)),ast.Global.outfile,ensure_ascii=False) 
	#file.close()
	#rprint(result)
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
			#print(thisDir)
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

	
	
	if args.fileext!=None:
		extlist=(args.fileext).split(',')
	for port in ports:
		for dir in dirs:
			url=args.domain.replace("fuzz", dir)
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
	
			#URLs_to_check.append(url)
	#print(URLs_to_check)
	try:
		if "fuzz" in args.headers:
			#print('in headers')
			for port in ports:
					for dir in dirs:
						data=args.headers.replace("fuzz", dir)
						l=[dir,ast.literal_eval(data)]
						DATA_to_check.append(tuple(l))
						#DATA_to_check.append(ast.literal_eval(data))
						#print(ast.literal_eval(str(data)))
			_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
			_print_info("Execution starting with %s threads..." % args.threads)
			print()
			console.print(f"[violet]{str('Size'): <{20}}{str('Payload'): <{23}}{str('Status Code'): >{20}}[/]" ,style="bold violet")
			processes = []
			thread_args = []
			
			if args.X!=None:
				for i in DATA_to_check:
					thread_args.append((args.domain,i[1],i[0],args.data,args.ignorecertificate,args.writeresponse, args.timeout))
			else:
				for i in DATA_to_check:
					thread_args.append((args.domain,i[1],i[0],args.ignorecertificate,args.writeresponse, args.timeout))

			with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
				executor.map(_fetch_get_header, *zip(*thread_args))

			_print_succ("Completed exection on %s items." % len(URLs_to_check))
			print('exiting')
			exit()
	except Exception:
		#traceback.print_exc()
		pass
	#to check if args are present
	argspresent=True
	try:
		if "fuzz" not in args.headers:
			argspresent=True
		else:
			argspresent=False
	except:
		argspresent=True
	if args.X == "POST" and argspresent:
		if "fuzz" in args.data:
			#print("POSt")
			for port in ports:
				for dir in dirs:
					data=args.data.replace("fuzz", dir)
					l=[dir,ast.literal_eval(data)]
					DATA_to_check.append(tuple(l))
					#print(type(tuple(l)))
			_print_info("Starting execution on %s URLs of %s ports and %s directories." % (len(URLs_to_check), len(ports), len(dirs)))
			_print_info("Execution starting with %s threads..." % args.threads)
			print()
			console.print(f"[violet]{str('Size'): <{20}}{str('Payload'): <{23}}{str('Status Code'): >{20}}[/]" ,style="bold violet")
			processes = []
			thread_args = []
			#exit()
			tokens = {'Token': '326729'}
			#print((DATA_to_check[0]))
			#for i in DATA_to_check:
			#	print(i)
			#NEW_DATA_CHECK= DATA_to_check.items()


			for i in DATA_to_check:
				thread_args.append((args.domain,i[0],i[1],args.ignorecertificate,args.writeresponse, args.timeout))

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
		print()
		console.print(f"[violet]{str('Size'): <{20}}{str('Payload'): <{23}}{str('Status Code'): >{20}}[/]" ,style="bold violet")
		
		#for i in URLs_to_check:
		#	print(i[1])
		#print((URLs_to_check[1]))
		thread_args = []
		count=0
		for i in URLs_to_check:
			count+=1
			thread_args.append((i[1],i[0],count,headers,args.ignorecertificate,args.writeresponse, args.timeout))
		#print(thread_args[-1][2])
		max = thread_args[-1][2]
		ast.Global.max=max
		with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
			executor.map(_fetch_url, *zip(*thread_args))

	_print_succ("Completed exection on %s items." % len(URLs_to_check))

	# Write output to file
	'''with open(args.output, 'w', newline='') as csvfile:
		fieldnames = ['Datetime', 'URL', 'StatusCode', 'ResponseSize']
		writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

		writer.writeheader()
		for item in FOUND:
			thisItem = {'Datetime': item[0], 'URL':item[1], 'StatusCode':item[2], 'ResponseSize': item[3]}
			writer.writerow(thisItem)

	_print_succ("Wrote all items to file '%s'." % args.output)'''

	exit()

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		_print_err("Got keyboard interrupt. Byebye now.")
		exit()


