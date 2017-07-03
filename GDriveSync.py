#!/usr/bin/python
# -*- coding: utf_8 -*-  
'''
GDriveSync

Sync files in local directory to a Google Drive directory.
'''
import codecs
import httplib2
import json
import math
import fnmatch
import sys
import os
import shutil
import logging
import datetime
import time
import traceback
import pytz, tzlocal
import dateutil.parser
import mimetypes
import unicodedata
import threading
import webbrowser
import FileLock

try:
	from ConfigParser import ConfigParser
except Exception:
	from configparser import ConfigParser
from oauth2client.client import OAuth2WebServerFlow,  OAuth2Credentials
from apiclient import errors
from apiclient.discovery import build
from apiclient.http import MediaFileUpload

LTZ = tzlocal.get_localzone()
SENC = sys.getdefaultencoding()
FENC = sys.getfilesystemencoding()
DT1970 = datetime.datetime(1970,1,1).replace(tzinfo=pytz.utc)
SMALL = 2 * 1024 * 1024
LOG = None

if sys.version_info >= (3, 0):
	def unicode(s):
		return str(s)
	def raw_input(s):
		return input(s)


def normpath(s):
	return unicodedata.normalize('NFC', s)

LOCK = threading.Lock()
def uprint(s):
	with LOCK:
		try:
			print(s)
		except Exception:
			try:
				print(s.encode(SENC))
			except Exception:
				print(s.encode('utf-8'))

def tprint(i, s):
	n = datetime.datetime.now().strftime('%H:%M:%S ')
	uprint(u'%s %s %s' % (i, n, s))

def udebug(s):
	return
	tprint('-', s)
	if LOG:
		LOG.debug(s)

def uinfo(s):
	tprint('>', s)
	if LOG:
		LOG.info(s)

def uwarn(s):
	tprint('+', s)
	if LOG:
		LOG.warn(s)

def uerror(s):
	tprint('!', s)
	if LOG:
		LOG.error(s)

def uexception(ex):
	traceback.print_exc()
	if LOG:
		LOG.exception(ex)

def szstr(n):
	return "{:,}".format(n)

def utime(d):
	return d.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

def mtime(p):
	return datetime.datetime.fromtimestamp(os.path.getmtime(p)).replace(microsecond=0, tzinfo=LTZ)

def ftime(dt):
	return tseconds(dt.astimezone(pytz.utc) - DT1970)

def tseconds(td):
	return (td.seconds + td.days * 24 * 3600)

def touch(p, d = None):
	atime = ftime(datetime.datetime.now().replace(tzinfo=LTZ))
	mtime = atime if d is None else ftime(d)
	os.utime(p, ( atime, mtime ))

def mkpdirs(p):
	d = os.path.dirname(p)
	if not os.path.exists(d):
		os.makedirs(d)

def trimdir(p):
	if p == '':
		return p

	if p[-1] == os.path.sep:
		p = p[:-1]
	return unicode(p)

class Config:
	"""Singleton style/static initialisation wrapper thing"""
	def __init__(self):
		self.dict = ConfigParser()
		paths = (os.path.abspath('.gdrivesync.ini'), os.path.expanduser('~/.gdrivesync.ini'))
		for filename in paths:
			if os.path.exists(filename):
				uprint('using gdrivesync.ini file "%s"' % os.path.abspath(filename))
				fp = codecs.open(filename, "r", "utf-8")
				self.dict.readfp(fp)
				fp.close()
				break

		# debug
		self.debug_log = self.get('debug_log', '')
		
		# error
		self.error_log = self.get('error_log', '')
		
		# Location
		self.root_dir = trimdir(os.path.abspath(self.get('root_dir', '.')))
		
		# self.get('trash_dir', self.root_dir + '/.trash')
		self.trash_dir = self.get('trash_dir', '')
		if self.trash_dir:
			self.trash_dir = trimdir(os.path.abspath(self.trash_dir))

		# user webbrowser
		self.webbrowser = True if self.get('webbrowser', 'true') == 'true' else False 

		# max_file_size
		self.max_file_size = int(self.get('max_file_size', '1073741824'))

		# max retry
		self.max_retry = int(self.get('max_retry', '3'))
		
		# Threads
		self.max_threads = int(self.get('num_threads', '4'))

		# includes
		self.includes = json.loads(self.get('includes', '[]'))
		self.excludes = json.loads(self.get('excludes', '[]'))

		# GDrive API
		self.OAUTH_SCOPE = 'https://www.googleapis.com/auth/drive'
		self.REDIRECT_URI = 'http://localhost'
		self.client_id = self.get('client_id', '1051614873204-7fsgjppvimpjj0e1g03lu3ksjmhk64d5.apps.googleusercontent.com')
		self.client_secret = self.get('client_secret', 'Z8wuT_jQbhNmUriHJu-mayX6')
		self.token_file = self.get('token_file', '.gdrivesync.token')

		if os.path.exists(self.token_file):
			self.last_sync = mtime(self.token_file)
		else:
			self.last_sync = DT1970

	def get(self, configparam, default=None):
		"""get the value from the ini file's default section."""
		defaults = self.dict.defaults()
		if configparam in defaults:
			return defaults[configparam]
		if not default is None:
			return default
		raise KeyError(configparam)


# global config
config = Config()

# init
mimetypes.init()

class GoogleCredentials(object):
	def __init__(self):
		self.path = os.path.abspath(config.token_file)
		self.cred = None
		self.file = None
		self.lock = None

	def _load_credentials(self):
		if os.path.exists(self.path):
			self.file = open(self.path)
			try:
				self.cred = self.file.read()
				json.loads(self.cred)
			except Exception as e:
				self.cred = None
				uwarn("Failed to load credentials: " + str(e));

	def _save_credentials(self):
		self.file = open(self.path, 'w')
		self.file.write(self.cred)
		touch(self.path, config.last_sync)

	def _lock_credentials(self):
		FileLock.lock(self.file)

	def _get_credentials(self):
		flow = OAuth2WebServerFlow(config.client_id,
								config.client_secret,
								config.OAUTH_SCOPE,
								config.REDIRECT_URI)
		authorize_url = flow.step1_get_authorize_url()

		uprint('Go to the following link in your browser: ' + authorize_url)
		if config.webbrowser:
			webbrowser.open( authorize_url )

		code = raw_input('Enter verification code: ').strip()
		credentials = flow.step2_exchange(code)
		return credentials

	def get_service(self):
		self._load_credentials()

		if not self.cred:
			uinfo("Credentials not found, begin the Oauth process.")
			credentials = self._get_credentials()
			self.cred = credentials.to_json()
			self._save_credentials()
		else:
			credentials = OAuth2Credentials.from_json(self.cred)

		try:
			self._lock_credentials()
		except Exception as e:
			uerror(str(e))
			raise Exception('Failed to lock %s' % self.path)

		# Create an httplib2.Http object and authorize it with our credentials
		http = httplib2.Http()
		http = credentials.authorize(http)

		drive_service = build('drive', 'v2', http=http)

		return drive_service

class GFile:
	def __init__(self, r = None):
		self.owner = ''
		self.path = None
		self.parent = None
		self.action = None
		self.reason = ''

		if r:
			self.id = r['id']
			self.owner = r['owners'][0]['emailAddress']
			self.mdate = self.to_date(r['modifiedDate'])
			self.mime = r['mimeType']
			self.name = r['title']

			if self.mime == 'application/vnd.google-apps.folder':
				self.folder = True
				self.size = 0
				self.url = None
			else:
				self.folder = False
				self.size = int(r.get('fileSize', '0'))
				self.url = r.get('downloadUrl')
				
			if r['parents']:
				if not r['parents'][0]['isRoot']:
					self.parent = r['parents'][0]['id']
			else:
				self.parent = 'UNKNOWN'

	def to_date(self, md):
		return dateutil.parser.parse(md).replace(microsecond=0).astimezone(LTZ)


class GFileDownloader:
	def __init__(self, service, gf):
		self.service = service
		self.file = gf
		
	def execute(self):
		'''
		download the file content.
		'''
		resp, body = self.service._http.request(self.file.url)
		if resp.status != 200:
			raise errors.HttpError(resp, body)

		with open(self.file.npath, "wb") as f:
			f.write(body)
			
		return True

class GDriveSync:
	def __init__(self, service):
		'''
		:param service: The service of get_service by GoogleCredentials.
		:param target: The target folder to sync.
		'''
		self.service = service
		self.rfiles = {}
		self.rpaths = {}
		self.skips = []

	def exea(self, api, msg):
		cnt = 0
		while True:
			try:
				cnt += 1
				return api.execute()
			except errors.HttpError as e:
				if cnt <= config.max_retry:
					uwarn(str(e))
					uwarn("Failed to %s, retry %d" % (msg, cnt))
					time.sleep(3)
				else:
					uerror("Failed to %s" % msg)
					uexception(e)
					raise

	def print_files(self, paths):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		lp = ''
		ks = list(paths.keys())
		ks.sort()
		for n in ks:
			f = paths[n]
			tp = os.path.dirname(f.path)
			if tp != lp:
				lp = tp

			tz += f.size
			if f.folder:
				uprint(u"== %s ==" % (f.path))
			elif f.parent and f.parent != '/' and f.path[0] != '?':
				uprint(u"    %-40s  %8d  %s" % (f.name, f.size, f.mdate.strftime('%Y-%m-%dT%H:%M:%S')))
			else:
				uprint(u"%-44s  %8d  %s" % (f.path, f.size, f.mdate.strftime('%Y-%m-%dT%H:%M:%S')))

		uprint("--------------------------------------------------------------------------------")
		uprint("Total %d items (%d)" % (len(paths), tz))
	
	def print_updates(self, files):
		if files:
			uprint("--------------------------------------------------------------------------------")
			uinfo("Files to be synchronized:")
			for f in files:
				uprint("%s: %s  [%d] (%s) %s" % (f.action, f.path, f.size, str(f.mdate), f.reason))

	def print_skips(self, files):
		if photos:
			uprint("--------------------------------------------------------------------------------")
			uprint("Skipped files:")
			for f in files:
				uprint("%s: %s  [%s] (%s) %s" % (f.action, f.path, szstr(f.fsize), str(f.mdate), f.reason))

	def unknown_files(self, unknowns):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		for f in unknowns.values():
			tz += f.size
			uprint(u"%s %-44s  %8d  %s %s" % ('=' if f.folder else ' ', f.name, f.size, f.mdate.strftime('%Y-%m-%dT%H:%M:%S'), f.owner))

		uprint("--------------------------------------------------------------------------------")
		uprint("Unknown %d items (%d)" % (len(unknowns), tz))
	
	def get(self, fid):
		api = self.service.files().get(fileId=fid)
		r = self.exea(api, "get")
		uprint(str(r))
		
	def tree(self, verb = False):
		uinfo('Get remote folders ...')
		return self._list("mimeType = 'application/vnd.google-apps.folder' and trashed = false", verb)

	def list(self, verb = False, unknown = False):
		uinfo('Get remote files ...')
		return self._list('trashed = false', verb, unknown)

	def _list(self, query, verb, unknown = False):
		files = {}
		unknowns = {}

		page_token = None
		param = { 'maxResults': 1000, 'q': query }
		while True:
			if page_token:
				param['pageToken'] = page_token
			rs = self.exea(self.service.files().list(**param), "list")
	
			for r in rs['items']:
#				uprint("-------------")
#				uprint(str(r))
				f = GFile(r)
				
				# ignore unarchived SHARED files
				if f.parent == 'UNKNOWN':
					unknowns[f.id] = f
					continue
				
				# ignore online google docs
				if not f.folder and not f.url:
					unknowns[f.id] = f
					continue

				files[f.id] = f

			page_token = rs.get('nextPageToken')
			if not page_token:
				break

#		for f in files.itervalues():
#			if verb:
#				uprint("%s %s  %s" % (f.id, f.name, f.parent))

		self.rfiles = {}
		self.rpaths = {}
		if files:
			for k,f in files.items():
				p = self.get_path(files, f)
				if p[0] == '?':
					unknowns[f.id] = f
					continue
			
				if not self.accept_path(p):
					continue
				
				self.rfiles[f.id] = f
				self.rpaths[p] = f

			if verb:
				self.print_files(self.rpaths)

		if verb and unknown and unknowns:
			self.unknown_files(unknowns)

	def get_path(self, files, f):
		p = u'/' + f.name
		i = f
		while i.parent:
			i = files.get(i.parent)
			if i is None:
				p = u'?' + p
				break
			p = u'/' + i.name + p
		f.path = p
		f.npath = os.path.abspath(config.root_dir + p)
		return p

	def accept_path(self, path):
		"""
		Return if name matches any of the ignore patterns.
		"""
		if config.excludes:
			for pat in config.excludes:
				if fnmatch.fnmatch(path, pat):
					return False
		
		if config.includes:
			for pat in config.includes:
				if fnmatch.fnmatch(path, pat):
					return True
			return False

		return True

	"""
	get all files in folders and subfolders
	"""
	def scan(self, verbose = False):
		rootdir = config.root_dir

		uinfo('Scan local files %s ...' % rootdir)
		
		lpaths = {}
		for dirpath, dirnames, filenames in os.walk(rootdir, topdown=True, followlinks=True):
			# do not walk into unacceptable directory
			dirnames[:] = [d for d in dirnames if not d[0] == '.' and self.accept_path(os.path.normpath(os.path.join(dirpath, d))[len(rootdir):].replace('\\', '/'))]

			for d in dirnames:
				np = os.path.normpath(os.path.join(dirpath, d))
				rp = np[len(rootdir):].replace('\\', '/')
				if not self.accept_path(rp):
					continue

				gf = GFile()
				gf.folder = True
				gf.name = d
				gf.parent = os.path.dirname(rp)
				gf.npath = np
				gf.path = normpath(rp)
				gf.size = 0
				gf.mdate = mtime(np)
				gf.mime ='application/vnd.google-apps.folder'
				lpaths[gf.path] = gf

			for f in filenames:
				if f[0] == '.':
					continue

				np = os.path.normpath(os.path.join(dirpath, f))
				rp = np[len(rootdir):].replace('\\', '/')
				if not self.accept_path(rp):
					continue

				gf = GFile()
				gf.folder = False
				gf.name = f
				gf.parent = os.path.dirname(rp)
				gf.npath = np
				gf.path = normpath(rp)
				gf.size = os.path.getsize(np)
				gf.mdate = mtime(np)
				ext = os.path.splitext(f)[1]
				gf.mime = mimetypes.types_map.get(ext, 'application/octet-stream')
				lpaths[gf.path] = gf

		self.lpaths = lpaths
		
		if verbose:
			self.print_files(lpaths)


	"""
	find remote patch files
	"""
	def find_remote_patches(self):
		lps = []
		for lp,lf in self.lpaths.items():
			if lf.folder:
				continue

			# check patchable
			rf = self.rpaths.get(lp)
			if rf and lf.size == rf.size and math.fabs(tseconds(lf.mdate - rf.mdate)) > 2:
				lf.action = '^~'
				lf.reason = '| <> R:' + str(rf.mdate)
				lps.append(lp)

		lps.sort()
		ufiles = [ ]
		for lp in lps:
			ufiles.append(self.lpaths[lp])
		
		self.print_updates(ufiles)
		return ufiles

	"""
	find local touch files
	"""
	def find_local_touches(self):
		rps = []
		for rp,rf in self.rpaths.items():
			if rf.folder:
				continue

			# check touchable
			lf = self.lpaths.get(rp)
			if lf and lf.size == rf.size and math.fabs(tseconds(rf.mdate - lf.mdate)) > 2:
				rf.action = '>~'
				rf.reason = '| <> L:' + str(lf.mdate)
				rps.append(rp)

		rps.sort()
		ufiles = [ ]
		for rp in rps:
			ufiles.append(self.rpaths[rp])
		
		self.print_updates(ufiles)
		return ufiles

	"""
	find local updated files
	"""
	def find_local_updates(self, lastsync = None, force = False):
		lps = []
		for lp,lf in self.lpaths.items():
			if lf.folder:
				# skip for SYNC
				if lastsync:
					continue
				
				# check remote dir exists
				rf = self.rpaths.get(lp)
				if rf:
					continue
				lf.action = '^/'
			else:
				# check updateable
				rf = self.rpaths.get(lp)
				if rf:
					if tseconds(lf.mdate - rf.mdate) <= 2:
						if not force or lf.size == rf.size:
							continue
					lf.action = '^*'
					lf.reason = '| > R:' + str(rf.mdate)
				elif lastsync:
					if tseconds(lf.mdate - lastsync) > 2:
						lf.action = '^+'
					else:
						lf.action = '>-'
				else:
					lf.action = '^+'

			lps.append(lp)

		lps.sort()
		ufiles = [ ]
		for lp in lps:
			ufiles.append(self.lpaths[lp])
		
		# force to trash remote items that does not exist in local
		if force:
			# trash remote files
			for rp,rf in self.rpaths.items():
				if not rf.folder and not rp in self.lpaths:
					rf.action = '^-'
					ufiles.append(rf)

			# trash remote folders
			rps = []
			for rp,rf in self.rpaths.items():
				if rf.folder and not rp in self.lpaths:
					rf.action = '^-'
					rps.append(rp)

			rps.sort(reverse=True)
			for rp in rps:
				ufiles.append(self.rpaths[rp])
			
		self.print_updates(ufiles)
		return ufiles

	"""
	find remote updated files
	"""
	def find_remote_updates(self, lastsync = None, force = False):
		rps = []
		for rp,rf in self.rpaths.items():
			if rf.folder:
				# skip for SYNC
				if lastsync:
					continue
				
				# check local dir exists
				lf = self.lpaths.get(rp)
				if lf:
					continue
				rf.action = '>/'
			else:
				# check updateable
				lf = self.lpaths.get(rp)
				if lf:
					if tseconds(rf.mdate - lf.mdate) <= 2:
						if not force or lf.size == rf.size:
							continue
					rf.action = '>*'
					rf.reason = '| > L:' + str(lf.mdate)
				elif lastsync:
					if tseconds(rf.mdate - lastsync) > 2:
						rf.action = '>+'
					else:
						rf.action = '^-'
				else:
					rf.action = '>+'

			rps.append(rp)

		rps.sort()
		ufiles = [ ]
		for rp in rps:
			ufiles.append(self.rpaths[rp])
		
		
		# force to trash local items that does not exist in remote
		if force:
			# trash local files
			for lp,lf in self.lpaths.items():
				if not lf.folder and not lp in self.rpaths:
					lf.action = '>-'
					ufiles.append(lf)

			# delete local folders
			lps = []
			for lp,lf in self.lpaths.items():
				if lf.folder and not lp in self.rpaths:
					lf.action = '>!'
					lps.append(lp)
			
			lps.sort(reverse=True)
			for lp in lps:
				ufiles.append(self.lpaths[lp])

		self.print_updates(ufiles)
		return ufiles

	"""
	find synchronizeable files
	"""
	def find_sync_files(self):
		lfiles = self.find_local_updates(config.last_sync)
		rfiles = self.find_remote_updates(config.last_sync)

		sfiles = lfiles + rfiles
		spaths = {}
		for sf in sfiles:
			if sf.path in spaths:
				raise Exception('Duplicated sync file: %s' % sf.path)
			spaths[sf.path] = sf
			
		return sfiles

	def sync_files(self, sfiles):
		i = 0
		t = len(sfiles)
		for sf in sfiles:
			i += 1
			self.prog = '[%d/%d]' % (i, t)
			if sf.action == '^-':
				self.trash_remote_file(sf)
			elif sf.action == '^*':
				rf = self.rpaths[sf.path]
				self.update_remote_file(rf, sf)
			elif sf.action == '^+':
				pf = self.make_remote_dirs(os.path.dirname(sf.path))
				self.insert_remote_file(pf, sf)
			elif sf.action == '^/':
				self.make_remote_dirs(sf.path)
			elif sf.action == '^~':
				rf = self.rpaths[sf.path]
				self.patch_remote_file(rf, sf.mdate)
			elif sf.action in ('>*', '>+'):
				self.download_remote_file(sf)
			elif sf.action == '>/':
				self.create_local_dirs(sf)
			elif sf.action == '>-':
				self.trash_local_file(sf)
			elif sf.action == '>!':
				self.remove_local_file(sf)
			elif sf.action == '>~':
				lf = self.lpaths[sf.path]
				self.touch_local_file(lf, sf.mdate)

		self.print_skips(self.skips)

	def upload_files(self, lfiles):
		self.sync_files(lfiles)

	def dnload_files(self, rfiles):
		self.sync_files(rfiles)

	def touch_files(self, pfiles):
		self.sync_files(pfiles)

	def patch_files(self, pfiles):
		self.sync_files(pfiles)

	def patch(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()

		pfiles = self.find_remote_patches()
		if pfiles:
			if not noprompt:
				ans = raw_input("Are you sure to patch %d remote files? (Y/N): " % (len(pfiles)))
				if ans.lower() != "y":
					return
			self.patch_files(pfiles)
			uprint("--------------------------------------------------------------------------------")
			uinfo("PATCH Completed!")
		else:
			uinfo('No files need to be patched.')

	def touch(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()

		pfiles = self.find_local_touches()
		if pfiles:
			if not noprompt:
				ans = raw_input("Are you sure to touch %d local files? (Y/N): " % (len(pfiles)))
				if ans.lower() != "y":
					return
			self.touch_files(pfiles)
			uprint("--------------------------------------------------------------------------------")
			uinfo("TOUTH Completed!")
		else:
			uinfo('No files need to be touched.')

	def push(self, force = False, noprompt = False):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are in folders and not in remote
		ufiles = self.find_local_updates(None, force)
		
		if ufiles:
			if not noprompt:
				ans = raw_input("Are you sure to push %d files to Google Drive? (Y/N): " % len(ufiles))
				if ans.lower() != "y":
					return

			self.upload_files(ufiles)
			if force:
				self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("PUSH %s Completed!" % ('(FORCE)' if force else ''))
		else:
			uinfo('No files need to be uploaded to remote server.')

	def pull(self, force = False, noprompt = False):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are in folders and not in remote
		dfiles = self.find_remote_updates(None, force)
		
		if dfiles:
			if not noprompt:
				ans = raw_input("Are you sure to pull %d files to local? (Y/N): " % len(dfiles))
				if ans.lower() != "y":
					return

			self.dnload_files(dfiles)
			if force:
				self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("PULL %s Completed!" % ('(FORCE)' if force else ''))
		else:
			uinfo('No files need to be downloaded to local.')

	def sync(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are need to be sync
		sfiles = self.find_sync_files()
		
		if sfiles:
			if not noprompt:
				ans = raw_input("Are you sure to sync %d files? (Y/N): " % len(sfiles))
				if ans.lower() != "y":
					return
			self.sync_files(sfiles)
			self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("SYNC Completed!")
		else:
			self.up_to_date()
			uinfo('No files need to be synchronized.')


	def up_to_date(self):
		touch(config.token_file)

	def to_gfile(self, r):
		f = GFile(r)
		
		self.rfiles[f.id] = f
		self.get_path(self.rfiles, f)
		self.rpaths[f.path] = f
		
		return f
		
	def create_remote_folder(self, path, title, pid = None):
		'''
		Create a folder with title under a parnet folder with parent_id.
		'''
		uinfo("%s ^CREATE^ %s" % (self.prog, path))

		params = { 'title': title, 'mimeType': 'application/vnd.google-apps.folder' }
		if pid:
			params['parents'] = [{'id': pid}]
		a = self.service.files().insert(body=params)
		r = self.exea(a, 'create_remote_folder')
		
		f = self.to_gfile(r)
		return f

	def make_remote_dirs(self, path):
		rf = self.rpaths.get(path)
		if rf:
			return rf

		dirs = [i for i in path.strip().split('/') if i]
		p = ''
		f = None
		for d in dirs:
			p += '/' + d
			tf = self.rpaths.get(p)
			if tf:
				f = tf
			else:
				f = self.create_remote_folder(p, d, f.id if f else None)

		return f
	
	def trash_remote_file(self, file):
		"""
		Move a remote file to the trash.
		"""
		uinfo("%s ^TRASH^  %s [%d] (%s)" % (self.prog, file.path, file.size, str(file.mdate)))

		self.exea(self.service.files().trash(fileId=file.id), 'trash')
		self.rfiles.pop(file.id, file)
		self.rpaths.pop(file.path, file)

	def insert_remote_file(self, pf, lf):
		if lf.size > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to upload %s, File size [%s] exceed the limit" % (self.prog, lf.path, szstr(lf.size)))
			return

		'''
		Insert a file to google drive.
		'''
		uinfo("%s ^UPLOAD^ %s [%d] (%s)" % (self.prog, lf.path, lf.size, str(lf.mdate)))

		media_body = MediaFileUpload(lf.npath, lf.mime, resumable=True if lf.size > SMALL else False)
		body = { 'title': lf.name, 'modifiedDate': utime(lf.mdate) }
		if pf:
			body['parents'] = [{'id': pf.id}]
		
		a = self.service.files().insert(body=body, media_body=media_body)
		r = self.exea(a, 'insert')
		f = self.to_gfile(r)
		return f

	def update_remote_file(self, rf, lf):
		if lf.size > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to upload %s, File size [%s] exceed the limit" % (self.prog, lf.path, szstr(lf.size)))
			return

		'''
		Update a file to google drive.
		'''
		uinfo("%s ^UPDATE^ %s [%d] (%s)" % (self.prog, rf.path, lf.size, str(lf.mdate)))

		media_body = MediaFileUpload(rf.npath, rf.mime, resumable=True if lf.size > SMALL else False)
		body = { 'title': rf.name, 'modifiedDate': utime(lf.mdate) }
		if rf.parent:
			body['parents'] = [{'id': rf.parent}]

		a = self.service.files().update(fileId=rf.id, body=body, media_body=media_body, newRevision=True, setModifiedDate=True)
		r = self.exea(a, 'update')
		f = self.to_gfile(r)
		return f

	def download_remote_file(self, rf):
		uinfo("%s >DNLOAD> %s [%d] (%s)" % (self.prog, rf.path, rf.size, str(rf.mdate)))
		
		mkpdirs(rf.npath)

		if rf.size == 0:
			with open(rf.npath, "wb") as f:
				pass
		else:
			api = GFileDownloader(self.service, rf)
			self.exea(api, "download")
		
		touch(rf.npath, rf.mdate)

	def patch_remote_file(self, rf, mt):
		'''
		Patch a remote file.
		'''
		uinfo("%s ^PATCH^  %s [%d] (%s)" % (self.prog, rf.path, rf.size, str(mt)))

		body = { 'modifiedDate': utime(mt) }
		api = self.service.files().patch(fileId=rf.id, body=body, setModifiedDate=True, fields='modifiedDate')
		self.exea(api, 'patch')
		rf.mdate = mt
		return rf

	def touch_local_file(self, lf, mt):
		'''
		Touch a local file.
		'''
		uinfo("%s >TOUTH>  %s [%d] (%s)" % (self.prog, lf.path, lf.size, str(mt)))

		ft = ftime(mt)
		os.utime(lf.npath, (ft, ft))

		lf.mdate = mt
		return lf

	def create_local_dirs(self, file):
		np = file.npath
		if os.path.exists(np):
			return

		uinfo("%s >CREATE> %s" % (self.prog, file.path))
		os.makedirs(np)

	def trash_local_file(self, lf):
		if config.trash_dir:
			uinfo("%s >TRASH>  %s" % (self.prog, lf.path))
	
			np = config.trash_dir + lf.path
			mkpdirs(np)
			
			if os.path.exists(np):
				os.remove(np)
			
			shutil.move(lf.npath, np)
		else:
			uinfo("%s >REMOVE>  %s" % (self.prog, lf.path))
			os.remove(lf.npath)

	def remove_local_file(self, lf):
		uinfo("%s >REMOVE> %s" % (self.prog, lf.path))

		np = lf.npath
		if os.path.exists(np):
			os.rmdir(np)

def help():
	print("GDriveSync.py <command> ...")
	print("  <command>: ")
	print("    help                print command usage")
	print("    get <id>            print remote file info")
	print("    tree                list remote folders")
	print("    list [all]          list [all] remote files")
	print("    scan                scan local files")
	print("    pull [go] [force]   download remote files")
	print("      [force]           force to update file whose size is different")
	print("                        force to trash file that not exists in remote")
	print("      [go]              no confirm (always yes)")
	print("    push [go] [force]   upload local files")
	print("      [force]           force to update file whose size is different")
	print("                        force to trash file that not exists in local")
	print("    sync [go]           synchronize local <--> remote files")
	print("    touch [go]          set local file's modified date by remote")
	print("    patch [go]          set remote file's modified date by local")
	print("    drop                delete all remote files")
	print("")
	print("  <marks>: ")
	print("    ^-: trash remote file")
	print("    ^*: update remote file")
	print("    ^+: add remote file")
	print("    ^/: add remote folder")
	print("    ^~: patch remote file timestamp")
	print("    >*: update local file")
	print("    >+: add local file")
	print("    >/: add local folder")
	print("    >-: trash local file")
	print("    >!: remove local file")
	print("    >~: touch local file timestamp")

"""
Initial entry point for the uploads
"""
def main(args):
	global LOG

	LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
	logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

	rlog = logging.getLogger('')
	rlog.handlers = [ logging.NullHandler() ]

	dbglog = config.debug_log
	if dbglog:
		debugs = logging.FileHandler(dbglog)
		debugs.setLevel(logging.DEBUG)
		debugs.setFormatter(logging.Formatter(LOG_FORMAT))
		rlog.addHandler(debugs)
		
	errlog = config.error_log
	if errlog:
		errors = logging.FileHandler(errlog)
		errors.setLevel(logging.ERROR)
		errors.setFormatter(logging.Formatter(LOG_FORMAT))
		rlog.addHandler(errors)

	LOG = logging.getLogger("gdrivesync")
	LOG.setLevel(logging.INFO)
#	logh = logging.StreamHandler()
#	logh.setFormatter(logging.Formatter(LOG_FORMAT))
#	LOG.addHandler(logh)

	cmd = ''
	if len(args) > 0:
		cmd = args[0]

	if cmd == 'help':
		help()
		exit(0)

	uinfo('Start...')

	gc = GoogleCredentials()
	service = gc.get_service()
	gs = GDriveSync(service)
	
	opt1 = '' if len(args) < 2 else args[1]

	if cmd == 'get':
		gs.get(opt1)
	elif cmd == 'list':
		all = False
		idx = 1
		while (idx < len(args)):
			opt = args[idx]
			idx += 1
			if len(opt) < 1:
				continue
			if opt == 'all':
				all = True
				continue
			ch = opt[0]
			if ch == '+':
				config.includes = opt[1:].split()
			elif ch == '-':
				config.excludes = opt[1:].split()
		gs.list(True, all)
	elif cmd == 'tree':
		idx = 1
		while (idx < len(args)):
			opt = args[idx]
			idx += 1
			if len(opt) < 1:
				continue
			ch = opt[0]
			if ch == '+':
				config.includes = opt[1:].split()
			elif ch == '-':
				config.excludes = opt[1:].split()
		gs.tree(True)
	elif cmd == 'scan':
		gs.scan(True)
	elif cmd == 'drop':
		gs.drop(True if 'go' in args else False)
	elif cmd == 'push':
		gs.push(True if 'force' in args else False, True if 'go' in args else False)
	elif cmd == 'pull':
		gs.pull(True if 'force' in args else False, True if 'go' in args else False)
	elif cmd == 'sync':
		gs.sync(opt1)
	elif cmd == 'patch':
		gs.patch(True if 'go' in args else False)
	elif cmd == 'touch':
		gs.touch(True if 'go' in args else False)
	else:
		help()


if __name__ == "__main__":
	main(sys.argv[1:])

