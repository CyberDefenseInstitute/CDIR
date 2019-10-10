/*
 * Copyright(C) 2019 Cyber Defense Institute, Inc.
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "stdafx.h"

#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <vector>
#include <utility>
#include <algorithm>
#include <userenv.h>
#include <shlwapi.h>

#include "CDIR.h"
#include "util.h"
#include "globals.h"
#include "WriteWrapper.h"

#include "openssl\sha.h"
#include "openssl\md5.h"

#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto-41.lib")
#pragma comment(lib, "UserEnv.lib")
#pragma comment(lib, "shlwapi.lib")

#define CHUNKSIZE 262144
#define BLOCKSIZE 4096

using namespace std;

typedef FileInfo_t* (__cdecl *StealthOpenFile_func)(char*);
typedef int(__cdecl *StealthReadFile_func)(FileInfo_t*, BYTE*, DWORD, ULONGLONG, DWORD*, ULONGLONG*, ULONGLONG);
typedef void(__cdecl *StealthCloseFile_func)(FileInfo_t*);

StealthOpenFile_func  StealthOpenFile;
StealthReadFile_func  StealthReadFile;
StealthCloseFile_func StealthCloseFile;

string WriteWrapper::address;
int WriteWrapper::port;
string WriteWrapper::proxy_address;
int WriteWrapper::proxy_port;
string WriteWrapper::path;
string WriteWrapper::uriroot;
bool WriteWrapper::useProxy;
string WriteWrapper::curdir = "";
int WriteWrapper::status = 0;

bool param_memdump = true,
param_mftdump = true,
param_securedump = true,
param_usndump = true,
param_evtxdump = true,
param_prefdump = true,
param_regdump = true,
param_webdump = true,
param_wmidump = true,
param_srumdump = true;

string param_output;

char osvolume[3], usrvolume[3];
char sysdir[MAX_PATH + 1], sysdir_old[MAX_PATH + 1], usrdir[MAX_PATH + 1], windir[MAX_PATH + 1], windir_old[MAX_PATH + 1];
char backupdir[MAX_PATH + 1], curdir[MAX_PATH + 1], exedir[MAX_PATH + 1], outdir[MAX_PATH + 1];

HMODULE hNTFSParserdll;

ConfigParser *config;


int launchprocess(char *cmdline, DWORD *status) {
	PROCESS_INFORMATION pi = {};
	STARTUPINFO si = {};

	if (cmdline == NULL) {
		return -1;
	}

	if (!CreateProcess(
		NULL,
		cmdline,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi)) {
		_perror("CreateProcess");
		return -1;
	}

	if (!CloseHandle(pi.hThread)) {
		_perror("CloseHandle");
		return -1;
	}

	*status = WaitForSingleObject(pi.hProcess, INFINITE);
	switch (*status) {
	case WAIT_FAILED:
		_perror("WAIT_FAILED");
		return -2;
	case WAIT_ABANDONED:
		_perror("WAIT_ABANDONED");
		return -2;
	case WAIT_OBJECT_0:
		break;
	case WAIT_TIMEOUT:
		_perror("WAIT_TIMEOUT");
		return -2;
	default:
		cerr << "wait code: " << *status << endl;
		_perror(" ");
		return -2;
	}

	if (!GetExitCodeProcess(pi.hProcess, status)) {
		_perror("GetExitCodeProcess");
		return -3;
	}

	if (!CloseHandle(pi.hProcess)) {
		_perror("CloseHandle");
		return -4;
	}

	return 0;
}

int CopyFileTime(char* src, char* dst) {
	WIN32_FILE_ATTRIBUTE_DATA w32ad;
	FILETIME ctime, atime, wtime;
	HANDLE hfile;

	if (src == NULL || dst == NULL) {
		return -1;
	}

	if (!GetFileAttributesEx(src, GetFileExInfoStandard, &w32ad)) {
		// _perror("GetFileAttributesEx");
		return -3;
	}

	ctime = w32ad.ftCreationTime;
	atime = w32ad.ftLastAccessTime;
	wtime = w32ad.ftLastWriteTime;

	if ((hfile = CreateFile(dst,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "(%s)", dst);
		_perror("CreateFile");
		return -2;
	}

	if (!SetFileTime(hfile, &ctime, &atime, &wtime)) {
		fprintf(stderr, "(%s) ", dst);
		_perror("SetFileTime");
		return -1;
	}
	if (!CloseHandle(hfile)) {
		_perror("CloseHandle");
		return -1;
	}

	return 0;
}

uint64_t get_filesize(char *fname) {
	uint64_t fsize = 0;
	WIN32_FILE_ATTRIBUTE_DATA w32ad;

	if (fname == NULL) {
		return -1;
	}

	if (!GetFileAttributesEx(fname, GetFileExInfoStandard, &w32ad)) {
		fprintf(stderr, "%s: ", fname);
		_perror("GetFileAttributesEx");
		return -1;
	}

	fsize = w32ad.nFileSizeHigh * ((uint64_t)MAXDWORD + 1) + w32ad.nFileSizeLow;

	return fsize;
}

int log_hash(char *targetfile, ostringstream *osslog = NULL) {

	FILE *stream;
	BYTE *buf = (BYTE*)malloc(sizeof(BYTE)*CHUNKSIZE);

	if (buf == NULL) {
		_perror("malloc");
		return -1;
	}

	SHA256_CTX sha256;
	SHA_CTX sha1;
	MD5_CTX md5;

	if (!(SHA256_Init(&sha256) && SHA1_Init(&sha1) && MD5_Init(&md5))) {
		fprintf(stderr, "failed to initialize hash context.\n");
		return -1;
	}

	if (fopen_s(&stream, targetfile, "rb") == 0) {
		while (fread(buf, 1, CHUNKSIZE, stream) == CHUNKSIZE) {
			if (!(SHA256_Update(&sha256, buf, CHUNKSIZE)
				&& SHA1_Update(&sha1, buf, CHUNKSIZE)
				&& MD5_Update(&md5, buf, CHUNKSIZE))) {
				fprintf(stderr, "failed to update hash context.\n");
				return -1;
			}
		}
		int remain_bytes = size_t(get_filesize(targetfile)) % CHUNKSIZE;
		if (remain_bytes > 0) {
			fread(buf, 1, remain_bytes, stream);
			if (!(SHA256_Update(&sha256, buf, remain_bytes)
				&& SHA1_Update(&sha1, buf, remain_bytes)
				&& MD5_Update(&md5, buf, remain_bytes))) {
				fprintf(stderr, "failed to update hash context.\n");
				return -1;
			}
		}
		free(buf);
		fclose(stream);
	}
	else {
		fprintf(stderr, "failed to open file.\n");
		return -1;
	}

	unsigned char md5hash[MD5_DIGEST_LENGTH];
	unsigned char sha1hash[SHA_DIGEST_LENGTH];
	unsigned char sha256hash[SHA256_DIGEST_LENGTH];

	if (!(SHA256_Final(sha256hash, &sha256) && SHA1_Final(sha1hash, &sha1) && MD5_Final(md5hash, &md5))) {
		fprintf(stderr, "failed to finalize hash context.\n");
		return -1;
	}

	*osslog << hexdump(md5hash, MD5_DIGEST_LENGTH) << "   ";
	*osslog << hexdump(sha1hash, SHA_DIGEST_LENGTH) << "   ";
	*osslog << hexdump(sha256hash, SHA256_DIGEST_LENGTH) << "   ";

	return 0;
}

int log_timestamp(char *targetfile, ostringstream *osslog = NULL) {

	WIN32_FILE_ATTRIBUTE_DATA w32ad;
	FILETIME ft_c, ft_a, ft_w;
	SYSTEMTIME st_c, st_a, st_w;
	char str_c[32], str_a[32], str_w[32];

	if (!GetFileAttributesEx(targetfile, GetFileExInfoStandard, &w32ad)) {
		_perror("GetFileAttributesEx");
	}
	else {
		ft_c = w32ad.ftCreationTime;
		ft_a = w32ad.ftLastAccessTime;
		ft_w = w32ad.ftLastWriteTime;

		FileTimeToSystemTime(&ft_c, &st_c);
		FileTimeToSystemTime(&ft_a, &st_a);
		FileTimeToSystemTime(&ft_w, &st_w);

		sprintf(str_c, "%d/%02d/%02d %02d:%02d:%02d", st_c.wYear, st_c.wMonth, st_c.wDay, st_c.wHour, st_c.wMinute, st_c.wSecond);
		sprintf(str_a, "%d/%02d/%02d %02d:%02d:%02d", st_a.wYear, st_a.wMonth, st_a.wDay, st_a.wHour, st_a.wMinute, st_a.wSecond);
		sprintf(str_w, "%d/%02d/%02d %02d:%02d:%02d", st_w.wYear, st_w.wMonth, st_w.wDay, st_w.wHour, st_w.wMinute, st_w.wSecond);

		*osslog << str_c << string(22 - string(str_c).size(), ' ');
		*osslog << str_a << string(22 - string(str_a).size(), ' ');
		*osslog << str_w << string(22 - string(str_w).size(), ' ');
	}

	return 0;

}

int StealthGetFile(char *filepath, char *outpath, ostringstream *osslog = NULL, BOOL SparseSkip = false) {
	//cerr << filepath << endl;

	if (!(StealthOpenFile && StealthReadFile && StealthCloseFile)) {
		fprintf(stderr, "NTFSParser functions could not be loaded.\n");
		__exit(EXIT_FAILURE);
	}

	if (filepath == NULL || outpath == NULL) {
		fprintf(stderr, "both filepath and outpath must not be NULL\n");
		return -1;
	}

	BYTE *buf = (BYTE*)malloc(sizeof(BYTE)*CHUNKSIZE);
	if (buf == NULL) {
		_perror("malloc");
		return -1;
	}
	DWORD bytesread = 0;
	ULONGLONG bytesleft = 0;
	ULONG64 offset = 0;

	FileInfo_t *file;
	if ((file = StealthOpenFile(filepath)) == NULL) {
		fprintf(stderr, "could not open file: %s\n", filepath);
		return -1;
	};

	ULONGLONG filesize = (ULONGLONG)file->data->GetDataSize();
	WriteWrapper wfile(outpath, filesize);

	SHA256_CTX sha256;
	SHA_CTX sha1;
	MD5_CTX md5;

	if (!(SHA256_Init(&sha256)
		&& SHA1_Init(&sha1)
		&& MD5_Init(&md5))) {
		fprintf(stderr, "failed to initialize hash context.\n");
		return -1;
	}

	uint64_t skipclusters = 0;
	if (SparseSkip) {
		CDataRunList *drlist = ((CAttrNonResident*)(file->data))->GetDataRunList();
		const DataRun_Entry *dr = drlist->FindFirstEntry();

		for (int i = 0; i < drlist->GetCount(); i++) {
			if (dr == NULL) {
				fprintf(stderr, "failed to find entry of DataRunList.\n");
				break;
			}
			if (dr->LCN == -1) {
				skipclusters += dr->Clusters;
			}
			else {
				break;
			}
			dr = drlist->FindNextEntry();
		}
		offset = skipclusters * file->volume->GetClusterSize();
	}

	char journalpath[MAX_PATH + 1];
	sprintf(journalpath, "\\$Extend\\$UsnJrnl:$J");
	char securitypath[MAX_PATH + 1];
	sprintf(securitypath, "\\$SECURE:$SDS");

	if (!WriteWrapper::isLocal() && !(SparseSkip && strlen(filepath) > 3 && strcmp(&(filepath[2]), journalpath) == 0)) { // if using WebDAV and reading file except UsnJrnl
		if (wfile.sendheader()) {
			fprintf(stderr, "failed to send header.\n");
			return -1;
		}
	}

	int atrnum = 0;
	do {
		int ret;

		if ((ret = StealthReadFile(file, buf, CHUNKSIZE, offset, &bytesread, &bytesleft, filesize)) != 0) {
			if (SparseSkip && strlen(filepath) > 3 && strcmp(&(filepath[2]), journalpath) == 0) {
				filesize -= offset;
				skipclusters = 0;
				file->data = (CAttrBase*)file->fileRecord->FindNextStream("$J", atrnum);
				if (file->data == NULL) {
					fprintf(stderr, "failed to find nextstream.\n");
					return -1;
				}
				atrnum++;
				CDataRunList *drlist = ((CAttrNonResident*)(file->data))->GetDataRunList();
				const DataRun_Entry *dr = drlist->FindFirstEntry();
				for (int i = 0; i < drlist->GetCount(); i++) {
					if (dr == NULL) {
						fprintf(stderr, "failed to find entry of DataRunList.\n");
						return -1;
					}
					if (dr->LCN == -1) {
						skipclusters += dr->Clusters;
					}
					else {
						break;
					}
					dr = drlist->FindNextEntry();
				}
				offset = skipclusters * file->volume->GetClusterSize();
				bytesleft = 1; // To continue loop
				continue;
			}
			else if (ret == 4 && offset < filesize) {
				filesize -= offset;
				if (strcmp(&(filepath[2]), securitypath) == 0)
					file->data = (CAttrBase*)file->fileRecord->FindNextStream("$SDS", atrnum);
				else
					file->data = (CAttrBase*)file->fileRecord->FindNextStream(0, atrnum);

				if (file->data == NULL) {
					fprintf(stderr, "failed to find nextstream.\n");
					return -1;
				}
				atrnum++;
				CDataRunList *drlist = ((CAttrNonResident*)(file->data))->GetDataRunList();
				offset = 0;
				bytesleft = 1; // To continue loop
				continue;
			}
			else if (ret == 3) {
				int adjustsize = CHUNKSIZE;
				adjustsize -= BLOCKSIZE;
				while (StealthReadFile(file, buf, adjustsize, offset, &bytesread, &bytesleft, filesize) == 3)
					adjustsize -= BLOCKSIZE;
			}
			else {
				_perror("Error reading file");
				printf("filename: %s, offset: %lld\n", filepath, offset);
				return ret;
			}
		}

		if (SparseSkip && skipclusters > 0 && file->volume->GetClusterSize() * skipclusters > offset) {
			offset += bytesread;
			continue;
		}

		if (!wfile.isLocal() && !wfile.isHeaderSent) { // in case of UsnJrnl, sending WebDAV header here
			if (wfile.sendheader(filesize - offset)) {
				fprintf(stderr, "failed to send header.\n");
				return -1;
			}
		}

		if (osslog) {
			if (!(SHA256_Update(&sha256, buf, bytesread)
				&& SHA1_Update(&sha1, buf, bytesread)
				&& MD5_Update(&md5, buf, bytesread))) {
				fprintf(stderr, "failed to update hash context.\n");
				return -1;
			}
		}
		if (wfile.write((char*)buf, bytesread) < 0) {
			fprintf(stderr, "failed to write file.\n");
			return -1;
		}
		offset += bytesread;
	} while (bytesleft > 0 && offset < filesize);

	wfile.close();

	free(buf);

	StealthCloseFile(file);

	if (WriteWrapper::isLocal()) {
		if (CopyFileTime(filepath, outpath)) {
			fprintf(stderr, "failed to copy filetime: %s\n", filepath);
		}
	}

	if (osslog) {

		log_timestamp(filepath, osslog);

		unsigned char md5hash[MD5_DIGEST_LENGTH];
		unsigned char sha1hash[SHA_DIGEST_LENGTH];
		unsigned char sha256hash[SHA256_DIGEST_LENGTH];

		if (!(SHA256_Final(sha256hash, &sha256)
			&& SHA1_Final(sha1hash, &sha1)
			&& MD5_Final(md5hash, &md5))) {
			fprintf(stderr, "failed to finalize hash context.\n");
			return -1;
		}

		*osslog << hexdump(md5hash, MD5_DIGEST_LENGTH);
		*osslog << "   ";
		*osslog << hexdump(sha1hash, SHA_DIGEST_LENGTH);
		*osslog << "   ";
		*osslog << hexdump(sha256hash, SHA256_DIGEST_LENGTH);
		*osslog << "   ";
		*osslog << filepath;
	}

	if (osslog)	*osslog << "\r\n";

	return 0;
}

int filecheck(char *path) {
	if (path == NULL) {
		return -1;
	}
	if (!PathFileExists(path)) {
		//		cerr << path << msg(" が見つかりませんでした.", " not found") << endl;
		return -1;
	}
	return 0;
}

int get_pagefilepath(char *ret) {
	if (ret == NULL) {
		return -1;
	}
	// get pagefile path from registry
	{
		HKEY hkey;
		DWORD vt, vs = 256;
		wchar_t value[256];

		if (RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
			NULL,
			KEY_READ,
			&hkey)) {
			_perror("RegOpenKeyEx");
			return -1;
		}

		if (RegQueryValueEx(
			hkey,
			"ExistingPageFiles",
			NULL,
			&vt,
			NULL,
			&vs)) {
			_perror("RegQueryValueEx");
			return -1;
		}

		if (vt == REG_MULTI_SZ && RegQueryValueEx(
			hkey,
			"ExistingPageFiles",
			0,
			&vt,
			(LPBYTE)value,
			&vs)) {
			_perror("RegQueryValueEx");
			return -1;
		}

		if (wcstombs(ret, value, 256) == (size_t)-1) {
			cerr << "failed to convert wcs to mbs." << endl;
			return -1;
		}

		if (RegCloseKey(hkey)) {
			_perror("RegCloseKey");
			return -1;
		}
	}
	return 0;
}

int get_memdump(bool is_x64, char *computername, char *pagefilepath) {
	// winpmem	
	char tmp[256];
	DWORD status;

	if (computername == NULL) {
		fprintf(stderr, "computername is NULL.\n");
		return -1;
	}
	if (config->isSet("MemoryDumpCmdline"))
		sprintf(tmp, "%s\\%s", exedir, (CASTVAL(string, config->getValue("MemoryDumpCmdline"))).c_str());
	else
		sprintf(tmp, "%s\\winpmem.exe -dd --output RAM_%s.aff4 -t", exedir, computername);

	if (launchprocess(tmp, &status)) {
		return -1;
	}

	// for pagefile.sys acquisition
	//	sprintf(tmp, "..\\winpmem.exe -dd -p %s -o RAM_%s.aff4 -t", pagefilepath + 4, computername);
	//	launchprocess(tmp);

	return 0;
}

int get_analysisdata_evtx(char *sysdir, char *dstdir, ostringstream *osslog = NULL) {
	char findpath[MAX_PATH + 1];
	char srcpath[MAX_PATH + 1];
	char dstpath[MAX_PATH + 1];

	sprintf(findpath, "%s\\winevt\\Logs\\*.evtx", sysdir);
	auto files = findfiles(string(findpath));

	for (auto file : files) {
		//uint64_t size = w32fd.nFileSizeHigh * ((uint64_t)MAXDWORD + 1) + w32fd.nFileSizeLow;
		//if (size == 69632)
		//	continue;
		sprintf(srcpath, "%s\\winevt\\Logs\\%s", sysdir, file.first.c_str());
		sprintf(dstpath, "%s\\%s", dstdir, file.first.c_str());
		if (StealthGetFile(srcpath, dstpath, osslog, false))
		{
			if (!WriteWrapper::isLocal())
				continue;
			// If SltealthGetFile failed and isLocal, then tried wevtutil - workaround
			char cmdline[1024];
			DWORD status;
			sprintf(cmdline, "wevtutil epl \"%s\" \"%s\" /lf", srcpath, dstpath);
			if (launchprocess(cmdline, &status))
				cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
			else { // hashing & logging
				if (!osslog)
					continue;

				if (WriteWrapper::isLocal()) {
					if (CopyFileTime(srcpath, dstpath)) {
						fprintf(stderr, "failed to copy filetime: %s\n", srcpath);
					}
				}

				log_timestamp(dstpath, osslog);
				log_hash(dstpath, osslog);
				*osslog << srcpath << " (wevtutil)";
				*osslog << "\r\n";
			}
		}
	}

	return 0;
}

int get_analysisdata_web(char *userpath, vector<string> users, string outdirbase, ostringstream *osslog = NULL) {
	for (auto user : users) {
		// Firefrox
		{
			string basepath = string(userpath) + "\\Users\\" + user + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\";
			auto profiles = findfiles(basepath + "*", false);
			char outdir[MAX_PATH + 1];
			if (!profiles.empty()) {
				snprintf(outdir, MAX_PATH + 1, "%s", (outdirbase + string("\\Firefox")).c_str());
				mkdir(outdir, false);
				for (auto _profile : profiles) {
					string profile = _profile.first;
					vector<string> histfiles = {
						"cookies.sqlite", "cookies.sqlite-shm", "cookies.sqlite-wal",
						"places.sqlite", "places.sqlite-shm", "places.sqlite-wal"
					};
					for (string _histfile : histfiles) {
						string histfile = basepath + profile + "\\" + _histfile;
						if (PathFileExists(histfile.c_str())) {
							string outpath = outdirbase + "\\Firefox\\" + user + "_" + profile + "_" + _histfile;
							if (StealthGetFile((char*)histfile.c_str(), (char*)outpath.c_str(), osslog, false)) {
								cerr << msg("取得失敗", "failed to save") << ": " << histfile << endl;
							}
						}
					}
				}
			}
		}

		// Chrome
		{
			string basepath = string(userpath) + "\\Users\\" + user + "\\AppData\\Local\\Google\\Chrome\\User Data\\";
			auto profiles = findfiles(basepath + "*", false);
			char outdir[MAX_PATH + 1];
			if (!profiles.empty()) {
				snprintf(outdir, MAX_PATH + 1, "%s", (outdirbase + string("\\Chrome")).c_str());
				mkdir(outdir, false);
				for (auto _profile : profiles) {
					string profile = _profile.first;
					string histfile = basepath + profile + "\\History";
					if (PathFileExists(histfile.c_str())) {
						string outpath = outdirbase + "\\Chrome\\" + user + "_" + profile + "_" + "History";
						if (StealthGetFile((char*)histfile.c_str(), (char*)outpath.c_str(), osslog, false)) {
							cerr << msg("取得失敗", "failed to save") << ": " << histfile << endl;
						}
					}
				}
			}
		}

		// IE >= 10 and Edge
		{
			string basepath = string(userpath) + "\\Users\\" + user + "\\AppData\\Local\\Microsoft\\Windows\\WebCache\\";
			auto files = findfiles(basepath + "*", false);
			char outdir[MAX_PATH + 1];
			if (!files.empty()) {
				snprintf(outdir, MAX_PATH + 1, "%s", (outdirbase + string("\\IE10_Edge")).c_str());
				mkdir(outdir, false);
				for (auto file : files) {
					string histfile = basepath + file.first;
					string outpath = outdirbase + "\\IE10_Edge\\" + user + "_" + file.first;
					if (StealthGetFile((char*)histfile.c_str(), (char*)outpath.c_str(), osslog, false)) {
						cerr << msg("取得失敗", "failed to save") << ": " << histfile << endl;
					}
				}
			}
		}
	}

	return 0;
}

int get_analysisdata(ostringstream *osslog = NULL) {
	// collect somefiles

	// order of collection
	// $MFT
	// $SECURE
	// $UsnJrnl:$J (skip beginning sparse data)
	// Evtx (%SystemRoot%\winevt\Logs)
	// Prefetch (C:\Windows\Prefetch)
	// Registry 
	// * C:\Windows\System32\config\
	//   * SAM, Security, Software, System
	// * %USERNAME%
	//   * ntuser.dat
	//   * Appdata\Roaming\UsrClass.dat
	// WMI (C:\Windows\System32\WBEM\Repository)
	// SRUM (C:\Windows\System32)
	// Web
	// * C:\Users\[user]\AppData\Roaming\Mozilla\Firefox\Profiles\
	//	* cookies.sqlite, places.sqlite
	// * C:\Users\[user]\AppData\Local\Google\Chrome\User Data\
	//  * History
	// * C:\Users\[user]\AppData\Local\Microsoft\Windows\WebCache\
	// 
	// pagefile.sys

	PVOID oldval = NULL;
	Wow64DisableWow64FsRedirection(&oldval);

	char findpath[MAX_PATH + 1];
	char filepath[MAX_PATH + 1];
	char srcpath[MAX_PATH + 1];
	char dstpath[MAX_PATH + 1];

	if (param_mftdump || param_securedump || param_usndump) {
		mkdir("NTFS");
	}

	if (param_mftdump == true) {
		// get MFT
		sprintf(srcpath, "%s\\$MFT", osvolume);
		sprintf(dstpath, "NTFS\\%c_$MFT", osvolume[0]);
		if (!StealthGetFile(srcpath, dstpath, osslog, false)) {
			cerr << msg("メタデータ 取得完了 ", "metadata is saved ") << srcpath << endl;
		}
		else {
			cerr << msg("メタデータ 取得失敗 ", "failed to save metadata ") << srcpath << endl;
		}

		if (osvolume[0] != usrvolume[0]) {
			sprintf(srcpath, "%s\\$MFT", usrvolume);
			sprintf(dstpath, "NTFS\\%c_$MFT", usrvolume[0]);
			if (!StealthGetFile(srcpath, dstpath, osslog, false)) {
				cerr << msg("メタデータ 取得完了 ", "metadata is saved ") << srcpath << endl;
			}
			else {
				cerr << msg("メタデータ 取得失敗 ", "failed to save metadata ") << srcpath << endl;
			}
		}
	}

	if (param_securedump == true) {

		sprintf(srcpath, "%s\\$SECURE:$SDS", osvolume);
		sprintf(dstpath, "NTFS\\%c_$SECURE-$SDS", usrvolume[0]);
		if (!StealthGetFile(srcpath, dstpath, osslog, false)) {
			cerr << msg("セキュリティ 取得完了 ", "$SECURE:$SDS is saved ") << srcpath << endl;
		}
		else {
			cerr << msg("セキュリティ 取得失敗 ", "failed to save $SECURE:$SDS ") << srcpath << endl;
		}
		if (osvolume[0] != usrvolume[0]) {
			sprintf(srcpath, "%s\\$SECURE:$SDS", osvolume);
			sprintf(dstpath, "NTFS\\%c_$SECURE-$SDS", usrvolume[0]);
			if (!StealthGetFile(srcpath, dstpath, osslog, false)) {
				cerr << msg("セキュリティ 取得完了 ", "$SECURE:$SDS is saved ") << srcpath << endl;
			}
			else {
				cerr << msg("セキュリティ 取得失敗 ", "failed to save $SECURE:$SDS ") << srcpath << endl;
			}
		}
	}

	if (param_usndump == true) {
		// get UsnJrnl	
		sprintf(srcpath, "%s\\$Extend\\$UsnJrnl:$J", osvolume);
		sprintf(dstpath, "NTFS\\%c_$UsnJrnl-$J", osvolume[0]);

		StealthGetFile(srcpath, dstpath, osslog, true);

		if (WriteWrapper::isLocal()) {
			if (!get_filesize(dstpath)) {
				if (!StealthGetFile(srcpath, dstpath, osslog, false)) {
					cerr << msg("ジャーナル 取得完了 ", "journal is saved ") << srcpath << endl;
				}
				else {
					cerr << msg("ジャーナル 取得失敗 ", "failed to save journal ") << srcpath << endl;
				}
			}
			else {
				cerr << msg("ジャーナル 取得完了 ", "journal is saved ") << srcpath << endl;
			}
		}
		else {
			cerr << msg("ジャーナル 取得完了 ", "journal is saved ") << srcpath << endl;
		}

		sprintf(srcpath, "%s\\$Extend\\$UsnJrnl:$J", usrvolume);
		sprintf(dstpath, "NTFS\\%c_$UsnJrnl-$J", usrvolume[0]);

		if (osvolume[0] != usrvolume[0] && PathFileExists(srcpath)) {
			StealthGetFile(srcpath, dstpath, osslog, true);

			if (WriteWrapper::isLocal()) {
				if (!get_filesize(dstpath)) {
					if (!StealthGetFile(srcpath, dstpath, osslog, false)) {
						cerr << msg("ジャーナル 取得完了 ", "journal is saved ") << srcpath << endl;
					}
					else {
						cerr << msg("ジャーナル 取得失敗 ", "failed to save journal ") << srcpath << endl;
					}
				}
				else {
					cerr << msg("ジャーナル 取得完了 ", "journal is saved ") << srcpath << endl;
				}
			}
			else {
				cerr << msg("ジャーナル 取得完了 ", "journal is saved ") << srcpath << endl;
			}
		}
	}

	if (param_evtxdump == true) {
		// get event logs		
		mkdir("Evtx");

		get_analysisdata_evtx(sysdir, "Evtx", osslog);
		cerr << msg("イベントログ 取得完了", "event log is saved") << endl;

		// Windows.old
		if (PathIsDirectory(backupdir)) {
			mkdir("Evtx_old");
			get_analysisdata_evtx(sysdir_old, "Evtx_old", osslog);
			cerr << msg("イベントログ 取得完了(Windows.old)", "event log is saved (Windows.old)") << endl;
		}

	}

	if (param_prefdump == true) {
		// get prefetch files
		mkdir("Prefetch");

		sprintf(findpath, "%s\\Prefetch\\*", windir);
		auto files = findfiles(string(findpath));
		bool flag = false;
		for (auto file : files) {
			if ( file.first.substr(file.first.length() - 3) == ".pf" ) {
				sprintf(srcpath, "%s\\Prefetch\\%s", windir, file.first.c_str());
				sprintf(dstpath, "Prefetch\\%s", file.first.c_str());
				if (StealthGetFile(srcpath, dstpath, osslog, false)) {
					cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
				}
				else {
					flag = true;
				}
			}
			// check if the file has ADS or not
			sprintf(filepath, "%s\\Prefetch\\%s", windir, file.first.c_str());
			auto strms = findstreams(filepath);
			if ( strms.size() > 0 ){
				for (auto strm : strms) {
					sprintf(srcpath, "%s\\Prefetch\\%s%s", windir, file.first.c_str(), strm.first.c_str());
					sprintf(dstpath, "Prefetch\\%s%s", file.first.c_str(), strm.first.c_str());
					if (StealthGetFile(srcpath, dstpath, osslog, false)) {
						cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
					}
					else {
						flag = true;
					}
				}
			}

		}

		if (flag) {
			cerr << msg("プリフェッチ 取得完了", "prefetch is saved") << endl;
		}
		else {
			cerr << msg("プリフェッチ 無し", "no prefetch found") << endl;
		}

		// Windows.old
		if (PathIsDirectory(backupdir)) {
			
			mkdir("Prefetch_old");
			sprintf(findpath, "%s\\Prefetch\\*", windir_old);
			auto files = findfiles(string(findpath));

			bool flag = false;

			for (auto file : files) {
				if ( file.first.substr(file.first.length() - 3) == ".pf" ) {
					sprintf(srcpath, "%s\\Prefetch\\%s", windir_old, file.first.c_str());
					sprintf(dstpath, "Prefetch_old\\%s", file.first.c_str());
					if (StealthGetFile(srcpath, dstpath, osslog, false)) {
						cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
					}
					else {
						flag = true;
					}
				}
				// check if the file has ADS or not
				sprintf(filepath, "%s\\Prefetch\\%s", windir_old, file.first.c_str());
				auto strms = findstreams(filepath);
				if (strms.size() > 0) {
					for (auto strm : strms) {
						sprintf(srcpath, "%s\\Prefetch\\%s%s", windir_old, file.first.c_str(), strm.first.c_str());
						sprintf(dstpath, "Prefetch_old\\%s%s", file.first.c_str(), strm.first.c_str());
						if (StealthGetFile(srcpath, dstpath, osslog, false)) {
							cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
						}
						else {
							flag = true;
						}
					}
				}
			}
			if (flag) {
				cerr << msg("プリフェッチ 取得完了(Windows.old)", "prefetch is saved (Windows.old)") << endl;
			}
			else {
				cerr << msg("プリフェッチ 無し(Windows.old)", "no prefetch found (Windows.old)") << endl;
			}
		}
	}

	// user list
	vector<string> users;
	{
		auto files = findfiles(string(usrvolume) + "\\Users\\*");
		for (auto file : files) {
			string fname = file.first;
			if (fname == "."
				|| fname == ".."
				|| fname == "Public"
				|| fname == "Default User"
				|| fname == "All Users"
				|| !file.second)
				continue;
			users.push_back(fname);
		}
	}

	if (param_regdump == true) {
		// get registry
		vector<string> paths = {
			"\\config\\SAM",
			"\\config\\SAM.LOG1",
			"\\config\\SAM.LOG2",
			"\\config\\SECURITY",
			"\\config\\SECURITY.LOG1",
			"\\config\\SECURITY.LOG2",
			"\\config\\SOFTWARE",
			"\\config\\SOFTWARE.LOG1",
			"\\config\\SOFTWARE.LOG2",
			"\\config\\SYSTEM",
			"\\config\\SYSTEM.LOG1",
			"\\config\\SYSTEM.LOG2"
		};
		vector<pair<string, string> > paths_pair;
		for (size_t i = 0; i < paths.size(); i++) {
			paths_pair.push_back(pair<string, string>(string(sysdir) + paths[i], "Registry\\" + basename(paths[i])));
		}

		// Amcache.hve
		paths_pair.push_back(pair<string, string>(string(windir) + "\\AppCompat\\Programs\\Amcache.hve", "Registry\\Amcache.hve"));
		paths_pair.push_back(pair<string, string>(string(windir) + "\\AppCompat\\Programs\\Amcache.hve.LOG1", "Registry\\Amcache.hve.LOG1"));
		paths_pair.push_back(pair<string, string>(string(windir) + "\\AppCompat\\Programs\\Amcache.hve.LOG2", "Registry\\Amcache.hve.LOG2"));

		for (size_t i = 0; i < users.size(); i++) {
			paths_pair.push_back(pair<string, string>(string(usrvolume) + "\\Users\\" + users[i] + "\\NTUSER.dat", "Registry\\" + users[i] + "_NTUSER.dat"));
			paths_pair.push_back(pair<string, string>(string(usrvolume) + "\\Users\\" + users[i] + "\\NTUSER.dat.LOG1", "Registry\\" + users[i] + "_NTUSER.dat.LOG1"));
			paths_pair.push_back(pair<string, string>(string(usrvolume) + "\\Users\\" + users[i] + "\\NTUSER.dat.LOG2", "Registry\\" + users[i] + "_NTUSER.dat.LOG2"));
			paths_pair.push_back(pair<string, string>(string(usrvolume) + "\\Users\\" + users[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "Registry\\" + users[i] + "_UsrClass.dat"));
			paths_pair.push_back(pair<string, string>(string(usrvolume) + "\\Users\\" + users[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1", "Registry\\" + users[i] + "_UsrClass.dat.LOG1"));
			paths_pair.push_back(pair<string, string>(string(usrvolume) + "\\Users\\" + users[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2", "Registry\\" + users[i] + "_UsrClass.dat.LOG2"));
		}

		mkdir("Registry");

		for (size_t i = 0; i < paths_pair.size(); i++) {
			char *srcpath, *dstpath;
			srcpath = strdup(paths_pair[i].first.c_str());
			dstpath = strdup(paths_pair[i].second.c_str());

			if (filecheck(srcpath)) {
				continue;
			}
			if (StealthGetFile(srcpath, dstpath, osslog, false)) {
				cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
			}
		}
		cerr << msg("レジストリ 取得完了", "registry is saved") << endl;

		// Windows.old
		if (PathIsDirectory(backupdir)) {
			vector<string> users_old;
			{
				auto files = findfiles(string(backupdir) + "\\Users\\*");
				for (auto file : files) {
					string fname = file.first;
					if (fname == "."
						|| fname == ".."
						|| fname == "Public"
						|| fname == "Default User"
						|| fname == "All Users"
						|| !file.second)
						continue;
					users_old.push_back(fname);
				}
			}

			paths_pair.erase(paths_pair.begin(), paths_pair.end());
			for (size_t i = 0; i < paths.size(); i++) {
				paths_pair.push_back(pair<string, string>(string(sysdir_old) + paths[i], "Registry_old\\" + basename(paths[i])));
			}

			// Amcache.hve
			paths_pair.push_back(pair<string, string>(string(windir_old) + "\\AppCompat\\Programs\\Amcache.hve", "Registry_old\\Amcache.hve"));
			paths_pair.push_back(pair<string, string>(string(windir_old) + "\\AppCompat\\Programs\\Amcache.hve.LOG1", "Registry_old\\Amcache.hve.LOG1"));
			paths_pair.push_back(pair<string, string>(string(windir_old) + "\\AppCompat\\Programs\\Amcache.hve.LOG2", "Registry_old\\Amcache.hve.LOG2"));

			for (size_t i = 0; i < users_old.size(); i++) {
				paths_pair.push_back(pair<string, string>(string(backupdir) + "\\Users\\" + users_old[i] + "\\NTUSER.dat", "Registry_old\\" + users_old[i] + "_NTUSER.dat"));
				paths_pair.push_back(pair<string, string>(string(backupdir) + "\\Users\\" + users_old[i] + "\\NTUSER.dat.LOG1", "Registry_old\\" + users_old[i] + "_NTUSER.dat.LOG1"));
				paths_pair.push_back(pair<string, string>(string(backupdir) + "\\Users\\" + users_old[i] + "\\NTUSER.dat.LOG2", "Registry_old\\" + users_old[i] + "_NTUSER.dat.LOG2"));
				paths_pair.push_back(pair<string, string>(string(backupdir) + "\\Users\\" + users_old[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "Registry_old\\" + users_old[i] + "_UsrClass.dat"));
				paths_pair.push_back(pair<string, string>(string(backupdir) + "\\Users\\" + users_old[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1", "Registry_old\\" + users_old[i] + "_UsrClass.dat.LOG1"));
				paths_pair.push_back(pair<string, string>(string(backupdir) + "\\Users\\" + users_old[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2", "Registry_old\\" + users_old[i] + "_UsrClass.dat.LOG2"));
			}

			mkdir("Registry_old");

			for (size_t i = 0; i < paths_pair.size(); i++) {
				char *srcpath, *dstpath;
				srcpath = strdup(paths_pair[i].first.c_str());
				dstpath = strdup(paths_pair[i].second.c_str());

				if (filecheck(srcpath)) {
					continue;
				}
				if (StealthGetFile(srcpath, dstpath, osslog, false)) {
					cerr << msg("取得失敗(Windows.old)", "failed to save (Windows.old)") << ": " << srcpath << endl;
				}
			}
			cerr << msg("レジストリ 取得完了(Windows.old)", "registry is saved (Windows.old)") << endl;
		}
	}

	if (param_wmidump == true) {
		// get WMI data
		mkdir("WMI");

		string basepath = string(sysdir) + "\\wbem\\Repository\\";
		auto files = findfiles(basepath + "*", false);

		for (auto file : files) {
			string srcpath = basepath + file.first;
			string dstpath = "WMI\\" + file.first;
			if (StealthGetFile((char*)srcpath.c_str(), (char*)dstpath.c_str(), osslog, false)) {
				cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
			}
		}
		cerr << msg("WMI 取得完了", "wmi data is saved") << endl;

		// Windows.old
		if (PathIsDirectory(backupdir)) {
			mkdir("WMI_old");

			basepath = string(sysdir_old) + "\\wbem\\Repository\\";
			files = findfiles(basepath + "*", false);

			for (auto file : files) {
				string srcpath = basepath + file.first;
				string dstpath = "WMI_old\\" + file.first;
				if (StealthGetFile((char*)srcpath.c_str(), (char*)dstpath.c_str(), osslog, false)) {
					cerr << msg("取得失敗(Windows.old)", "failed to save (Windows.old)") << ": " << srcpath << endl;
				}
			}
			cerr << msg("WMI 取得完了(Windows.old)", "wmi data is saved (Windows.old)") << endl;
		}
	}

	if (param_srumdump == true) {
		// get SRUM data
		mkdir("SRUM");

		string basepath = string(sysdir) + "\\sru\\";
		auto files = findfiles(basepath + "*", false);

		bool flag = false;
		for (auto file : files) {
			string srcpath = basepath + file.first;
			string dstpath = "SRUM\\" + file.first;
			if (StealthGetFile((char*)srcpath.c_str(), (char*)dstpath.c_str(), osslog, false)) {
				cerr << msg("取得失敗", "failed to save") << ": " << srcpath << endl;
			}
			else {
				flag = true;
			}
		}
		if (flag) {
			cerr << msg("SRUM 取得完了", "srum is saved") << endl;
		}
		else {
			cerr << msg("SRUM 無し", "no srum found") << endl;
		}

		// Windows.old
		if (PathIsDirectory(backupdir)) {
			mkdir("SRUM_old");

			basepath = string(sysdir_old) + "\\sru\\";
			files = findfiles(basepath + "*", false);

			flag = false;
			for (auto file : files) {
				string srcpath = basepath + file.first;
				string dstpath = "SRUM_old\\" + file.first;
				if (StealthGetFile((char*)srcpath.c_str(), (char*)dstpath.c_str(), osslog, false)) {
					cerr << msg("取得失敗(Windows.old)", "failed to save (Windows.old)") << ": " << srcpath << endl;
				}
				else {
					flag = true;
				}
			}
			if (flag) {
				cerr << msg("SRUM 取得完了(Windows.old)", "srum is saved (Windows.old)") << endl;
			}
			else {
				cerr << msg("SRUM 無し(Windows.old)", "no srum found (Windows.old)") << endl;
			}
		}
	}

	if (param_webdump == true) {
		// get webbrowser data
		mkdir("Web");

		get_analysisdata_web(usrvolume, users, string("Web"), osslog);
		cerr << msg("インターネット(Web) 取得完了", "internet artifact data is saved") << endl;

		if (PathIsDirectory(backupdir)) {
			mkdir("Web_old");
			get_analysisdata_web(backupdir, users, string("Web_old"), osslog);
			cerr << msg("インターネット(Web) 取得完了(Windows.old)", "internet artifact data is saved (Windows.old)") << endl;
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	bool is_x64;
	int input = 0;
	string procname;
	char dllpath[MAX_PATH + 1], foldername[MAX_PATH + 1], computername[MAX_COMPUTERNAME_LENGTH + 1], pagefilepath[MAX_PATH + 1], timestamp[15];
	char t_beg[32], t_end[32];
	DWORD dwsize = 256;

	time_t _t_beg, _t_end;
	uint64_t time_diff;
	struct tm *t;
	SYSTEM_INFO sysinfo;

	sprintf(dllpath, "%s\\NTFSParserDLL.dll", dirname(string(argv[0])).c_str());
	if ((hNTFSParserdll = LoadLibrary(dllpath)) == NULL) {
		_perror("could not load NTFSParserDLL.dll");
		__exit(EXIT_FAILURE);
	}

	StealthOpenFile = (StealthOpenFile_func)GetProcAddress(hNTFSParserdll, "StealthOpenFile");
	StealthReadFile = (StealthReadFile_func)GetProcAddress(hNTFSParserdll, "StealthReadFile");
	StealthCloseFile = (StealthCloseFile_func)GetProcAddress(hNTFSParserdll, "StealthCloseFile");

	if (((ULONG32)StealthOpenFile & (ULONG32)StealthReadFile & (ULONG32)StealthCloseFile) == NULL) {
		_perror("could not load some functions");
		__exit(EXIT_FAILURE);
	}

	// chack proces name
	procname = basename(string(argv[0]));
	cout << msg("CDIR Collector v1.3.4 - 初動対応用データ収集ツール", "CDIR Collector v1.3.4 - Data Acquisition Tool for First Response") << endl;
	cout << msg("Cyber Defense Institute, Inc.\n", "Cyber Defense Institute, Inc.\n") << endl;

	// set curdir -> exedir
	if (!GetModuleFileName(NULL, exedir, MAX_PATH)) {
		_perror("GetModuleFileName");
		__exit(EXIT_FAILURE);
	}
	PathRemoveFileSpec(exedir);

	if (!SetCurrentDirectory(exedir)) {
		_perror("SetCurrentDirectory:");
		__exit(EXIT_FAILURE);
	}

	// get config
	string confnames[2] = { std::string(exedir) + "\\cdir.ini", std::string(exedir) + "\\cdir.conf" };
	for (string confname : confnames) {
		config = new ConfigParser(confname);
		if (config && config->isOpened()) {
			cerr << msg(confname + "を読み込み中...", "Loading " + confname + "...") << endl;
			break;
		}
	}

	if (config->isOpened()) {
		// param, JP, EN
		vector<pair<vector<string>, void*>> params = {
			{{"MemoryDump", "メモリダンプ", "Memory dump"}, &param_memdump},
			{{"MFT", "MFT", "MFT"}, &param_mftdump},
			{{"Secure", "Secure", "Secure" }, &param_securedump},
			{{"UsnJrnl", "ジャーナル", "UsnJrnl"}, &param_usndump},
			{{"EventLog", "イベントログ", "Event log"}, &param_evtxdump},
			{{"Prefetch", "プリフェッチ", "Prefetch"}, &param_prefdump},
			{{"Registry", "レジストリ", "Registry"}, &param_regdump},
			{{"WMI", "WMI", "WMI"}, &param_wmidump},
			{{"SRUM", "SRUM", "SRUM" }, &param_srumdump},
			{{"Web", "ブラウザ", "Web"}, &param_webdump}
		};

		for (size_t i = 0; i < params.size(); i++) {
			string param, jp, en;
			param = params[i].first[0], jp = params[i].first[1], en = params[i].first[2];

			void *ptr = params[i].second;
			Value val = config->getValue(param);

			switch (CONFIGLIST[param]) {
			case TYPE_BOOL:
				CASTPTR(bool, ptr) = CASTVAL(bool, val);
				cerr << msg(jp + ": " + (CASTVAL(bool, val) ? "ON" : "OFF"), en + ": " + (CASTVAL(bool, val) ? "ON" : "OFF")) << endl;
				break;
			case TYPE_INT:
				CASTPTR(int, ptr) = CASTVAL(int, val);
				cerr << msg(jp + ": " + to_string(CASTVAL(int, val)), en + ": " + to_string(CASTVAL(int, val))) << endl;
				break;
			case TYPE_STRING:
				CASTPTR(string, ptr) = CASTVAL(string, val);
				cerr << msg(jp + ": " + CASTVAL(string, val), en + ": " + CASTVAL(string, val)) << endl;
				break;
			}
		}
	}


	// begin time
	if ((_t_beg = time(NULL)) == -1) {
		_perror("time");
		__exit(EXIT_FAILURE);
	}
	if ((t = localtime(&_t_beg)) == NULL) {
		_perror("localtime");
		__exit(EXIT_FAILURE);
	}
	if (!strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", t) || !strftime(t_beg, sizeof(t_beg), "%Y/%m/%d %H:%M:%S", t)) {
		_perror("strftime");
		__exit(EXIT_FAILURE);
	}


	// get PC info
	if (!GetComputerName(computername, &dwsize)) {
		cerr << msg("[エラー] コンピュータ名",
			"[ERROR] failed to get computer name.") << endl;
		__exit(EXIT_FAILURE);
	}
	if (!GetSystemDirectory(sysdir, MAX_PATH + 1)) {
		cerr << msg("[エラー] システムディレクトリ",
			"[ERROR] failed to get system directory") << endl;
		__exit(EXIT_FAILURE);
	}
	if (!GetWindowsDirectory(windir, MAX_PATH + 1)) {
		cerr << msg("[エラー] Windowsディレクトリ",
			"[ERROR] failed to get windows directory") << endl;
		__exit(EXIT_FAILURE);
	}
	else {
		strncpy(backupdir, windir, MAX_PATH + 1);
		strncat(backupdir, ".old", MAX_PATH + 1);

		strncpy(windir_old, backupdir, MAX_PATH + 1);
		strncat(windir_old, "\\Windows", MAX_PATH + 1);

		strncpy(sysdir_old, windir_old, MAX_PATH + 1);
		strncat(sysdir_old, "\\system32", MAX_PATH + 1);
	}
	dwsize = MAX_PATH;
	if (!GetProfilesDirectory(usrdir, &dwsize)) {
		cerr << msg("[エラー] Usersディレクトリ",
			"[ERROR] failed to get Users directory") << endl;
		__exit(EXIT_FAILURE);
	}
	if (!GetCurrentDirectory(MAX_PATH + 1, curdir)) {
		_perror("GetCurrentDirectory");
		__exit(EXIT_FAILURE);
	}

	strncpy(osvolume, sysdir, 2); // copy sys_drive letter
	strncpy(usrvolume, usrdir, 2); // copy usr_drive letter


	if (config->isSet("Target")) {
		strncpy(osvolume, (CASTVAL(string, config->getValue("Target"))).c_str(), 2);
		strncpy(usrvolume, (CASTVAL(string, config->getValue("Target"))).c_str(), 2);
		strncpy(sysdir, (CASTVAL(string, config->getValue("Target"))).c_str(), 2);
		strncpy(windir, (CASTVAL(string, config->getValue("Target"))).c_str(), 2);
		strncpy(backupdir, (CASTVAL(string, config->getValue("Target"))).c_str(), 2);
		cerr << "Target: " << osvolume << endl;
	}

	osvolume[sizeof(osvolume) - 1] = '\0'; // null terminate

	GetNativeSystemInfo(&sysinfo);
	if ((sysinfo.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64) || (sysinfo.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) == 64) {
		is_x64 = true;
	}
	else if (sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		is_x64 = false;
	}
	else {
		cerr << msg("[エラー] 対応していないアーキテクチャ",
			"[ERROR] Unsupported architecture.") << endl;
		__exit(EXIT_FAILURE);
	}

	if (config->isSet("Target"))
		sprintf(foldername, "%s_%c_%s", computername, osvolume[0], timestamp);
	else
		sprintf(foldername, "%s_%s", computername, timestamp);

	if (config->isSet("Output")) {
		if (!SetCurrentDirectory((CASTVAL(string, config->getValue("Output"))).c_str())) {
			cerr << msg("対応していない保存先です", "unsupported destination") << endl;
			// _perror("SetCurrentDirectory:");
			__exit(EXIT_FAILURE);
		}
	}

	mkdir(foldername);
	chdir(foldername);

	if (!GetCurrentDirectory(MAX_PATH + 1, outdir)) {
		_perror("GetCurrentDirectory");
		__exit(EXIT_FAILURE);
	}
	if (WriteWrapper::isLocal())
		cerr << msg("保存先: ", "Output Directory: ") << outdir << endl;

	// start logging
	ostringstream ossinfo, osslog;

	// start collecting
	//if (get_pagefilepath(pagefilepath)) {
	//	fprintf(stderr, "failed to get pagepath.\n");
	//}

	// memdump対応
	if (param_memdump) {
		char buf[MAX_PATH];
		if (!GetFullPathName(foldername, MAX_PATH, buf, NULL)) {
			_perror("GetFullPathName");
			__exit(EXIT_FAILURE);
		}

		bool flag = true;
		for (char c : buf) {
			if (c == '\0') break;
			if (!isascii(c)) {
				flag = false;
				break;
			}
		}
		if (flag) {
			for (char c : computername) {
				if (c == '\0') break;
				if (!isascii(c)) {
					flag = false;
					break;
				}
			}
		}
		if (!flag) {
			cerr << msg("パスに非ASCII文字列が含まれているため、メモリダンプは取得されません。",
				"Non ASCII character is included in path, so memory dump is not captured.") << endl;
			param_memdump = false;
		}
	}


	if (param_memdump) {
		if (!(config->isSet("MemoryDumpCmdline")) && filecheck((char*)((string)exedir + "\\winpmem.exe").c_str())) {
			cerr << msg("メモリダンプ用プログラムがありません",
				"No memory dump program found") << endl;
		}
		else {
			if (!get_memdump(is_x64, computername, pagefilepath)) {
				cerr << msg("メモリダンプ取得完了",
					"Finished collecting memory dump") << endl;
			}
			else {
				cerr << msg("メモリダンプ取得失敗",
					"Failed to collect memory dump") << endl;
			}
		}
	}

	cerr << msg("ディスク内データ 取得開始", "Start collecting data for analysis") << endl;
	if (!get_analysisdata(&osslog)) {
		cerr << msg("解析用データ取得完了", "Finished collecting data for analysis") << endl;
	}
	else {
		cerr << msg("解析用データ取得失敗", "Failed to collect data for analysis") << endl;
	}


	if (!FreeLibrary(hNTFSParserdll)) {
		_perror("FreeLibrary");
	}


	// end time
	if ((_t_end = time(NULL)) == -1) {
		_perror("time");
		__exit(EXIT_FAILURE);
	}
	if ((t = localtime(&_t_end)) == NULL) {
		_perror("localtime");
		__exit(EXIT_FAILURE);
	}
	if (!strftime(t_end, sizeof(t_end), "%Y/%m/%d %H:%M:%S", t)) {
		_perror("strftime");
		__exit(EXIT_FAILURE);
	}


	// output log
	ossinfo << msg("開始時刻: ", "Start   time: ") << t_beg << "\r\n";
	ossinfo << msg("終了時刻: ", "End     time: ") << t_end << "\r\n";
	ossinfo << msg("所要時間: ", "Elapsed time: ");
	time_diff = (uint64_t)difftime(_t_end, _t_beg);
	if (time_diff / (60 * 60)) {
		ossinfo << setfill('0') << setw(2) << (time_diff / (60 * 60)) << ":";
		time_diff %= (60 * 60);
	}
	else {
		ossinfo << "00:";
	}
	if (time_diff / 60) {
		ossinfo << setfill('0') << setw(2) << (time_diff / 60) << ":";
		time_diff %= 60;
	}
	else {
		ossinfo << "00:";
	}
	ossinfo << setfill('0') << setw(2) << time_diff << "\r\n";

	ossinfo << "\r\n";

	ossinfo << "CreationTime" << string(22 - string("CreationTime").size(), ' ');
	ossinfo << "AccessTime" << string(22 - string("AccessTime").size(), ' ');
	ossinfo << "WriteTime" << string(22 - string("WriteTime").size(), ' ');

	ossinfo << "MD5" << string(MD5_DIGEST_LENGTH * 2 - 3, ' ') << "   ";
	ossinfo << "SHA1" << string(SHA_DIGEST_LENGTH * 2 - 4, ' ') << "   ";
	ossinfo << "SHA256" << string(SHA256_DIGEST_LENGTH * 2 - 6, ' ') << "   ";
	ossinfo << "\r\n";
	ossinfo << string(19, '=') << "   ";
	ossinfo << string(19, '=') << "   ";
	ossinfo << string(19, '=') << "   ";
	ossinfo << string(MD5_DIGEST_LENGTH * 2, '=') << "   ";
	ossinfo << string(SHA_DIGEST_LENGTH * 2, '=') << "   ";
	ossinfo << string(SHA256_DIGEST_LENGTH * 2, '=') << "   ";
	ossinfo << "\r\n";
	ossinfo << osslog.str();

	string log_str = ossinfo.str();
	WriteWrapper log("collector-log.txt", log_str.size());
	if (log.sendfile(log_str.c_str())) {
		fprintf(stderr, "failed to save log");
	}
	log.close();
	__exit(EXIT_SUCCESS);
}