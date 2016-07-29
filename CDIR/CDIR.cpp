/*
 * Copyright(C) 2016 Cyber Defense Institute, Inc.
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

#include "CDIR.h"
#include "util.h"
#include "WriteWrapper.h"
#include "globals.h"

#include "openssl\sha.h"
#include "openssl\md5.h"

#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto-38.lib")

#define CHUNKSIZE 262144

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

bool memdump = true, mftdump = true, usndump = true, evtxdump = true, prefdump = true, regdump = true;

char osvolume[3], sysdir[MAX_PATH + 1], windir[MAX_PATH + 1];

HMODULE hNTFSParserdll;

ConfigParser *config;

int launchprocess(char *cmdline) {
	PROCESS_INFORMATION pi = {};
	STARTUPINFO si = {};

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
		__exit(EXIT_FAILURE);
	}

	if (!CloseHandle(pi.hThread)) {
		_perror("CloseHandle");
		__exit(EXIT_FAILURE);
	}

	DWORD ret = WaitForSingleObject(pi.hProcess, INFINITE);
	switch (ret) {
	case WAIT_FAILED:
		_perror("WAIT_FAILED");
		__exit(EXIT_FAILURE);
	case WAIT_ABANDONED:
		_perror("WAIT_ABANDONED");
		__exit(EXIT_FAILURE);
	case WAIT_OBJECT_0:
		break;
	case WAIT_TIMEOUT:
		_perror("WAIT_TIMEOUT");
		__exit(EXIT_FAILURE);
	default:
		fprintf(stderr, "wait code: %d", ret);
		_perror(" ");
		__exit(EXIT_FAILURE);
	}

	if (!GetExitCodeProcess(pi.hProcess, &ret)) {
		_perror("GetExitCodeProcess");
		__exit(EXIT_FAILURE);
	}

	return ret;
}

int CopyFileTime(char* src, char* dst) {
	WIN32_FILE_ATTRIBUTE_DATA w32ad;
	FILETIME ctime, atime, wtime;
	HANDLE hfile;

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
		fprintf(stderr, "(%s) ", dst);
		_perror("CreateFile");
		return -2;
	}

	if (!SetFileTime(hfile, &ctime, &atime, &wtime)) {
		fprintf(stderr, "(%s) ", dst);
		_perror("SetFileTime");
		return -1;
	}
	CloseHandle(hfile);

	return 0;
}

uint64_t get_filesize(char *fname) {
	uint64_t fsize = 0;
	WIN32_FILE_ATTRIBUTE_DATA w32ad;

	if (!GetFileAttributesEx(fname, GetFileExInfoStandard, &w32ad)) {
		fprintf(stderr, "%s: ", fname);
		_perror("GetFileAttributesEx");
		return 0;
	}

	fsize = w32ad.nFileSizeHigh * ((uint64_t)MAXDWORD + 1) + w32ad.nFileSizeLow;

	return fsize;
}

int StealthGetFile(char *filepath, char *outpath, ostringstream *osslog = NULL, BOOL SparseSkip=false) {
	//cerr << filepath << endl;

	if (!(StealthOpenFile && StealthReadFile && StealthCloseFile)) {
		fprintf(stderr, "NTFSParser functions could not be loaded.\n");
		__exit(EXIT_FAILURE);
	}
	
	BYTE *buf = (BYTE*)malloc(sizeof(BYTE)*CHUNKSIZE);
	DWORD bytesread = 0;
	ULONGLONG bytesleft = 0;
	ULONG64 offset = 0;

	FileInfo_t *file;
	if ((file = StealthOpenFile(filepath)) == NULL) {
		fprintf(stderr, "could not open file: %s\n", filepath);
		__exit(EXIT_FAILURE);
	};

	ULONGLONG filesize = (ULONGLONG)file->data->GetDataSize();
	WriteWrapper wfile(outpath, filesize);

	SHA256_CTX sha256;
	SHA_CTX sha1;
	MD5_CTX md5;

	SHA256_Init(&sha256);
	SHA1_Init(&sha1);
	MD5_Init(&md5);
	
	uint64_t skipclusters = 0;
	if (SparseSkip) {
		CDataRunList *drlist = ((CAttrNonResident*)(file->data))->GetDataRunList();
		const DataRun_Entry *dr = drlist->FindFirstEntry();

		for (int i = 0; i < drlist->GetCount(); i++){
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

	if (!WriteWrapper::isLocal() && !(SparseSkip && strcmp(filepath, "C:\\$Extend\\$UsnJrnl:$J") == 0)) { // if using WebDAV and reading file except UsnJrnl
		wfile.sendheader();
	}

	int atrnum = 0;
	do {
		int ret;

		if ((ret = StealthReadFile(file, buf, CHUNKSIZE, offset, &bytesread, &bytesleft, filesize)) != 0) {
			if(SparseSkip && strcmp(filepath, "C:\\$Extend\\$UsnJrnl:$J") == 0){
				filesize -= offset;
				skipclusters = 0;
				file->data = (CAttrBase*)file->fileRecord->FindNextStream("$J", atrnum);
				atrnum++;
				CDataRunList *drlist = ((CAttrNonResident*)(file->data))->GetDataRunList();
				const DataRun_Entry *dr = drlist->FindFirstEntry();
				for (int i = 0; i < drlist->GetCount(); i++) {
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
			else if (offset < filesize) {
				filesize -= offset;
				file->data = (CAttrBase*)file->fileRecord->FindNextStream(0,atrnum);
				atrnum++;
				CDataRunList *drlist = ((CAttrNonResident*)(file->data))->GetDataRunList();
				offset = 0;
				bytesleft = 1; // To continue loop
				continue;
			}
			else{
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
			wfile.sendheader(filesize - offset);
		}

		if (osslog) {
			SHA256_Update(&sha256, buf, bytesread);
			SHA1_Update(&sha1, buf, bytesread);
			MD5_Update(&md5, buf, bytesread);
		}
		// osfile.write((char*)buf, bytesread);
		wfile.write((char*)buf, bytesread);
		offset += bytesread;
	} while (bytesleft > 0 && offset < filesize);

	wfile.close();

	free(buf);

	StealthCloseFile(file);

	if (WriteWrapper::isLocal()) {
		CopyFileTime(filepath, outpath);
	}

	if (osslog) {
		unsigned char sha256hash[SHA256_DIGEST_LENGTH];
		unsigned char sha1hash[SHA_DIGEST_LENGTH];
		unsigned char md5hash[MD5_DIGEST_LENGTH];

		SHA256_Final(sha256hash, &sha256);
		SHA1_Final(sha1hash, &sha1);
		MD5_Final(md5hash, &md5);
		
		*osslog << hexdump(md5hash, MD5_DIGEST_LENGTH);
		*osslog << "\t";
		*osslog << hexdump(sha1hash, SHA_DIGEST_LENGTH);
		*osslog << "\t";
		*osslog << hexdump(sha256hash, SHA256_DIGEST_LENGTH);
		*osslog << "\t";
		*osslog << filepath;
		*osslog << "\r\n";
	}

	return 0;
}

int filecheck(char *path) {
	if (!PathFileExists(path)) {
//		cerr << path << msg(" が見つかりませんでした.", " not found") << endl;
		return 1;
	}
	return 0;
}

int get_pagefilepath(char *ret) {
	// get pagefile path from registry
	{
		HKEY hkey;
		DWORD vt, vs = 256;
		wchar_t value[256];

		RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
			NULL,
			KEY_READ,
			&hkey);

		RegQueryValueEx(
			hkey,
			"ExistingPageFiles",
			NULL,
			&vt,
			NULL,
			&vs);

		if (vt == REG_MULTI_SZ) {
			RegQueryValueEx(
				hkey,
				"ExistingPageFiles",
				0,
				&vt,
				(LPBYTE)value,
				&vs);
		}

		RegCloseKey(hkey);
		wcstombs(ret, value, 256);
	}

	return 0;
}

int get_memdump(bool is_x64, char *computername, char *pagefilepath) {
	// winpmem	
	char tmp[256];

	sprintf(tmp, "..\\winpmem.exe --output RAM_%s.aff4", computername);

	launchprocess(tmp);

	// for pagefile.sys acquisition
	//	sprintf(tmp, "..\\winpmem.exe -p %s -o RAM_%s.aff4", pagefilepath + 4, computername);
	//	launchprocess(tmp);

	return 0;
}

int get_analysisdata(ostringstream *osslog = NULL) {
	// collect somefiles

	// order of collection
	// $MFT
	// $UsnJrnl:$J (skip beginning sparse data)
	// Evtx
	// Prefetch
	// Registry 
	// * C:\Windows\System32\config\
	//   * SAM
	//   * Security
	//   * Software
	//	 * System
	// 
	// * %USERNAME%
	//   * ntuser.dat
	// 
	//   * Appdata\Roaming
	//     * UsrClass.dat
	// pagefile.sys

	PVOID oldval = NULL;
	Wow64DisableWow64FsRedirection(&oldval);

	HANDLE hfind;
	WIN32_FIND_DATA w32fd;

	char findpath[MAX_PATH + 1];
	char srcpath[MAX_PATH + 1];
	char dstpath[MAX_PATH + 1];

	if (mftdump == true) {
		// get MFT
		sprintf(srcpath, "%s\\$MFT", osvolume);
		sprintf(dstpath, "$MFT");
		StealthGetFile(srcpath, dstpath, osslog, false);
		cerr << msg("メタデータ 取得完了", "metadata is saved") << endl;
	}

	if (usndump == true) {
		// get UsnJrnl	
		sprintf(srcpath, "%s\\$Extend\\$UsnJrnl:$J", osvolume);
		sprintf(dstpath, "$UsnJrnl-$J");

		StealthGetFile(srcpath, dstpath, osslog, true);

		if (WriteWrapper::isLocal()) {
			if (!get_filesize("$UsnJrnl-$J")) {
				StealthGetFile(srcpath, dstpath, osslog, false);
			}
		}
		cerr << msg("ジャーナル 取得完了", "journal is saved") << endl;
	}

	if (evtxdump == true) {
		// get event logs		
		mkdir("Evtx");

		sprintf(findpath, "%s\\winevt\\Logs\\*.evtx", sysdir);
		hfind = FindFirstFile(findpath, &w32fd);

		if (hfind == INVALID_HANDLE_VALUE) {
			_perror("getting evtx files");
		}
		else {
			do {
				char srcpath[MAX_PATH + 1];
				char dstpath[MAX_PATH + 1];
				//uint64_t size = w32fd.nFileSizeHigh * ((uint64_t)MAXDWORD + 1) + w32fd.nFileSizeLow;
				//if (size == 69632)
				//	continue;
				sprintf(srcpath, "%s\\winevt\\Logs\\%s", sysdir, w32fd.cFileName);
				sprintf(dstpath, "Evtx\\%s", w32fd.cFileName);
				StealthGetFile(srcpath, dstpath, osslog, false);
			} while (FindNextFile(hfind, &w32fd));
			FindClose(hfind);
		}
		cerr << msg("イベントログ 取得完了", "event log is saved") << endl;
	}
	
	if (prefdump == true) {
		// get prefetch files
		mkdir("Prefetch");

		sprintf(findpath, "%s\\Prefetch\\*.pf", windir);
		hfind = FindFirstFile(findpath, &w32fd);

		if (hfind == INVALID_HANDLE_VALUE) {
			_perror("Prefetch files");
		}
		else {
			do {
				//uint64_t size = w32fd.nFileSizeHigh * ((uint64_t)MAXDWORD + 1) + w32fd.nFileSizeLow;
				sprintf(srcpath, "%s\\Prefetch\\%s", windir, w32fd.cFileName);
				sprintf(dstpath, "Prefetch\\%s", w32fd.cFileName);
				StealthGetFile(srcpath, dstpath, osslog, false);
			} while (FindNextFile(hfind, &w32fd));
			FindClose(hfind);
		}
		cerr << msg("プリフェッチ 取得完了", "prefetch is saved") << endl;
	}


	if (regdump == true) {
		// get registry
		vector<string> paths = {
			"\\config\\SAM",
			"\\config\\SECURITY",
			"\\config\\SOFTWARE",
			"\\config\\SYSTEM"
		};
		vector<pair<string, string> > paths_pair;
		for (int i = 0; i < paths.size(); i++) {
			paths_pair.push_back(pair<string, string>(string(sysdir) + paths[i], "Registry\\" + basename(paths[i])));
		}

		// Amcache.hve
		paths_pair.push_back(pair<string, string>(string(osvolume) + "\\Windows\\AppCompat\\Programs\\Amcache.hve", "Registry\\Amcache.hve"));

		//// each user
		vector<string> users;

		sprintf(findpath, "%s\\Users\\*", osvolume);
		hfind = FindFirstFile(findpath, &w32fd);

		if (hfind == INVALID_HANDLE_VALUE) {
			_perror("getting user");
		}
		else {
			do {
				if (string(w32fd.cFileName) == "."
					|| string(w32fd.cFileName) == ".."
					|| string(w32fd.cFileName) == "Public"
					|| string(w32fd.cFileName) == "Default User"
					|| string(w32fd.cFileName) == "All Users"
					|| (w32fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
					continue;
				users.push_back(w32fd.cFileName);
			} while (FindNextFile(hfind, &w32fd));
			FindClose(hfind);
		}

		for (int i = 0; i < users.size(); i++) {
			paths_pair.push_back(pair<string, string>(string(osvolume) + "\\Users\\" + users[i] + "\\NTUSER.dat", "Registry\\" + users[i] + "_NTUSER.dat"));
			paths_pair.push_back(pair<string, string>(string(osvolume) + "\\Users\\" + users[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "Registry\\" + users[i] + "_UsrClass.dat"));
		}

		mkdir("Registry");

		for (int i = 0; i < paths_pair.size(); i++) {
			char *srcpath, *dstpath;
			srcpath = strdup(paths_pair[i].first.c_str());
			dstpath = strdup(paths_pair[i].second.c_str());

			if (filecheck(srcpath)) {
				continue;
			}
			StealthGetFile(srcpath, dstpath, osslog, false);
		}
		cerr << msg("レジストリ 取得完了", "registry is saved") << endl;
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


	// chack proces name
	procname = basename(string(argv[0]));
	cout << msg("CDIR Collector v1.1 - 初動対応用データ収集ツール", "CDIR Collector v1.1 - Data Acquisition Tool for First Response") << endl;
	cout << msg("Cyber Defense Institute, Inc.\n", "Cyber Defense Institute, Inc.\n") << endl;

	// getting config
	string confnames[2] = {"cdir.ini", "cdir.conf"};
	for (string confname : confnames) {
		config = new ConfigParser(confname);
		if (config->isOpened()) {
			cerr << msg(confname+"を読み込み中...",
				"Loading "+confname+"...") << endl;
			break;
		}
	}

	if (config->isOpened()) {
		// param, JP, EN
		vector<pair<vector<string>, bool*>> params = {
			{{"MemoryDump", "メモリダンプ", "Memory dump"}, &memdump},
			{{"MFT", "MFT", "MFT"}, &mftdump},
			{{"UsnJrnl", "ジャーナル", "UsnJrnl"}, &usndump},
			{{"EventLog", "イベントログ", "Event log"}, &evtxdump},
			{{"Prefetch", "プリフェッチ", "Prefetch"}, &prefdump},
			{{"Registry", "レジストリ", "Registry"}, &regdump}
		};

		for (size_t i = 0; i < params.size(); i++) {
			string param, jp, en;
			param = params[i].first[0], jp = params[i].first[1], en = params[i].first[2];
			bool *ptr = params[i].second;
			bool flag = config->getBool(param);
			*ptr = flag;
		}

		for (size_t i = 0; i < params.size(); i++) {
			string param, jp, en;
			param = params[i].first[0], jp = params[i].first[1], en = params[i].first[2];
			bool flag = *(params[i].second);
			cerr << msg(jp + ": " + (flag ? "ON" : "OFF"), en + ": " + (flag ? "ON" : "OFF")) << endl;
		}
	}


	// begin time
	_t_beg = time(NULL);
	t = localtime(&_t_beg);
	if (!strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", t) || !strftime(t_beg, sizeof(t_beg), "%Y %m/%d %H:%M:%S", t)) {
		_perror("strftime");
		__exit(EXIT_FAILURE);
	}

	
	// get PC info
	if (!GetComputerName(computername, &dwsize)) {
		cerr << msg("[エラー] コンピュータ名",
			        "[ERROR] failed to get computer name.") << endl;
		__exit(EXIT_FAILURE);
	}
	if (!GetSystemDirectory(sysdir, MAX_PATH+1)) {
		cerr << msg("[エラー] システムディレクトリ",
			        "[ERROR] failed to get system directory") << endl;
		__exit(EXIT_FAILURE);
	}
	if (!GetWindowsDirectory(windir, MAX_PATH + 1)) {
		cerr << msg("[エラー] Windowsディレクトリ",
			        "[ERROR] failed to get windows directory") << endl;
		__exit(EXIT_FAILURE);
	}

	strncpy(osvolume, sysdir, 2); // copy drive letter

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

	sprintf(foldername, "%s_%s", computername, timestamp);
	mkdir(foldername);
	chdir(foldername);


	// start logging
	ostringstream ossinfo, osslog;

	// start collecting
	get_pagefilepath(pagefilepath);

	if (memdump) {
		if (filecheck("..\\winpmem.exe")) {
			cout << msg("メモリダンプ用プログラムがありません",
				"No memory dump program found") << endl;
		}
		else {
			get_memdump(is_x64, computername, pagefilepath);
			cout << msg("メモリダンプ取得完了",
				"Finished collecting memory dump") << endl;
		}
	}
	
	cout << msg("ディスク内データ 取得開始",
		        "Start collecting data for analysis") << endl;
	get_analysisdata(&osslog);
	cout << msg("解析用データ取得完了",
		        "Finished collecting data for analysis") << endl;


	FreeLibrary(hNTFSParserdll);


	// end time
	_t_end = time(NULL);
	t = localtime(&_t_end);
	if (!strftime(t_end, sizeof(t_end), "%Y %m/%d %H:%M:%S", t)) {
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
	ossinfo << "MD5" << "\t\t\t\t\t";
	ossinfo << "SHA1" << "\t\t\t\t\t\t";
	ossinfo << "SHA256" << "\t\t\t\t\t";
	ossinfo << "\r\n";
	ossinfo << "================================" << "\t";
	ossinfo << "========================================" << "\t";
	ossinfo << "================================================================" << "\t";
	ossinfo << "\r\n";
	ossinfo << osslog.str();

	string log_str = ossinfo.str();
	WriteWrapper log("collector-log.txt", log_str.size());
	log.sendfile(log_str.c_str());
	log.close();
	__exit(EXIT_SUCCESS);
}