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
#include <map>
#include <utility>
#include <thread>
#include <mutex>

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>

#include "..\NTFSParserDLL\NTFS.h"
#include "..\NTFSParserDLL\NTFS_DataType.h"

#include "hash-library\sha256.h"
#include "hash-library\sha1.h"
#include "hash-library\md5.h"

#pragma comment(lib, "shlwapi.lib")
#pragma warning(disable:4996)
#pragma warning(disable:4700)
#define CHUNKSIZE 262144

using namespace std;

struct FileInfo_t
{
	CNTFSVolume* volume;
	CFileRecord* fileRecord;
	CIndexEntry* indexEntry;
	CAttrBase* data;
};

typedef FileInfo_t* (__cdecl *StealthOpenFile_func)(char*);
typedef int(__cdecl *StealthReadFile_func)(FileInfo_t*, BYTE*, DWORD, ULONGLONG, DWORD*, ULONGLONG*, ULONGLONG);
typedef void(__cdecl *StealthCloseFile_func)(FileInfo_t*);

StealthOpenFile_func  StealthOpenFile;
StealthReadFile_func  StealthReadFile;
StealthCloseFile_func StealthCloseFile;

HMODULE hNTFSParserdll;
char osvolume[3], sysdir[MAX_PATH + 1], windir[MAX_PATH + 1];


void __exit(int code) {
	cerr << "Press Enter key to continue..." << endl;
	char c;
	cin.ignore();
	cin.get(c);
	exit(code);
}

void _perror(char *msg) {
	char buf[1024];
	DWORD ec = GetLastError(); // Error Code
	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ec, 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf,
		1024,
		NULL);
	cerr << msg << ": " << buf << endl;
}

char *expandenv(char *str) {
	int size = strlen(str) + 1024;
	char *out = (char*)malloc(size);
	if (ExpandEnvironmentStrings(str, out, size) != 0)
		return out;
	else
		return NULL;
}

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

string msg(string jp, string en, WORD lang=GetUserDefaultLangID()) {
	if ((lang&0xff) == LANG_JAPANESE)
		return jp;
	else
		return en;
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

string basename(string &path, char delim='\\') {
	return path.substr(path.find_last_of(delim) + 1);
}

string dirname(string &path, char delim = '\\') {
	return path.substr(0, path.find_last_of(delim));
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
	ofstream osfile(outpath, ios::out | ios::binary | ios::app);
	SHA256 sha256;
	SHA1 sha1;
	MD5 md5;

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
		if (osslog) {
			sha256.add(buf, bytesread);
			sha1.add(buf, bytesread);
			md5.add(buf, bytesread);
		}
		osfile.write((char*)buf, bytesread);
		offset += bytesread;
	} while (bytesleft > 0 && offset < filesize);

	osfile.close();

	free(buf);

	StealthCloseFile(file);

	CopyFileTime(filepath, outpath);

	if (osslog) {
		*osslog << md5.getHash();
		*osslog << "\t";
		*osslog << sha1.getHash();
		*osslog << "\t";
		*osslog << sha256.getHash();
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
	// ramcapture and winpmem	
	char tmp[256];

	sprintf(tmp, "..\\winpmem_1.6.2.exe RAM_%s.raw", computername);

	launchprocess(tmp);

	sprintf(tmp, "RAM_%s.raw", computername);

	if (filecheck(tmp)) {
		sprintf(tmp, "..\\winpmem.exe -p %s -o RAM_%s.aff4", pagefilepath + 4, computername);
		launchprocess(tmp);
	}

	return 0;
}

int get_analysisdata(ostringstream *osslog=NULL) {
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


	// get MFT
	sprintf(srcpath, "%s\\$MFT", osvolume);
	sprintf(dstpath, "$MFT");
	StealthGetFile(srcpath, dstpath, osslog, false);
	cerr << msg("メタデータ 取得完了", "metadata is saved") << endl;


	// get UsnJrnl
	sprintf(srcpath, "%s\\$Extend\\$UsnJrnl:$J", osvolume);
	sprintf(dstpath, "$UsnJrnl-$J");
	StealthGetFile(srcpath, dstpath, osslog, true);

	if (!get_filesize("$UsnJrnl-$J")) {
		StealthGetFile(srcpath, dstpath, osslog, false);
	}
	cerr << msg("ジャーナル 取得完了", "journal is saved") << endl;

	// get event logs		
	CreateDirectory("Evtx", NULL);
	
	sprintf(findpath, "%s\\winevt\\Logs\\*.evtx", sysdir);
	hfind = FindFirstFile(findpath, &w32fd);

	if (hfind == INVALID_HANDLE_VALUE) {
		_perror("getting evtx files");
	}
	else {
		do {
			char srcpath[MAX_PATH+1];
			char dstpath[MAX_PATH+1];
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


	// get prefetch files
	CreateDirectory("Prefetch", NULL);

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


	// get registry
	vector<string> paths = {
		"\\config\\SAM",
		"\\config\\SECURITY",
		"\\config\\SOFTWARE",
		"\\config\\SYSTEM"
	};
	vector<pair<string, string> > paths_pair;
	for (int i = 0; i < paths.size(); i++) {
		paths_pair.push_back(pair<string, string>(string(sysdir)+paths[i], "Registry\\"+basename(paths[i])));
	}

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
		paths_pair.push_back(pair<string, string>(string(osvolume)+"\\Users\\" + users[i] + "\\NTUSER.dat", "Registry\\"+users[i]+"_NTUSER.dat"));
		paths_pair.push_back(pair<string, string>(string(osvolume)+"\\Users\\" + users[i] + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "Registry\\"+users[i]+"_UsrClass.dat"));
	}

	CreateDirectory("Registry", NULL);

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


	return 0;
}

int main(int argc, char **argv)
{
	bool memdump = false, is_x64;
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
	cout << msg("CDIR Collector v1.0 - 初動対応用データ収集ツール", "CDIR Collector v1.0 - Data Acquisition Tool for First Response") << endl;
	cout << msg("Cyber Defense Institute, Inc.\n", "Cyber Defense Institute, Inc.\n") << endl;

	if (!stricmp(procname.c_str(), "cdir-collector.exe")) {
		memdump = false;
		cout << msg("メモリダンプ 取得する:1 取得しない:2 プログラム終了:0 (デフォルト 0)", 
			        "Collect memory dump? [0] (1:ON 2:OFF 0:EXIT)") << endl << "> ";
		cin >> input; memdump = (input == 1) ? true : false;

		if (!input)	__exit(EXIT_SUCCESS);
	}
	else {
		if (procname.find("_mem") != string::npos) {
			cerr << msg("メモリダンプ: ON", 
				        "Memory dump: ON") << endl;
			memdump = true;
		}
		else if (procname.find("_nomem") != string::npos) {
			cerr << msg("メモリダンプ: OFF", 
				        "Memory dump: OFF") << endl;
		}
		else {
			cerr << msg("[エラー] 無効なファイル名",
				        "[ERROR] Invalid file name") << endl;
			__exit(EXIT_FAILURE);
		}
	}


	if (memdump && filecheck("winpmem_1.6.2.exe")){
		// __exit(EXIT_FAILURE);
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
	CreateDirectory(foldername, NULL);
	if (!SetCurrentDirectory(foldername)) {
		_perror("SetCurrentDirectory:");
	}


	// start logging
	ofstream ofsinfo("collector-log.txt", ios::out | ios::app);
	ostringstream osslog;


	// start collecting
	get_pagefilepath(pagefilepath);

	if (memdump) {
		get_memdump(is_x64, computername, pagefilepath);
		cout << msg("メモリダンプ取得完了",
			        "Finished collecting memory dump") << endl;
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
	ofsinfo << msg("開始時刻: ", "Start   time: ") << t_beg << "\r\n";
	ofsinfo << msg("終了時刻: ", "End     time: ") << t_end << "\r\n";
	ofsinfo << msg("所要時間: ", "Elapsed time: ");
	time_diff = (uint64_t)difftime(_t_end, _t_beg);
	if (time_diff / (60 * 60)) {
		ofsinfo << setfill('0') << setw(2) << (time_diff / (60 * 60)) << ":";
		time_diff %= (60 * 60);
	}
	else {
		ofsinfo << "00:";
	}
	if (time_diff / 60) {
		ofsinfo << setfill('0') << setw(2) << (time_diff / 60) << ":";
		time_diff %= 60;
	}
	else {
		ofsinfo << "00:";
	}
	ofsinfo << setfill('0') << setw(2) << time_diff << "\r\n";

	ofsinfo << "\r\n";
	ofsinfo << "MD5" << "\t\t\t\t\t";
	ofsinfo << "SHA1" << "\t\t\t\t\t\t";
	ofsinfo << "SHA256" << "\t\t\t\t\t";
	ofsinfo << "\r\n";
	ofsinfo << "================================" << "\t";
	ofsinfo << "========================================" << "\t";
	ofsinfo << "================================================================" << "\t";
	ofsinfo << "\r\n";
	ofsinfo << osslog.str();
	ofsinfo.close();
	__exit(EXIT_SUCCESS);
}
