#pragma once

#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <windows.h>

#include "openssl\ssl.h"

using namespace std;

class WriteWrapper
{
private:
	char *filename;
	ULONGLONG filesize;

	ofstream osfile;

	static string address;
	static int port;
	static string proxy_address;
	static int proxy_port;
	static string path;
	static string uriroot;
	static bool useProxy;
	static string curdir;

	WSADATA wsadata;
	struct sockaddr_in server;
	bool isSSL;
	SSL *ssl;
	SOCKET sock;

public:
	static const int STATUS_UNINTIALIZED = 0;
	static const int STATUS_LOCAL = 1;
	static const int STATUS_REMOTE = 2;

public:
	static int status; // 0: uninitialized, 1: local, 2: remote
	bool isHeaderSent;

public:
	WriteWrapper(char *, ULONGLONG, bool isDirectory=false);
	static bool isLocal();
	bool getConnInfo();
	int getProxyInfo();
	string urlencode(string);
	void mkdir(string);
	static void chdir(string);
	void sendfile(const char *);
	int sendheader(ULONGLONG = 0);
	long long write(const char *, long long);
	long long read(char *, long long);
	string readall();
	string readuntil(string);
	void close();

};