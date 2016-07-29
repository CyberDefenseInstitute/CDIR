#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>

#include "stdafx.h"
#include "WriteWrapper.h"
#include "util.h"
#include "globals.h"

#include "openssl\err.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)

WriteWrapper::WriteWrapper(char *_filename, ULONGLONG _filesize, bool isDirectory) {
	filename = _filename;
	filesize = _filesize;
	isHeaderSent = false;

	if (!status) {
		status = (getConnInfo()) ? STATUS_REMOTE : STATUS_LOCAL;
	}

	if (status == STATUS_REMOTE) {
		isSSL = false;

		string _address = (useProxy) ? proxy_address : address;
		int _port = (useProxy) ? proxy_port : port;

		if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
			_perror("WSAStartup");
			return;
		}

		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET) {
			_perror("socket");
			return;
		}

		hostent *he = gethostbyname(_address.c_str());
		if (he == NULL) {
			_perror("gethostbyname");
			return;
		}

		server.sin_family = AF_INET;
		server.sin_port = htons(_port);
		server.sin_addr.S_un.S_addr = *(ULONG *)he->h_addr_list[0];

		if (connect(sock, (struct sockaddr *) &server, sizeof(server))) {
			_perror("connect");
			return;
		}

		if (!isLocal() && port == 443) {
			//// CONNECT https://target HTTP/1.1
			//// Host: target:443
			int ret;

			if (useProxy) {
				string header = "CONNECT " + address + ":443" + " HTTP/1.1" + "\r\n"
					+ "Host: " + address + ":443\r\n"
					+ "\r\n";
				write(header.c_str(), header.length());
				readuntil("\r\n\r\n");
			}

			SSL_load_error_strings();
			SSL_library_init();
			OpenSSL_add_all_algorithms();

			SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
			//SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
			ssl = SSL_new(ctx);
			ret = SSL_set_fd(ssl, sock);
			ret = SSL_connect(ssl);
			isSSL = true;
		}
	}
	else {
		osfile.open(filename, ios::out | ios::binary | ios::app);
	}
}

bool WriteWrapper::isLocal() {
	return status == STATUS_LOCAL;
}

bool WriteWrapper::getConnInfo() { // true: remote, false: local
	if (config->isOpened() && config->isSet("host") && config->isSet("port") && config->isSet("path")) {
		address = config->getValue("host");
		port = stoi(config->getValue("port"));
		path = config->getValue("path");
		uriroot = path;
		getProxyInfo();

		return true;
	}
	else {
		return false;
	}
}

void WriteWrapper::getProxyInfo() {
	char proxy[1024] = { 0 };
	DWORD proxyenable;
	{
		HKEY hkey;
		DWORD vt, vs = 256;

		RegOpenKeyEx(
			HKEY_CURRENT_USER,
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			NULL,
			KEY_READ,
			&hkey);

		RegQueryValueEx(
			hkey,
			"ProxyServer",
			NULL,
			&vt,
			NULL,
			&vs);

		RegQueryValueEx(
			hkey,
			"ProxyServer",
			0,
			&vt,
			(LPBYTE)proxy,
			&vs);

		RegCloseKey(hkey);
	}
	{
		HKEY hkey;
		DWORD vt, vs = 256;

		RegOpenKeyEx(
			HKEY_CURRENT_USER,
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			NULL,
			KEY_READ,
			&hkey);

		RegQueryValueEx(
			hkey,
			"ProxyEnable",
			NULL,
			&vt,
			NULL,
			&vs);

		RegQueryValueEx(
			hkey,
			"ProxyEnable",
			0,
			&vt,
			(LPBYTE)&proxyenable,
			&vs);

		RegCloseKey(hkey);
	}
	
	if (proxyenable) {
		if (proxy[0] != '\0') {
			string tmp = string(proxy);
			proxy_address = tmp.substr(0, tmp.find(":"));
			proxy_port = stoi(tmp.substr(tmp.find(":") + 1));
			useProxy = true;
			if (port == 80) {
				uriroot = "http://" + address + uriroot;
			}
			else if (port == 443) {
				uriroot = "https://" + address + uriroot;
			}
		}
		else {
			useProxy = false;
		}
	}
	else {
		useProxy = false;
	}

}

string WriteWrapper::urlencode(string s) {
	ostringstream res;
	res << hex;

	for (char c : s) {
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
			res << c;
			continue;
		}
		res << uppercase << '%' << setw(2) << int((unsigned char)c);
	}
	return res.str();
}

void WriteWrapper::mkdir(string dirname) {
	string header = "MKCOL " + join({uriroot, curdir, WriteWrapper::urlencode(dirname)}, "/") + "/" + " HTTP/1.1" + "\r\n"
		+ "Host: " + address + ":" + to_string(port) + "\r\n\r\n";
	write(header.c_str(), header.length());
}

void WriteWrapper::chdir(string dirname) {
	curdir = join({ curdir, dirname }, "/");
}

void WriteWrapper::sendfile(const char *data) {
	if(!isLocal())
		sendheader();
	write(data, filesize);
}

void WriteWrapper::sendheader(ULONGLONG size) {
	if (size > 0) {
		filesize = size;
	}
	string filename_s = string(filename);
	replace(filename_s.begin(), filename_s.end(), '\\', '/');

	string header = "PUT " + join({ uriroot, curdir, urlencode(filename_s) }, "/") + " HTTP/1.1" + "\r\n"
		+ "Host: " + address + ":" + to_string(port) + "\r\n"
		+ "Content-Length: " + to_string(filesize) + "\r\n"
		+ "\r\n";
	write(header.c_str(), header.length());
	isHeaderSent = true;
}

int WriteWrapper::write(const char *buf, long long size) {
	if (status == STATUS_REMOTE) {
		if (!isSSL)
			return send(sock, buf, size, 0);
		else
			return SSL_write(ssl, buf, size);
	}
	else {
		osfile.write(buf, size);
	}
	return 0;
}

int WriteWrapper::read(char *buf, long long size) {
	if (status == STATUS_REMOTE) {
		if (!isSSL)
			return recv(sock, buf, size, 0);
		else
			return SSL_read(ssl, buf, size);
	}
	return 0;
}

string WriteWrapper::readall() {
	string ret = "";
	char buf;

	while (true) {
		int r;
		if ((r = read(&buf, 1))>0) {
			ret += buf;
		}
		else {
			break;
		}
	}
	return ret;
}

string WriteWrapper::readuntil(string delim) {
	string ret = "";
	char buf;

	while (true) {
		read(&buf, 1);
		ret += buf;
		if (ret.find(delim) != string::npos)
			break;
	}

	return ret;
}

void WriteWrapper::close() {
	if (status == STATUS_REMOTE) {
		closesocket(sock);
		WSACleanup();
	}
	else {
		osfile.close();
	}
}