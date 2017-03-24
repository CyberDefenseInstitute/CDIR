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
#pragma comment(lib, "Advapi32.lib")
#pragma warning(disable: 4996)

WriteWrapper::WriteWrapper(char *_filename, ULONGLONG _filesize, bool isDirectory) {
	if (_filename == NULL) {
		cerr << "filename must not be null" << endl;
		return;
	}

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
				if (write(header.c_str(), header.length()) != 0) {
					readuntil("\r\n\r\n");
				}
			}

			SSL_load_error_strings();
			SSL_library_init();
			OpenSSL_add_all_algorithms();

			SSL_CTX *ctx;
			if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
				_perror("SSL_CTX_new");
				return;
			}
			//SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
			if ((ssl = SSL_new(ctx)) == NULL) {
				_perror("SSL_new");
				return;
			}
			if ((ret = SSL_set_fd(ssl, sock)) == 0) {
				_perror("SSL_set_fd");
				return;
			}
			if ((ret = SSL_connect(ssl)) != 1) {
				cerr << "SSL_connect: " << SSL_get_error(ssl, ret) << endl;
				return;
			}
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
		address = CASTVAL(string,config->getValue("host"));
		port = CASTVAL(int,config->getValue("port"));
		path = CASTVAL(string,config->getValue("path"));
		uriroot = path;
		getProxyInfo();
		return true;
	}
	else {
		return false;
	}
}

int WriteWrapper::getProxyInfo() {
	char proxy[1024] = { 0 };
	DWORD proxyenable;
	{
		HKEY hkey;
		DWORD vt, vs = 256;

		if (RegOpenKeyEx(
			HKEY_CURRENT_USER,
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			NULL,
			KEY_READ,
			&hkey)) {
			_perror("RegOpenKeyEx");
			return -1;
		}

		if (RegQueryValueEx(
			hkey,
			"ProxyServer",
			NULL,
			&vt,
			NULL,
			&vs)) {
			_perror("RegQueryValueEx");
			return -1;
		}

		if (RegQueryValueEx(
			hkey,
			"ProxyServer",
			0,
			&vt,
			(LPBYTE)proxy,
			&vs)) {
			_perror("RegQueryValueEx");
			return -1;
		}

		if (RegCloseKey(hkey)) {
			_perror("RegCloseKey");
			return -1;
		}
	}
	{
		HKEY hkey;
		DWORD vt, vs = 256;

		if (RegOpenKeyEx(
			HKEY_CURRENT_USER,
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			NULL,
			KEY_READ,
			&hkey)) {
			_perror("RegOpenKeyEx");
			return -1;
		}

		if (RegQueryValueEx(
			hkey,
			"ProxyEnable",
			NULL,
			&vt,
			NULL,
			&vs)) {
			_perror("RegQueryValueEx");
			return -1;
		}

		if (RegQueryValueEx(
			hkey,
			"ProxyEnable",
			0,
			&vt,
			(LPBYTE)&proxyenable,
			&vs)) {
			_perror("RegQueryValueEx");
			return -1;
		}

		if (RegCloseKey(hkey)) {
			_perror("RegCloseKey");
			return -1;
		}
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

	return 0;
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
	if (write(header.c_str(), header.length()) == 0) {
		cerr << "write failed" << endl;
	}
}

void WriteWrapper::chdir(string dirname) {
	if (dirname == ".." || dirname == "../") {
		curdir = curdir.substr(0, curdir.find_last_of('/'));
	}
	else {
		curdir = join({ curdir, dirname }, "/");
	}
}

void WriteWrapper::sendfile(const char *data) {
	if(!isLocal())
		if (sendheader()) {
			fprintf(stderr, "failed to send header.\n");
			return;
		}
	if (write(data, filesize) == 0) {
		cerr << "write failed" << endl;
	}
}

int WriteWrapper::sendheader(ULONGLONG size) {
	if (size > 0) {
		filesize = size;
	}
	string filename_s = string(filename);
	replace(filename_s.begin(), filename_s.end(), '\\', '/');

	string header = "PUT " + join({ uriroot, curdir, urlencode(filename_s) }, "/") + " HTTP/1.1" + "\r\n"
		+ "Host: " + address + ":" + to_string(port) + "\r\n"
		+ "Content-Length: " + to_string(filesize) + "\r\n"
		+ "\r\n";
	if (write(header.c_str(), header.length())) {
		isHeaderSent = true;
		return 0;
	}
	return -1;
}


/// <summary>
/// インスタンスが持つオブジェクトに書き込む
/// </summary>
/// <param name="buf">書き込むデータ</param>
/// <param name="size">書き込むサイズ</param>
/// <returns>失敗すると-1が返る</returns>
long long WriteWrapper::write(const char *buf, long long size) {
	if (status == STATUS_REMOTE) {
		long long sent = 0;
		int r;
		while (sent < size) {
			if (!isSSL) {
				if ((r = send(sock, buf+sent, (int)size, 0)) < 0) {
					return -1;
				}
				sent += r;
			}
			else {
				if ((r = SSL_write(ssl, buf+sent, (int)size)) < 0) {
					return -1;
				}
				sent += r;
			}
		}
		return sent;
	}
	else {
		size_t prev = (size_t)osfile.tellp();
		osfile.write(buf, size);
		if (osfile.fail() || osfile.bad()) {
			return -1;
		}
		return (size_t)osfile.tellp() - prev;
	}
}

long long WriteWrapper::read(char *buf, long long size) {
	if (status == STATUS_REMOTE) {
		long long recieved = 0;
		int r;
		while (recieved < size) {
			if (!isSSL) {
				if ((r = recv(sock, buf+recieved, (int)size, 0)) < 0) {
					return -1;
				}
				recieved += r;
			}
			else {
				if ((r = SSL_read(ssl, buf+recieved, (int)size)) < 0) {
					return -1;
				}
				recieved += r;
			}
		}
		return recieved;
	}
	return 0;
}

string WriteWrapper::readall() {
	string ret = "";
	char buf;

	while (true) {
		long long r;
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