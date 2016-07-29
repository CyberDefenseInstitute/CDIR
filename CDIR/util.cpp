#include "WriteWrapper.h"
#include "globals.h"
#include "util.h"

#include <sstream>
#include <iomanip>

void __exit(int code) {
	cerr << "Press any key to continue..." << endl;
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

void mkdir(char *dirname) {
	WriteWrapper dir("", 0, true);

	if (dir.isLocal()) {
		CreateDirectory(dirname, NULL);
	}
	else {
		dir.mkdir(dirname);
	}
	dir.close();
}

void chdir(char *dirname) {
	WriteWrapper dir("", 0, true);

	if (dir.isLocal()) {
		if (!SetCurrentDirectory(dirname)) {
			_perror("SetCurrentDirectory:");
		}
	}
	else {
		dir.chdir(dirname);
	}
	dir.close();
}

string basename(string &path, char delim) {
	return path.substr(path.find_last_of(delim) + 1);
}

string dirname(string &path, char delim) {
	return path.substr(0, path.find_last_of(delim));
}

string msg(string jp, string en, WORD lang) {
	if ((lang & 0xff) == LANG_JAPANESE)
		return jp;
	else
		return en;
}

string join(vector<string> vs, string delim) {
	string ret = "";
	for (int i = 0; i < vs.size() - 1; i++) {
		if (vs[i].empty()) continue;
		ret += vs[i] + delim;
	}
	ret += vs[vs.size() - 1];
	return ret;
}

string hexdump(const unsigned char *s, size_t size) {
	ostringstream res;
	for (size_t i = 0; i < size; i++) {
		res << setw(2) << setfill('0') << hex << (unsigned int)s[i];
	}
	return res.str();
}