#include "WriteWrapper.h"
#include "globals.h"
#include "util.h"

#include <sstream>
#include <iomanip>

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
	if (FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ec,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf,
		1024,
		NULL) == 0) {
		cerr << "FormatMessage failed" << endl;
	}
	else {
		cerr << msg << ": " << buf << endl;
	}
}

void mkdir(char *dirname, bool error) {
	WriteWrapper dir("", 0, true);

	string dirname_s = string(dirname);

	size_t pos;
	if ((pos = dirname_s.find_first_of('\\')) == string::npos) {
		if (dir.isLocal()) {
			if (!CreateDirectory(dirname, NULL)) {
				if (error)
					_perror("CreateDirectory");
			}
		}
		else {
			dir.mkdir(dirname);
		}
		dir.close();
	}
	else {
		string topdir = dirname_s.substr(0, pos);
		string subdir = dirname_s.substr(pos + 1);
		mkdir((char*)topdir.c_str(), error);
		chdir((char*)topdir.c_str());
		mkdir((char*)subdir.c_str(), error);
		chdir("..");
	}
}

void chdir(char *dirname) {
	WriteWrapper dir("", 0, true);

	if (dir.isLocal()) {
		if (!SetCurrentDirectory(dirname)) {
			_perror("SetCurrentDirectory");
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
	for (size_t i = 0; i < vs.size() - 1; i++) {
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

vector<pair<string, int>> findfiles(string filepath, bool error) {
	// return found file and isdir
	HANDLE hfind;
	WIN32_FIND_DATA w32fd;
	vector<pair<string, int>> paths;

	hfind = FindFirstFile(filepath.c_str(), &w32fd);

	if (hfind == INVALID_HANDLE_VALUE) {
		if (error) {
			_perror((char*)filepath.c_str());
		}
		return paths;
	}
	else {
		do {
			if (!strcmp(w32fd.cFileName, ".")
				|| !strcmp(w32fd.cFileName, ".."))
				continue;
			paths.push_back(pair<string, int>((string)w32fd.cFileName, w32fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY));
		} while (FindNextFile(hfind, &w32fd));
	}
	if (!FindClose(hfind)) {
		_perror("FindClose");
	}

	return paths;
}