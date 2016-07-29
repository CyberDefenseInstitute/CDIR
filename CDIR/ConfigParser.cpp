#include "stdafx.h"
#include "ConfigParser.h"
#include "util.h"

#include <algorithm>
#include <string>


ConfigParser::ConfigParser(string path)
{
	ifstream file(path);
	string l;
	if (file.is_open()) {
		opened = true;
		while (getline(file, l)) {
			size_t idx;
			// check if comment
			for (idx = 0; idx < l.size() && isspace(l[idx]); idx++);
			if (l[idx] == '#' || l[idx] == ';') continue;

			if ((idx = l.find_first_of('=')) != string::npos) {
				string key = l.substr(0, idx);
				string value = l.substr(idx+1);

				// trim string
				key = trim(key);
				value = trim(value);
				transform(key.begin(), key.end(), key.begin(), ::tolower);
				m[key] = value;
			}
		}
	}
	else {
		opened = false;
	}
}


ConfigParser::~ConfigParser()
{
}

bool ConfigParser::isOpened() {
	return opened;
}

bool ConfigParser::isSet(string key) {
	transform(key.begin(), key.end(), key.begin(), ::tolower);
	return m.find(key) != m.end();
}

bool ConfigParser::getBool(string key) {
	string keyname = key;
	transform(key.begin(), key.end(), key.begin(), ::tolower);
	if (isSet(key)) {
		if (_stricmp("true", m[key].c_str()) == 0) {
			return true;
		}
		if (_stricmp("false", m[key].c_str()) == 0) {
			return false;
		}
		if (strcmp("1", m[key].c_str()) == 0) {
			return true;
		}
		if (strcmp("0", m[key].c_str()) == 0) {
			return false;
		}

		cerr << msg("パースエラー",
			"parse error.") << endl;
		cerr << keyname + " " + "(1:ON 2:OFF 0:EXIT)" << endl << "> ";
		int input;  cin >> input;
		if (!input)	__exit(EXIT_SUCCESS);

		return (input == 1) ? true : false;
	}
	else {
		cerr << keyname << msg("は定義されていません", " is undefined") << endl;
		cerr << keyname + " " + "(1:ON 2:OFF 0:EXIT)" << endl << "> ";
		int input;  cin >> input;
		if (!input)	__exit(EXIT_SUCCESS);
		return (input == 1) ? true : false;
	}
}

string ConfigParser::getValue(string key) {
	transform(key.begin(), key.end(), key.begin(), ::tolower);
	return m[key];
}

string ConfigParser::trim(string &str) {
	size_t beg, end;
	for (beg = 0; beg < str.size() && isspace(str[beg]); beg++);
	for (end = beg; end < str.size() && !isspace(str[end]); end++);
	str = str.substr(beg, end - beg);
	return str;
}