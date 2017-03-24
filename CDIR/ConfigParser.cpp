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
				string val = l.substr(idx+1);

				// trim string
				key = trim(key);
				val = trim(val);
				if (CONFIGLIST.find(key) != CONFIGLIST.end()) {
					Value value;
					value.type = CONFIGLIST[key];
					switch (CONFIGLIST[key]) {
					case TYPE_BOOL:
						value.ptr = new bool;
						*((bool*)value.ptr) = [=]() {
							if (_stricmp("true", val.c_str()) == 0) {
								return true;
							}
							if (_stricmp("false", val.c_str()) == 0) {
								return false;
							}
							if (strcmp("1", val.c_str()) == 0) {
								return true;
							}
							if (strcmp("0", val.c_str()) == 0) {
								return false;
							}
							cerr << msg("パースエラー",
								"parse error.") << endl;
							cerr << key + " " + "(1:ON 2:OFF 0:EXIT)" << endl << "> ";
							int input;  cin >> input;
							if (!input)	__exit(EXIT_SUCCESS);

							return (input == 1) ? true : false;
						}();						

						break;
					case TYPE_INT:
						value.ptr = new int;
						*((int*)value.ptr) = atoi(val.c_str());
						break;
					case TYPE_STRING:
						value.ptr = new string;
						*((string*)value.ptr) = val;
						break;
					}
					m[key] = value;
				}
			}
		}
		//for (auto &it : CONFIGLIST) {
		//	cout << it.first << endl;
		//}
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
	return m.find(key) != m.end();
}


Value ConfigParser::getValue(string key) {
	if (m.find(key) != m.end()) {
		return m[key];
	}
	else {
		cerr << key << msg("は定義されていません", " is undefined") << endl;
		cerr << key + " " + "(1:ON 2:OFF 0:EXIT)" << endl << "> ";
		int input;  cin >> input;
		if (!input)	__exit(EXIT_SUCCESS);
		Value val;
		val.type = TYPE_BOOL;
		val.ptr = new bool;
		CASTVAL(bool,val) = (input == 1) ? true : false;
		return val;
	}	
}

string ConfigParser::trim(string &str) {
	size_t beg, end;
	for (beg = 0; beg < str.size() && isspace(str[beg]); beg++);
	for (end = beg; end < str.size() && !isspace(str[end]); end++);
	str = str.substr(beg, end - beg);
	return str;
}