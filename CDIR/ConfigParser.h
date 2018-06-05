#pragma once
#include <iostream>
#include <string>
#include <map>
#include <fstream>

using namespace std;

#define CASTVAL(type,val) *((type*)(val).ptr)
#define CASTPTR(type,ptr) *((type*)ptr)

enum TYPE_ID {
	TYPE_BOOL,
	TYPE_INT,
	TYPE_STRING
};

struct Value {
	TYPE_ID type;
	void* ptr;
};

//#define GETVALUE(val) ((val).type==TYPE_BOOL)?(CASTPTR(bool,(val).ptr)):((val.type==TYPE_INT)?(CASTPTR(int,(val).ptr)):(CASTPTR(string,(val).ptr)))
//#define GETVALUE(val) [=](){if(val.type==TYPE_BOOL)return CASTPTR(bool,(val).ptr);if(val.type==TYPE_INT)return CASTPTR(int,(val).ptr);if(val.type==TYPE_STRING)return CASTPTR(int,(val).ptr);}

struct c_ignorecase:std::binary_function<string, string, bool> {
	bool operator() (const string &s1, const string &s2) const {
		return _stricmp(s1.c_str(), s2.c_str()) < 0;
	}
};

static map<string, TYPE_ID, c_ignorecase> CONFIGLIST = {
	{"MemoryDump", TYPE_BOOL},
	{"MFT", TYPE_BOOL},
	{"Secure", TYPE_BOOL},
	{"UsnJrnl", TYPE_BOOL},
	{"EventLog", TYPE_BOOL},
	{"Prefetch", TYPE_BOOL},
	{"Registry", TYPE_BOOL},
	{"WMI", TYPE_BOOL},
	{"SRUM", TYPE_BOOL },
	{"Web", TYPE_BOOL },
	{"Output", TYPE_STRING},
	{"Target", TYPE_STRING},
	{"MemoryDumpCmdline", TYPE_STRING},
	{"host", TYPE_STRING},
	{"port", TYPE_INT},
	{"path", TYPE_STRING}
};

class ConfigParser
{
private:
	bool opened;
	map<string, Value, c_ignorecase> m;

public:
	ConfigParser(string);
	~ConfigParser();
	bool isOpened();
	bool isSet(string);
	Value getValue(string);
	static string trim(string&);
};