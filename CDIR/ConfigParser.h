#pragma once
#include <iostream>
#include <string>
#include <map>
#include <fstream>

using namespace std;

class ConfigParser
{
private:
	bool opened;
	map<string, string> m;

public:
	ConfigParser(string);
	~ConfigParser();
	bool isOpened();
	bool isSet(string);
	bool getBool(string);
	string getValue(string);
	static string trim(string&);
};