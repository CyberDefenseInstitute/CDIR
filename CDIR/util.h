#pragma once

#include <iostream>
#include <vector>
#include <windows.h>

using namespace std;

void __exit(int);
void _perror(char *);
void mkdir(char *);
void chdir(char *);
string basename(string &, char delim = '\\');
string dirname(string &, char delim = '\\');
string msg(string jp, string en, WORD lang = GetUserDefaultLangID());
string join(vector<string>, string);
string hexdump(const unsigned char*, size_t);