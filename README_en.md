# cdir-collector

[Japanese](README.md)

cdir-collector is a collection tool for first response. it collects the following data on Windows.

* RAM
* NTFS
  * $MFT
  * $SECURE:$SDS
  * $UsnJrnl:$J
* Prefetch
* EventLog
* Registry
  * Amcache.hve
  * SAM, SECURITY, SOFTWARE, SYSTEM
  * NTUser.dat, UsrClass.dat
* WMI
* SRUM
* Web
  * History (Chrome)
  * cookies.sqlite, places.sqlite (Firefox)
  * WebCacheV01.dat (IE, Edge)
  * History (Edge)
* Windows.old (if this folder exists)

## Download

Binary is available on the following link.

https://github.com/CyberDefenseInstitute/CDIR/releases

## Build

If you want to customise and build binary from source code, try to use Visual Studio 2019. 

Component of cdir-collector: 
* cdir.ini
* cdir-collector.exe
* NTFSParserDLL.dll
* libcrypto-41.dll
* libssl-43.dll
* winpmem.exe
* winpmem-2.1.post4.exe

## How to use

All of component files place into USB stick or file server, then double-click cdir-collector.exe. cdir-collector requires administrative privilege.
It creates "COMPUTERNAME_YYYYMMDDhhmmss" folder then collected data are stored on this folder. 

If you edit cdir.ini, you can switch the acquisition of each data type.

## Third Party

cdir-collector depends on the following library/tools.

* Library: NTFSParserDLL, LibreSSL
* Tool: winpmem

winpmem.exe is a part of c-aff4 project (https://github.com/Velocidex/c-aff4). 
winpmem-2.1.post4.exe is a part of rekall project (https://github.com/google/rekall).
