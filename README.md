# cdir-collector

[English](README_en.md)

cdir-collectorは初動対応時のデータ保全を支援するためのツールです。Windows PC上の以下のデータを取得することが可能です。

* メモリ
* NTFS
  * $MFT
  * $SECURE:$SDS
  * $UsnJrnl:$J
* プリフェッチ
* イベントログ
* レジストリ
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
* Windows.old フォルダ内の上記データ (フォルダが存在する場合) 

## ダウンロード

バイナリ版は以下から入手可能です。

https://github.com/CyberDefenseInstitute/CDIR/releases

## ビルド

ソースコードはVisual Studio 2019で読み込みビルドすることができます。cdir-collectorの構成ファイルは以下の通りです。

* cdir.ini
* cdir-collector.exe
* NTFSParserDLL.dll
* libcrypto-41.dll
* libssl-43.dll
* winpmem_x64.exe
* winpmem_x86.exe

## 使い方

cdir-collector.exeを含む関連ファイル一式をUSBメモリやファイルサーバ上に配置してから実行することを想定しています。cdir-collector.exeをダブルクリックして実行してください。実行には管理者権限が必要です。実行場所に"コンピュータ名_年月日時分秒"フォルダを作成し、そのフォルダ配下にデータを保存します。

cdir.iniファイルを編集することにより、それぞれのデータを取得する、しないを切り替えることができます。

## サードパーティ

cdir-collectorは以下のライブラリ、ツールを活用しています。

* ライブラリ: NTFSParserDLL, LibreSSL
* ツール: winpmem

winpmem_x64.exe、winpmem_x86.exeはWinPmemプロジェクト (https://github.com/Velocidex/WinPmem) で提供されているWindows用のメモリ保全プログラムです。
