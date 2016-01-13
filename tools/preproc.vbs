'CDIR v0.2.1


'WScriptで実行されていないかチェック
'If LCase(Right(WScript.FullName, 11))="wscript.exe" Then
'  WScript.Echo "launch.batで実行してください."
'  WScript.Quit
'End If


Dim objWShell, objFileSys, wmi_os
Set objWShell = CreateObject("WScript.Shell")
Set objFileSys = CreateObject("Scripting.FileSystemObject")
Set wmi_os = GetObject("winmgmts:").InstancesOf("Win32_OperatingSystem")
Set wmi_proc = GetObject("winmgmts:").InstancesOf("Win32_Processor")

Const REG_PAGEFILE = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\"

Dim timestamp, foldername, osvolume, computername, pagefilepath, osarchitecture, version

Dim hoge
For each c in wmi_os
  Set hoge = c
Next
Set wmi_os = hoge

For each c in wmi_proc
  Set hoge = c
Next
Set wmi_proc = hoge


timestamp = Mid(wmi_os.localdatetime, 1, 14) ' yyyyMMddhhmmss
computername = wmi_os.CSName
osvolume = wmi_os.SystemDrive
pagefilepath = getPagefilePath()
osarchitecture = wmi_proc.AddressWidth
version = wmi_os.Version

foldername = computername & "_" & timestamp

objFileSys.Createfolder(foldername)
objFileSys.Createfolder(foldername&"\info")

objFileSys.OpenTextFile(foldername&"\info\computername", 2, True).WriteLine(computername)
objFileSys.OpenTextFile(foldername&"\info\osvolume", 2, True).WriteLine(osvolume)
objFileSys.OpenTextFile(foldername&"\info\pagefilepath", 2, True).WriteLine(pagefilepath)
objFileSys.OpenTextFile(foldername&"\info\osarchitecture", 2, True).WriteLine(osarchitecture)
objFileSys.OpenTextFile(foldername&"\info\version", 2, True).WriteLine(Split(version, ".")(0))


WScript.Echo foldername


Function getPagefilePath()
  If CDbl(Mid(wmi_os.Version, 1, 3)) < 6.0 Then ' XP/2003: PagingFiles
    getPagefilePath = objWShell.RegRead(REG_PAGEFILE & "PagingFiles")(0)
  Else ' ExistingPageFiles
    getPagefilePath = Mid(objWShell.RegRead(REG_PAGEFILE & "ExistingPageFiles")(0), 5)
  End If
End Function
