# UAC-bypass-using-dll-injection
A small project to bypass UAC using dll injection technique

### Target System
Windows 10 (32/64)
Windows 8 (32/64)
Windows 7 (32/64)
### Usage
Tested on Windows 10.

  - Compile the UAC Bypass project.
  - Compile the `mscms dll` project (or use the already present `mscms.dll` for 64 bit machines)
  - Place both (`UAC Bypass.exe` and `mscms.dll`) in same directory along with the `script.vbs` file.
  - Execute the `UAC Bypass.exe`.
 
A command prompt with elevated privilege will appear without the UAC pop up.

### POC
<a href="https://gifyu.com/image/c6GW"><img src="https://s7.gifyu.com/images/uac-bypass1.gif" alt="uac-bypass1.gif" border="0" /></a>
