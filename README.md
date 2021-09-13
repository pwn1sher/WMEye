# WMEye
Various WMI experiments in a closed environment 

# UseCase
Fileless Lateral Movement using WMI, can be used with Cobalt Strike's Execute-Assembly

# Current Working

-  Creates a Remote WMI Class
-  Writes Shellcode as property value to the Created Class
- Create another Class and write MSBuild File Content as a property value to another Class - (Code for ShellCode Loader as Inline MSbuild XMl)
- Invokes Win32_Process Create to call powershell -> Reads property from second Class and dumps the MSBuild XML content to BuildConfig.xml
- Invokes Win32_Process Create to call MSbuild.exe remotely -> XML file is Inline task with Shellcoder loader, fetches shellcode from first class property and executes

# Upcoming

- Add GZIP Compression for Shellcode and XML File Bytes
- Add CLI Args for Username and Password for remote WMI lateral movement
- Add NTLM PTH Support 
- Get Rid of Powershell file transfer - easy detection, use the custom Consumer instead
 
