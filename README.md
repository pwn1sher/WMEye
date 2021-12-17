# WMEye
Various WMI experiments in a closed environment 

# UseCase
Fileless Lateral Movement using WMI, can be used with Cobalt Strike's Execute-Assembly

# Current Working

-  Creates a Remote WMI Class
-  Writes encoded Shellcode as property value to the above Created Class
-  Adds an WMI Event Filter that triggers a LogFileEventConsumer to copy MSBuild payload onto a remote file on remote computer on Event Trigger
-  Invokes Win32_Process Create to call MSbuild.exe remotely -> XML file is Inline task with Shellcoder loader, fetches shellcode from first class property and executes

# Upcoming

- Add GZIP Compression for Shellcode and XML File Bytes
- Add NTLM PTH Support 

 
# Whats Unique in this Project ?

- Uploads the encoded/encrypted shellcode to remote machines WMI property on a Created Fake Class (can maybe tweak to write shellcode into existing class's Property)
- Uses LogFileEventConsumer to upload MSBuild File , instead of relying in spawning Powershell.exe using win32_process Create 
 
