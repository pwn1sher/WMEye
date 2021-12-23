# WMEye

WMEye is an experimental tool that was developed when exploring about Windows WMI. The tool is developed for performing Lateral Movement using WMI and remote MSBuild Execution. It uploads the encoded/encrypted shellcode into remote targets WMI Class Property, create an event filter that when triggered writes an MSBuild based Payload using a special WMI Class called LogFileEventConsumer and finally executes the payload remotely.   

# UseCase
Fileless Lateral Movement using WMI, can be used with Cobalt Strike's Execute-Assembly

**Note**: This is still in experimental stage and no where near to be used in a real engagement. 

# Current Working

  - Creates a Remote WMI Class
  - Writes Shellcode as property value to the above created Fake WMI Class
  - Creates a WMI Event Filter to trigger on powershell.exe process creation 
  - On Event Trigger, it Uploads MSBuild Payload into remote system using LogFileEventConsumer (A WMI Consumer type to write Log Files) 
  - Finally Invoke `Win32_Process Create` to call MSbuild remotely 
  
 The MSBuild Payload fetches encoded shellcode from WMI Class Property, decodes and executes it.

# Upcoming Features

- Replace WIN32_Process Create method of invocation with something better
- Add GZIP Compression for Shellcode and XML File Bytes
- Add NTLM PTH Support 
- Add CleanUp Functions for removing event filter after the logfileeventconsumer finished writing the MSBuild Payload

 
# Whats Unique in this Project ?

- Uploads the encoded/encrypted shellcode to remote machines WMI property on a Created Fake Class (can maybe tweak to write shellcode into existing class's Property)
- Uses LogFileEventConsumer to upload MSBuild File , instead of relying in spawning Powershell.exe using win32_process Create 
 
 
 # Credits
 
 https://www.fireeye.de/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
 
  
