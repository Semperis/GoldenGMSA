using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GoldenGMSA
{
    public class RootKey
    {
        private static readonly string[] KdsRootKeyAttributes = {
            "msKds-SecretAgreementParam", "msKds-RootKeyData",
            "msKds-KDFParam", "msKds-KDFAlgorithmID",
            "msKds-CreateTime", "msKds-UseStartTime",
            "msKds-Version", "msKds-DomainID",
            "cn", "msKds-PrivateKeyLength",
            "msKds-PublicKeyLength",
            "msKds-SecretAgreementAlgorithmID" };

        public static int KdsRootKeyDataSizeDefault = 64;


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

        private RootKey(SearchResult sr)
        {
            msKdsVersion = (int)sr.Properties["msKds-Version"][0];
            cn = Guid.Parse(sr.Properties["cn"][0].ToString());
            ProbReserved = 0;
            msKdsVersion2 = (int)sr.Properties["msKds-Version"][0];
            ProbReserved2 = 0;
            msKdsKDFAlgorithmID = sr.Properties["msKds-KDFAlgorithmID"][0].ToString();
            msKdsKDFParam = (byte[])sr.Properties["msKds-KDFParam"][0];
            KDFParamSize = msKdsKDFParam.Length;
            ProbReserved3 = 0;
            KdsSecretAgreementAlgorithmID = sr.Properties["msKds-SecretAgreementAlgorithmID"][0].ToString();
            KdsSecretAgreementParam = (byte[])sr.Properties["msKds-SecretAgreementParam"][0];
            SecretAlgoritmParamSize = KdsSecretAgreementParam.Length;
            PrivateKeyLength = (int)sr.Properties["msKds-PrivateKeyLength"][0];
            PublicKeyLength = (int)sr.Properties["msKds-PublicKeyLength"][0];
            ProbReserved4 = 0;
            ProbReserved5 = 0;
            ProbReserved6 = 0;
            flag = 1;
            flag2 = 1;
            KdsDomainID = sr.Properties["msKds-DomainID"][0].ToString();
            KdsCreateTime = (long)sr.Properties["msKds-CreateTime"][0];
            KdsUseStartTime = (long)sr.Properties["msKds-UseStartTime"][0];
            ProbReserved7 = 0;
            KdsRootKeyDataSize = 64;
            KdsRootKeyData = (byte[])sr.Properties["msKds-RootKeyData"][0];
        }

        public RootKey(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            string[] lines = File.ReadAllLines(filePath);
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

        public RootKey(byte[] rootKeyBytes)
        {
            int trackSize = 32;
            msKdsVersion = BitConverter.ToInt32(rootKeyBytes, 0);
            byte[] temp = new byte[16];
            Array.Copy(rootKeyBytes, 4, temp, 0, 16);
            cn = new Guid(temp);
            ProbReserved = BitConverter.ToInt32(rootKeyBytes, 20);
            msKdsVersion2 = BitConverter.ToInt32(rootKeyBytes, 24);
            ProbReserved2 = BitConverter.ToInt32(rootKeyBytes, 28);
            int msKdfAlgorithmIDSize = BitConverter.ToInt32(rootKeyBytes, trackSize);
            msKdsKDFAlgorithmID = System.Text.Encoding.Unicode.GetString(rootKeyBytes, trackSize + 4, msKdfAlgorithmIDSize);
            KDFParamSize = BitConverter.ToInt32(rootKeyBytes, trackSize + msKdfAlgorithmIDSize + 4);
            if (KDFParamSize > 0)
            {
                msKdsKDFParam = new byte[KDFParamSize];
                Array.Copy(rootKeyBytes, trackSize + msKdfAlgorithmIDSize + 8, msKdsKDFParam, 0, KDFParamSize);
            }
            else
            {
                msKdsKDFParam = null;
            }
            trackSize += msKdfAlgorithmIDSize + KDFParamSize + 8;

            ProbReserved3 = BitConverter.ToInt32(rootKeyBytes, trackSize);
            trackSize += 4;

            int kdsSecretAgreementAlgorithmIDSize = BitConverter.ToInt32(rootKeyBytes, trackSize);
            KdsSecretAgreementAlgorithmID = System.Text.Encoding.Unicode.GetString(rootKeyBytes, trackSize + 4, kdsSecretAgreementAlgorithmIDSize);
            SecretAlgoritmParamSize = BitConverter.ToInt32(rootKeyBytes, trackSize + kdsSecretAgreementAlgorithmIDSize + 4);
            if (SecretAlgoritmParamSize > 0)
            {
                KdsSecretAgreementParam = new byte[SecretAlgoritmParamSize];
                Array.Copy(rootKeyBytes, trackSize + msKdfAlgorithmIDSize + 8, KdsSecretAgreementParam, 0, SecretAlgoritmParamSize);
            }
            else
            {
                KdsSecretAgreementParam = null;
            }
            trackSize += kdsSecretAgreementAlgorithmIDSize + SecretAlgoritmParamSize + 8;

            PrivateKeyLength = BitConverter.ToInt32(rootKeyBytes, trackSize);
            PublicKeyLength = BitConverter.ToInt32(rootKeyBytes, trackSize + 4);
            ProbReserved4 = BitConverter.ToInt32(rootKeyBytes, trackSize + 8);
            ProbReserved5 = BitConverter.ToInt32(rootKeyBytes, trackSize + 12);
            ProbReserved6 = BitConverter.ToInt32(rootKeyBytes, trackSize + 16);
            flag = BitConverter.ToInt64(rootKeyBytes, trackSize + 20);
            flag2 = BitConverter.ToInt64(rootKeyBytes, trackSize + 28);
            trackSize += 36;

            int kdsDomainIDSize = BitConverter.ToInt32(rootKeyBytes, trackSize);
            KdsDomainID = System.Text.Encoding.Unicode.GetString(rootKeyBytes, trackSize + 4, kdsDomainIDSize);
            trackSize += kdsDomainIDSize + 4;

            KdsCreateTime = BitConverter.ToInt64(rootKeyBytes, trackSize);
            KdsUseStartTime = BitConverter.ToInt64(rootKeyBytes, trackSize + 8);
            ProbReserved7 = BitConverter.ToInt64(rootKeyBytes, trackSize + 16);
            KdsRootKeyDataSize = BitConverter.ToInt64(rootKeyBytes, trackSize + 24);
            if (KdsRootKeyDataSize > 0)
            {
                KdsRootKeyData = new byte[KdsRootKeyDataSize];
                Array.Copy(rootKeyBytes, trackSize + 32, KdsRootKeyData, 0, KdsRootKeyDataSize);
            }
            else
            {
                KdsRootKeyData = null;
            }
        }

        protected RootKey(RootKey rk)
        {
            this.msKdsVersion = rk.msKdsVersion;
            this.cn = rk.cn;
            this.ProbReserved = 0;
            this.msKdsVersion2 = rk.msKdsVersion;
            this.ProbReserved2 = 0;
            this.msKdsKDFAlgorithmID = rk.msKdsKDFAlgorithmID;
            this.msKdsKDFParam = rk.msKdsKDFParam.ToArray();
            this.KDFParamSize = rk.KDFParamSize;
            this.ProbReserved3 = rk.ProbReserved3;
            this.KdsSecretAgreementAlgorithmID = rk.KdsSecretAgreementAlgorithmID;
            this.KdsSecretAgreementParam = rk.KdsSecretAgreementParam.ToArray();
            this.SecretAlgoritmParamSize = rk.SecretAlgoritmParamSize;
            this.PrivateKeyLength = rk.PrivateKeyLength;
            this.PublicKeyLength = rk.PublicKeyLength;
            this.ProbReserved4 = rk.ProbReserved4;
            this.ProbReserved5 = rk.ProbReserved5;
            this.ProbReserved6 = rk.ProbReserved6;
            this.flag = rk.flag;
            this.flag2 = rk.flag2;
            this.KdsDomainID = rk.KdsDomainID;
            this.KdsCreateTime = rk.KdsCreateTime;
            this.KdsUseStartTime = rk.KdsUseStartTime;
            this.ProbReserved7 = rk.ProbReserved7;
            this.KdsRootKeyDataSize = rk.KdsRootKeyDataSize;
            this.KdsRootKeyData = rk.KdsRootKeyData.ToArray();
        }


        public static RootKey GetRootKeyByGuid(string forestName, Guid rootKeyId)
        {
            using (var rootDse = Utils.GetRootDse(forestName))
            {
                string searchBase = rootDse.Properties["configurationNamingContext"].Value.ToString();
                string ldapFilter = $"(&(objectClass=msKds-ProvRootKey)(cn={rootKeyId}))";

                //Console.WriteLine($"searchBase={searchBase}; ldapFilter={ldapFilter}");

                var results = Utils.FindInConfigPartition(forestName, ldapFilter, KdsRootKeyAttributes);

                if (results == null || results.Count == 0)
                    return null;

                return new RootKey(results[0]);
            }
        }

        public static IEnumerable<RootKey> GetAllRootKeys(string forestName)
        {
            using (var rootDse = Utils.GetRootDse(forestName))
            {
                string searchBase = rootDse.Properties["configurationNamingContext"].Value.ToString();
                string ldapFilter = $"(objectClass=msKds-ProvRootKey)";

                var results = Utils.FindInConfigPartition(forestName, ldapFilter, KdsRootKeyAttributes);

                if (results == null || results.Count == 0)
                    yield break;

                foreach (SearchResult sr in results)
                {
                    RootKey rk = null;
                    try
                    {
                        rk = new RootKey(sr);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"WARNING: {sr.Properties["distinguishedName"][0]}: {ex.Message}");
                    }

                    if (rk != null)
                        yield return rk;
                }
            }
        }

        protected byte[] Serialize()
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
            BitConverter.GetBytes(flag).CopyTo(rootKeyBytes, trackSize + 20);
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




        // TODO: cleanup
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

        public string ToBase64String()
        {
            return Convert.ToBase64String(this.Serialize());
        }

        public override string ToString()
        {
            string result = $"Guid:\t\t{this.cn}{Environment.NewLine}";
            result += $"Base64 blob:\t{this.ToBase64String()}{Environment.NewLine}";
            result += $"----------------------------------------------{Environment.NewLine}";

            return result;
        }
    }
}
