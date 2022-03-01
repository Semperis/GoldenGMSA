using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GoldenGMSA
{
    public class GroupKeyEnvelope
    {
        public int Version { get; set; }
        public int Reserved { get; set; }
        public int isPublicKey { get; set; }
        public int L0Index { get; set; }
        public int L1Index { get; set; }
        public int L2Index { get; set; }
        public Guid RootKeyIdentifier { get; set; }
        public int cbKDFAlgorithm { get; set; }
        public int cbKDFParameters { get; set; }
        public int cbSecretAgreementAlgorithm { get; set; }
        public int cbSecretAgreementParameters { get; set; }
        public int PrivateKeyLength { get; set; }
        public int PublicKeyLength { get; set; }
        public int cbL1Key { get; set; }
        public int cbL2Key { get; set; }
        public int cbDomainName { get; set; }
        public int cbForestName { get; set; }
        public string KDFAlgorithm { get; set; }
        public byte[] KDFParameters { get; set; }
        public string SecretAgreementAlgorithm { get; set; }
        public byte[] SecretAgreementParameters { get; set; }
        public string DomainName { get; set; }
        public string ForestName { get; set; }
        public byte[] L1Key { get; set; } // 64 in size
        public byte[] L2Key { get; set; } // 64 in size


        public GroupKeyEnvelope()
        {
        }

        public GroupKeyEnvelope(byte[] gkeBytes)
        {
            Version = BitConverter.ToInt32(gkeBytes, 0);
            Reserved = BitConverter.ToInt32(gkeBytes, 4);
            isPublicKey = BitConverter.ToInt32(gkeBytes, 8);
            L0Index = BitConverter.ToInt32(gkeBytes, 12);
            L1Index = BitConverter.ToInt32(gkeBytes, 16);
            L2Index = BitConverter.ToInt32(gkeBytes, 20);
            byte[] temp = new byte[16];
            Array.Copy(gkeBytes, 24, temp, 0, 16);
            RootKeyIdentifier = new Guid(temp);
            cbKDFAlgorithm = BitConverter.ToInt32(gkeBytes, 40);
            cbKDFParameters = BitConverter.ToInt32(gkeBytes, 44);
            cbSecretAgreementAlgorithm = BitConverter.ToInt32(gkeBytes, 48);
            cbSecretAgreementParameters = BitConverter.ToInt32(gkeBytes, 52);
            PrivateKeyLength = BitConverter.ToInt32(gkeBytes, 56);
            PublicKeyLength = BitConverter.ToInt32(gkeBytes, 60);
            cbL1Key = BitConverter.ToInt32(gkeBytes, 64);
            cbL2Key = BitConverter.ToInt32(gkeBytes, 68);
            cbDomainName = BitConverter.ToInt32(gkeBytes, 72);
            cbForestName = BitConverter.ToInt32(gkeBytes, 76);

            int curIndex = 80;
            KDFAlgorithm = Encoding.Unicode.GetString(gkeBytes, curIndex, cbKDFAlgorithm);

            curIndex += cbKDFAlgorithm;
            Array.Copy(gkeBytes, curIndex, KDFParameters, 0, cbKDFParameters);

            curIndex += cbKDFParameters;
            SecretAgreementAlgorithm = Encoding.Unicode.GetString(gkeBytes, curIndex, cbSecretAgreementAlgorithm);

            curIndex += cbSecretAgreementAlgorithm;
            Array.Copy(gkeBytes, curIndex, SecretAgreementParameters, 0, cbSecretAgreementParameters);

            curIndex += cbSecretAgreementParameters;
            DomainName = Encoding.Unicode.GetString(gkeBytes, curIndex, cbDomainName);

            curIndex += cbDomainName;
            ForestName = Encoding.Unicode.GetString(gkeBytes, curIndex, cbForestName);

            if (cbL1Key > 0)
                Array.Copy(gkeBytes, curIndex + cbForestName, L1Key, 0, cbL1Key);
            else
                L1Key = null;

            if (cbL2Key > 0)
                Array.Copy(gkeBytes, curIndex + cbForestName + cbL1Key, L2Key, 0, cbL2Key);
            else
                L2Key = null;
        }


        public byte[] Serialize()
        {
            int gkeSize = 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm + cbSecretAgreementParameters + cbDomainName + cbForestName + cbL1Key + cbL2Key;
            byte[] gkeBytes = new byte[gkeSize];

            BitConverter.GetBytes(Version).CopyTo(gkeBytes, 0);
            BitConverter.GetBytes(Reserved).CopyTo(gkeBytes, 4);
            BitConverter.GetBytes(isPublicKey).CopyTo(gkeBytes, 8);
            BitConverter.GetBytes(L0Index).CopyTo(gkeBytes, 12);
            BitConverter.GetBytes(L1Index).CopyTo(gkeBytes, 16);
            BitConverter.GetBytes(L2Index).CopyTo(gkeBytes, 20);
            RootKeyIdentifier.ToByteArray().CopyTo(gkeBytes, 24);
            BitConverter.GetBytes(cbKDFAlgorithm).CopyTo(gkeBytes, 40);
            BitConverter.GetBytes(cbKDFParameters).CopyTo(gkeBytes, 44);
            BitConverter.GetBytes(cbSecretAgreementAlgorithm).CopyTo(gkeBytes, 48);
            BitConverter.GetBytes(cbSecretAgreementParameters).CopyTo(gkeBytes, 52);
            BitConverter.GetBytes(PrivateKeyLength).CopyTo(gkeBytes, 56);
            BitConverter.GetBytes(PublicKeyLength).CopyTo(gkeBytes, 60);
            BitConverter.GetBytes(cbL1Key).CopyTo(gkeBytes, 64);
            BitConverter.GetBytes(cbL2Key).CopyTo(gkeBytes, 68);
            BitConverter.GetBytes(cbDomainName).CopyTo(gkeBytes, 72);
            BitConverter.GetBytes(cbForestName).CopyTo(gkeBytes, 76);
            Encoding.Unicode.GetBytes(KDFAlgorithm).CopyTo(gkeBytes, 80);

            int curIndex = 80 + cbKDFAlgorithm;
            KDFParameters.CopyTo(gkeBytes, curIndex);

            curIndex += cbKDFParameters;
            Encoding.Unicode.GetBytes(SecretAgreementAlgorithm).CopyTo(gkeBytes, curIndex);

            curIndex += cbSecretAgreementAlgorithm;
            SecretAgreementParameters.CopyTo(gkeBytes, curIndex);

            curIndex += cbSecretAgreementParameters;
            Encoding.Unicode.GetBytes(DomainName).CopyTo(gkeBytes, curIndex);

            curIndex += cbDomainName;
            Encoding.Unicode.GetBytes(ForestName).CopyTo(gkeBytes, curIndex);

            curIndex += cbForestName;
            L1Key.CopyTo(gkeBytes, curIndex);

            curIndex += cbL1Key;
            L1Key.CopyTo(gkeBytes, curIndex);

            return gkeBytes;
        }

        public string ToBase64String()
        {
            return Convert.ToBase64String(this.Serialize());
        }
    }
}
