using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GoldengMSA
{
    class GetKey
    {
        public static L0_Key ComputeL0Key(Root_Key RootKey, int L0KeyID)
        {
            byte[] rootKeyGUID = RootKey.cn.ToByteArray();
            IntPtr kdfContext;
            int kdfContextSize;
            uint status;
            int kdfContextFlag;

            status = Utils.GenerateKDFContext(rootKeyGUID, L0KeyID, 0xffffffff, 0xffffffff, 0, out kdfContext, out kdfContextSize, out kdfContextFlag);
            if (status != 0)
            {
                throw new Exception("GenerateKDFContext in ComputeL0Key failed with error code " + status);
            }
            byte[] KDFContextArr = new byte[kdfContextSize];
            Marshal.Copy(kdfContext, KDFContextArr, 0, kdfContextSize);

            int KdsRootKeyDataSize = 64;
            byte[] GenerateDerivedKeyOut = new byte[KdsRootKeyDataSize];
            int labelSize = 0;
            byte[] label = null;

            status = Utils.GenerateDerivedKey(RootKey.msKdsKDFAlgorithmID, RootKey.msKdsKDFParam, RootKey.KDFParamSize, RootKey.KdsRootKeyData,
                RootKey.KdsRootKeyDataSize, KDFContextArr, kdfContextSize, ref kdfContextFlag, label, labelSize, 1, GenerateDerivedKeyOut, KdsRootKeyDataSize, 0);
            if (status != 0)
            {
                throw new Exception("GenerateDerivedKey in ComputeL0Key failed with error code " + status);
            }
            L0_Key l0Key = new L0_Key(RootKey, L0KeyID, GenerateDerivedKeyOut);

            return l0Key;
        }

        public static void GenerateL1Key(byte[] SecurityDescriptor, int SDSize, L0_Key L0Key, int L1KeyID, out byte[] OutDerivedKey, out byte[] OutDerivedKey2)
        {
            byte[] rootKeyGUID = L0Key.cn.ToByteArray();
            IntPtr kdfContext;
            int kdfContextFlag;
            int kdfContextSize;
            uint status;

            int KdsRootKeyDataSize = 64; // The reason this is hard coded is that it is also hardcoded in the DLL
            OutDerivedKey = new byte[KdsRootKeyDataSize];
            OutDerivedKey2 = null;

            status = Utils.GenerateKDFContext(rootKeyGUID, (int)L0Key.L0KeyID, 0x1f, 0xffffffff, 1, out kdfContext, out kdfContextSize, out kdfContextFlag);
            if (status != 0)
            {
                throw new Exception("GenerateKDFContext in GenerateL1Key failed with error code " + status);
            }
            int KDFContextModifiedSize = kdfContextSize + SDSize;
            byte[] KDFContextModified = new byte[KDFContextModifiedSize];
            Marshal.Copy(kdfContext, KDFContextModified, 0, kdfContextSize);
            Array.Copy(SecurityDescriptor, 0, KDFContextModified, kdfContextSize, SDSize);

            status = Utils.GenerateDerivedKey(L0Key.msKdsKDFAlgorithmID, L0Key.msKdsKDFParam, L0Key.KDFParamSize, L0Key.KdsRootKeyData,
                64, KDFContextModified, KDFContextModifiedSize, ref kdfContextFlag, null, 0, 1, OutDerivedKey, KdsRootKeyDataSize, 0);
            if (status != 0)
            {
                throw new Exception("GenerateDerivedKey in GenerateL1Key failed with error code " + status);
            }

            // This section will be used if 0<L1KeyID<31
            byte[] GenerateDerivedKeyOutCopy;
            byte[] KDFContextArr = new byte[kdfContextSize];
            Marshal.Copy(kdfContext, KDFContextArr, 0, kdfContextSize);

            if (L1KeyID != 31)
            {
                KDFContextArr[kdfContextFlag] = (byte)(KDFContextArr[kdfContextFlag] - 1);
                GenerateDerivedKeyOutCopy = OutDerivedKey.ToArray();
                status = Utils.GenerateDerivedKey(L0Key.msKdsKDFAlgorithmID, L0Key.msKdsKDFParam, L0Key.KDFParamSize, GenerateDerivedKeyOutCopy,
                    64, KDFContextArr, kdfContextSize, ref kdfContextFlag, null, 0, 31 - L1KeyID, OutDerivedKey, KdsRootKeyDataSize, 0);
                if (status != 0)
                {
                    throw new Exception("GenerateDerivedKey in GenerateL1Key failed with error code " + status);
                }
            }
            if (L1KeyID > 0)
            {
                KDFContextArr[kdfContextFlag] = (byte)(L1KeyID - 1);
                OutDerivedKey2 = new byte[KdsRootKeyDataSize];
                GenerateDerivedKeyOutCopy = OutDerivedKey.ToArray();
                status = Utils.GenerateDerivedKey(L0Key.msKdsKDFAlgorithmID, L0Key.msKdsKDFParam, L0Key.KDFParamSize, GenerateDerivedKeyOutCopy,
                    64, KDFContextArr, kdfContextSize, ref kdfContextFlag, null, 0, 1, OutDerivedKey2, KdsRootKeyDataSize, 0);
                if (status != 0)
                {
                    throw new Exception("GenerateDerivedKey in GenerateL1Key failed with error code " + status);
                }
            }
            return;
        }

        public static void GenerateL2Key(L0_Key L0Key, byte[] L1DerivedKey, int L1KeyID, int L2KeyID, out int FlagKDFContext, out byte[] OutDerivedKey)
        {
            byte[] rootKeyGUID = L0Key.cn.ToByteArray();
            IntPtr KDFContext;
            int KDFContextSize;
            uint status;

            int KdsRootKeyDataSize = 64; // The reason this is hard coded is that it is also hardcoded in the DLL
            OutDerivedKey = new byte[KdsRootKeyDataSize];

            status = Utils.GenerateKDFContext(rootKeyGUID, (int)L0Key.L0KeyID, L1KeyID, 0x1f, 2, out KDFContext, out KDFContextSize, out FlagKDFContext);
            if (status != 0)
            {
                throw new Exception("GenerateKDFContext in GenerateL2Key failed with error code " + status);
            }

            byte[] KDFContextArr = new byte[KDFContextSize];
            Marshal.Copy(KDFContext, KDFContextArr, 0, KDFContextSize);

            int someFlag = 32 - L2KeyID;

            status = Utils.GenerateDerivedKey(L0Key.msKdsKDFAlgorithmID, L0Key.msKdsKDFParam, L0Key.KDFParamSize, L1DerivedKey,
                64, KDFContextArr, KDFContextSize, ref FlagKDFContext, null, 0, someFlag, OutDerivedKey, KdsRootKeyDataSize, 0);
            if (status != 0)
            {
                throw new Exception("GenerateDerivedKey in GenerateL2Key failed with error code " + status);
            }

            return;
        }

        public static void ComputeSIDPrivateKey(L0_Key L0Key, byte[] SecurityDescriptor, int SDSize, int L1KeyID, int L2KeyID, int AccessCheckFailed, out byte[] L1Key, out byte[] L2Key)
        {
            byte[] l1KeyFirst, l2KeySecond;
            int flag;
            GenerateL1Key(SecurityDescriptor, SDSize, L0Key, L1KeyID, out l1KeyFirst, out l2KeySecond);
            if (L2KeyID == 31 && AccessCheckFailed == 0)
            {
                L1Key = l1KeyFirst.ToArray();
                L2Key = null;
                return;
            }
            GenerateL2Key(L0Key, l1KeyFirst, L1KeyID, L2KeyID, out flag, out L2Key);
            if (L1KeyID > 0)
            {
                L1Key = l2KeySecond.ToArray();
            }
            else
            {
                L1Key = null;
            }
            return;
        }

        public static void FormatReturnBlob(L0_Key L0Key, int GuidExists, byte[] L1Key, int L1KeyID, byte[] L2Key, int L2KeyID, byte[] PublicKey, int PublicKeySize, out Group_Key_Envelope GKE, out int GKESize, string DomainName, string ForestName)
        {
            GKE = new Group_Key_Envelope();
            GKE.Version = 1;
            GKE.Reserved = 1263748171;
            GKE.L0Index = (int)L0Key.L0KeyID;
            GKE.L1Index = L1KeyID;
            GKE.L2Index = L2KeyID;
            GKE.RootKeyIdentifier = L0Key.cn;
            GKE.cbKDFAlgorithm = L0Key.msKdsKDFAlgorithmID.Length * 2 + 2;
            GKE.cbKDFParameters = L0Key.KDFParamSize;
            GKE.cbSecretAgreementAlgorithm = (L0Key.KdsSecretAgreementAlgorithmID.Length * 2 + 2);
            GKE.cbSecretAgreementParameters = L0Key.SecretAlgoritmParamSize;
            GKE.PrivateKeyLength = L0Key.PrivateKeyLength;
            GKE.PublicKeyLength = L0Key.PublicKeyLength;
            GKE.cbDomainName = DomainName.Length * 2 + 2;
            GKE.cbForestName = ForestName.Length * 2 + 2;
            GKE.KDFAlgorithm = L0Key.msKdsKDFAlgorithmID;
            GKE.KDFParameters = L0Key.msKdsKDFParam.ToArray();
            GKE.SecretAgreementAlgorithm = L0Key.KdsSecretAgreementAlgorithmID;
            GKE.SecretAgreementParameters = L0Key.KdsSecretAgreementParam.ToArray();
            GKE.DomainName = DomainName;
            GKE.ForestName = ForestName;

            int firstKeySize = 64;
            int secondKeySize = 64;

            if (PublicKey != null)
            {
                secondKeySize = PublicKeySize;
                firstKeySize = 0;
            }
            else if (L2KeyID == 31)
            {
                secondKeySize = 0;
            }
            else
            {
                if (L1KeyID == 0)
                {
                    firstKeySize = 0;
                }
            }
            GKE.cbL1Key = firstKeySize;
            GKE.cbL2Key = secondKeySize;
            int isPublicKey = 0;
            GKE.L1Key = null;
            GKE.L2Key = null;
            if (PublicKey != null)
            {
                isPublicKey |= 1;
            }
            isPublicKey |= 2;
            GKE.isPublicKey = isPublicKey;

            if (firstKeySize != 0)
            {
                GKE.L1Key = L1Key.ToArray();
            }

            if (secondKeySize != 0)
            {
                if (PublicKey != null)
                {
                    GKE.L2Key = PublicKey.ToArray();
                }
                else
                {
                    GKE.L2Key = L2Key.ToArray();
                }
            }
            GKESize = 80 + GKE.cbKDFAlgorithm + GKE.cbKDFParameters + GKE.cbSecretAgreementAlgorithm + GKE.cbSecretAgreementParameters +
                GKE.cbDomainName + GKE.cbForestName + GKE.cbL1Key + GKE.cbL2Key;
        }

        // Original signature is GetSIDKeyLocal(byte[] SecurityDescriptor, int SDSize, int GuidFlag, Guid RootKeyGUID, int L0KeyID, int L1KeyID, int L2KeyID, int AccessCheckFailed, ref IntPtr outSomething, out byte[] GKE, out int GKESize)
        public static void GetSIDKeyLocal(byte[] SecurityDescriptor, int SDSize, Root_Key RootKey, int L0KeyID, int L1KeyID, int L2KeyID, int AccessCheckFailed,
            out Group_Key_Envelope GKE, out int GKESize, string DomainName, string ForestName)
        {
            L0_Key l0Key = ComputeL0Key(RootKey, L0KeyID);
            byte[] l1Key, l2Key;
            ComputeSIDPrivateKey(l0Key, SecurityDescriptor, SDSize, L1KeyID, L2KeyID, AccessCheckFailed, out l1Key, out l2Key);
            // There is another function that is being called if AccessCheckFailed != 0  which is ComputePublicKey - should not be relevant for us
            int guidExists = (RootKey.cn == Guid.Empty || RootKey.cn == null) ? 0 : 1;
            FormatReturnBlob(l0Key, guidExists, l1Key, L1KeyID, l2Key, L2KeyID, null, 0, out GKE, out GKESize, DomainName, ForestName);
        }

    }

    public class Group_Key_Envelope
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

        public Group_Key_Envelope (byte[] GKEBytes)
        {
            Version = BitConverter.ToInt32(GKEBytes, 0);
            Reserved = BitConverter.ToInt32(GKEBytes, 4);
            isPublicKey = BitConverter.ToInt32(GKEBytes, 8);
            L0Index = BitConverter.ToInt32(GKEBytes, 12);
            L1Index = BitConverter.ToInt32(GKEBytes, 16);
            L2Index = BitConverter.ToInt32(GKEBytes, 20);
            byte[] temp = new byte[16];
            Array.Copy(GKEBytes, 24, temp, 0, 16);
            RootKeyIdentifier = new Guid(temp);
            cbKDFAlgorithm = BitConverter.ToInt32(GKEBytes, 40);
            cbKDFParameters = BitConverter.ToInt32(GKEBytes, 44);
            cbSecretAgreementAlgorithm = BitConverter.ToInt32(GKEBytes, 48);
            cbSecretAgreementParameters = BitConverter.ToInt32(GKEBytes, 52);
            PrivateKeyLength = BitConverter.ToInt32(GKEBytes, 56);
            PublicKeyLength = BitConverter.ToInt32(GKEBytes, 60);
            cbL1Key = BitConverter.ToInt32(GKEBytes, 64);
            cbL2Key = BitConverter.ToInt32(GKEBytes, 68);
            cbDomainName = BitConverter.ToInt32(GKEBytes, 72);
            cbForestName = BitConverter.ToInt32(GKEBytes, 76);
            KDFAlgorithm = System.Text.Encoding.Unicode.GetString(GKEBytes, 80, cbKDFAlgorithm);
            Array.Copy(GKEBytes, 80 + cbKDFAlgorithm, KDFParameters, 0, cbKDFParameters);
            SecretAgreementAlgorithm = System.Text.Encoding.Unicode.GetString(GKEBytes, 80 + cbKDFAlgorithm + cbKDFParameters, cbSecretAgreementAlgorithm);
            Array.Copy(GKEBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm, SecretAgreementParameters, 0, cbSecretAgreementParameters);
            DomainName = System.Text.Encoding.Unicode.GetString(GKEBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm
                + cbSecretAgreementParameters, cbDomainName);
            ForestName = System.Text.Encoding.Unicode.GetString(GKEBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm
                + cbSecretAgreementParameters + cbDomainName, cbForestName);
            if (cbL1Key > 0)
            {
                Array.Copy(GKEBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm 
                    + cbSecretAgreementParameters + cbDomainName + cbForestName, L1Key, 0, cbL1Key);
            }
            else
            {
                L1Key = null;
            }
            if (cbL2Key > 0)
            {
                Array.Copy(GKEBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm
                    + cbSecretAgreementParameters + cbDomainName + cbForestName + cbL1Key, L2Key, 0, cbL2Key);
            }
            else
            {
                L2Key = null;
            }
        }

        public Group_Key_Envelope()
        {
        }

        public byte[] Serialize ()
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
            KDFParameters.CopyTo(gkeBytes, 80 + cbKDFAlgorithm);
            Encoding.Unicode.GetBytes(SecretAgreementAlgorithm).CopyTo(gkeBytes, 80 + cbKDFAlgorithm + cbKDFParameters);
            SecretAgreementParameters.CopyTo(gkeBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm);
            Encoding.Unicode.GetBytes(DomainName).CopyTo(gkeBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm + cbSecretAgreementParameters);
            Encoding.Unicode.GetBytes(ForestName).CopyTo(gkeBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm + cbSecretAgreementParameters + cbDomainName);
            L1Key.CopyTo(gkeBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm + cbSecretAgreementParameters + cbDomainName + cbForestName);
            L1Key.CopyTo(gkeBytes, 80 + cbKDFAlgorithm + cbKDFParameters + cbSecretAgreementAlgorithm + cbSecretAgreementParameters + cbDomainName + cbForestName + cbL1Key);

            return gkeBytes;
        }
    }
}
