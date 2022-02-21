using GoldenGMSA.Unsafe;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GoldenGMSA
{
    public static class GetKey
    {

        /// Original signature is: 
        /// GetSIDKeyLocal(byte[] SecurityDescriptor, int SDSize, int GuidFlag, Guid RootKeyGUID, int L0KeyID, int L1KeyID, int L2KeyID, int AccessCheckFailed, ref IntPtr outSomething, out byte[] GKE, out int GKESize)
        public static void GetSidKeyLocal(
            byte[] securityDescriptor,
            int sDSize,
            RootKey rootKey,
            int l0KeyId,
            int l1KeyId,
            int l2KeyId,
            int accessCheckFailed,
            string domainName,
            string forestName,
            out GroupKeyEnvelope gke,
            out int gkeSize)
        {
            L0Key l0Key = ComputeL0Key(rootKey, l0KeyId);

            ComputeSidPrivateKey(
                l0Key,
                securityDescriptor, sDSize,
                l1KeyId,
                l2KeyId,
                accessCheckFailed,
                out byte[] l1Key,
                out byte[] l2Key);

            // There is another function that is being called if AccessCheckFailed != 0  which is ComputePublicKey - should not be relevant for us
            int guidExists = (rootKey.cn == Guid.Empty || rootKey.cn == null) ? 0 : 1;

            FormatReturnBlob(
                l0Key,
                guidExists,
                l1Key, l1KeyId,
                l2Key, l2KeyId,
                null, 0,
                domainName, forestName,
                out gke,
                out gkeSize);
        }

        private static L0Key ComputeL0Key(
            RootKey rootKey,
            int l0KeyId)
        {
            byte[] rootKeyGuid = rootKey.cn.ToByteArray();

            uint errCode = KdsCli.GenerateKDFContext(
                rootKeyGuid, l0KeyId,
                0xffffffff, 0xffffffff,
                0,
                out IntPtr kdfContextPtr,
                out int kdfContextSize,
                out int kdfContextFlag);

            if (errCode != 0)
                throw new Exception($"{nameof(ComputeL0Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");

            byte[] kdfContext = new byte[kdfContextSize];
            Marshal.Copy(kdfContextPtr, kdfContext, 0, kdfContextSize);

            byte[] generateDerivedKey = new byte[RootKey.KdsRootKeyDataSizeDefault];
            int labelSize = 0;
            byte[] label = null;

            errCode = KdsCli.GenerateDerivedKey(
                rootKey.msKdsKDFAlgorithmID,
                rootKey.msKdsKDFParam,
                rootKey.KDFParamSize,
                rootKey.KdsRootKeyData,
                rootKey.KdsRootKeyDataSize,
                kdfContext, kdfContextSize,
                ref kdfContextFlag,
                label, labelSize,
                1, generateDerivedKey,
                RootKey.KdsRootKeyDataSizeDefault, 0);

            if (errCode != 0)
                throw new Exception($"{nameof(ComputeL0Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            L0Key l0Key = new L0Key(rootKey, l0KeyId, generateDerivedKey);

            return l0Key;
        }

        private static void GenerateL1Key(
            byte[] securityDescriptor,
            int sDSize,
            L0Key l0Key,
            int l1KeyId,
            out byte[] derivedKey,
            out byte[] derivedKey2)
        {
            byte[] rootKeyGuid = l0Key.cn.ToByteArray();
            derivedKey = new byte[RootKey.KdsRootKeyDataSizeDefault];
            derivedKey2 = null;

            uint errCode = KdsCli.GenerateKDFContext(
                rootKeyGuid, (int)l0Key.L0KeyID,
                0x1f, 0xffffffff, 1,
                out IntPtr kdfContextPtr,
                out int kdfContextSize,
                out int kdfContextFlag);

            if (errCode != 0)
                throw new Exception($"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");

            int kdfContextModifiedSize = kdfContextSize + sDSize;
            byte[] kdfContextModified = new byte[kdfContextModifiedSize];

            Marshal.Copy(kdfContextPtr, kdfContextModified, 0, kdfContextSize);
            Array.Copy(securityDescriptor, 0, kdfContextModified, kdfContextSize, sDSize);

            errCode = KdsCli.GenerateDerivedKey(
                l0Key.msKdsKDFAlgorithmID,
                l0Key.msKdsKDFParam,
                l0Key.KDFParamSize,
                l0Key.KdsRootKeyData,
                64,
                kdfContextModified, kdfContextModifiedSize,
                ref kdfContextFlag,
                null, 0, 1,
                derivedKey,
                RootKey.KdsRootKeyDataSizeDefault, 0);

            if (errCode != 0)
                throw new Exception($"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            // This section will be used if 0<L1KeyID<31
            byte[] generatedDerivedKey;
            byte[] kdfContext = new byte[kdfContextSize];
            Marshal.Copy(kdfContextPtr, kdfContext, 0, kdfContextSize);

            if (l1KeyId != 31)
            {
                kdfContext[kdfContextFlag] = (byte)(kdfContext[kdfContextFlag] - 1);
                generatedDerivedKey = derivedKey.ToArray();

                errCode = KdsCli.GenerateDerivedKey(
                    l0Key.msKdsKDFAlgorithmID, l0Key.msKdsKDFParam,
                    l0Key.KDFParamSize, generatedDerivedKey,
                    64, kdfContext,
                    kdfContextSize, ref kdfContextFlag,
                    null, 0,
                    31 - l1KeyId, derivedKey,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception($"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }

            if (l1KeyId > 0)
            {
                kdfContext[kdfContextFlag] = (byte)(l1KeyId - 1);
                derivedKey2 = new byte[RootKey.KdsRootKeyDataSizeDefault];
                generatedDerivedKey = derivedKey.ToArray();

                errCode = KdsCli.GenerateDerivedKey(
                    l0Key.msKdsKDFAlgorithmID, l0Key.msKdsKDFParam,
                    l0Key.KDFParamSize, generatedDerivedKey,
                    64, kdfContext,
                    kdfContextSize, ref kdfContextFlag,
                    null, 0,
                    1, derivedKey2,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception($"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }

            return;
        }

        private static void GenerateL2Key(
            L0Key l0Key,
            byte[] l1DerivedKey,
            int l1KeyId,
            int l2KeyId,
            out int flagKdfContext,
            out byte[] derivedKey)
        {
            byte[] rootKeyGuid = l0Key.cn.ToByteArray();

            derivedKey = new byte[RootKey.KdsRootKeyDataSizeDefault];

            uint errCode = KdsCli.GenerateKDFContext(
                rootKeyGuid, (int)l0Key.L0KeyID,
                l1KeyId, 0x1f,
                2,
                out IntPtr kdfContextPtr,
                out int KDFContextSize,
                out flagKdfContext);

            if (errCode != 0)
                throw new Exception($"{nameof(GenerateL2Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");

            byte[] kdfContext = new byte[KDFContextSize];
            Marshal.Copy(kdfContextPtr, kdfContext, 0, KDFContextSize);

            int someFlag = 32 - l2KeyId;

            errCode = KdsCli.GenerateDerivedKey(
                l0Key.msKdsKDFAlgorithmID, l0Key.msKdsKDFParam,
                l0Key.KDFParamSize, l1DerivedKey,
                64, kdfContext,
                KDFContextSize, ref flagKdfContext,
                null, 0,
                someFlag, derivedKey,
                RootKey.KdsRootKeyDataSizeDefault, 0);

            if (errCode != 0)
                throw new Exception($"{nameof(GenerateL2Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            return;
        }

        private static void ComputeSidPrivateKey(
            L0Key l0Key,
            byte[] securityDescriptor,
            int sDSize,
            int l1KeyId,
            int l2KeyId,
            int accessCheckFailed,
            out byte[] l1Key,
            out byte[] l2Key)
        {
            GenerateL1Key(securityDescriptor, sDSize, l0Key, l1KeyId, out byte[] l1KeyFirst, out byte[] l2KeySecond);

            if (l2KeyId == 31 && accessCheckFailed == 0)
            {
                l1Key = l1KeyFirst.ToArray();
                l2Key = null;
                return;
            }

            GenerateL2Key(l0Key, l1KeyFirst, l1KeyId, l2KeyId, out int flag, out l2Key);

            if (l1KeyId > 0)
                l1Key = l2KeySecond.ToArray();
            else
                l1Key = null;

            return;
        }

        private static void FormatReturnBlob(
            L0Key l0Key,
            int guidExists,
            byte[] l1Key,
            int l1KeyID,
            byte[] l2Key,
            int l2KeyID,
            byte[] publicKey,
            int publicKeySize,
            string domainName,
            string forestName,
            out GroupKeyEnvelope gke,
            out int gkeSize
            )
        {
            gke = new GroupKeyEnvelope()
            {
                Version = 1,
                Reserved = 1263748171,
                L0Index = (int)l0Key.L0KeyID,
                L1Index = l1KeyID,
                L2Index = l2KeyID,
                RootKeyIdentifier = l0Key.cn,
                cbKDFAlgorithm = l0Key.msKdsKDFAlgorithmID.Length * 2 + 2,
                cbKDFParameters = l0Key.KDFParamSize,
                cbSecretAgreementAlgorithm = (l0Key.KdsSecretAgreementAlgorithmID.Length * 2 + 2),
                cbSecretAgreementParameters = l0Key.SecretAlgoritmParamSize,
                PrivateKeyLength = l0Key.PrivateKeyLength,
                PublicKeyLength = l0Key.PublicKeyLength,
                cbDomainName = domainName.Length * 2 + 2,
                cbForestName = forestName.Length * 2 + 2,
                KDFAlgorithm = l0Key.msKdsKDFAlgorithmID,
                KDFParameters = l0Key.msKdsKDFParam.ToArray(),
                SecretAgreementAlgorithm = l0Key.KdsSecretAgreementAlgorithmID,
                SecretAgreementParameters = l0Key.KdsSecretAgreementParam.ToArray(),
                DomainName = domainName,
                ForestName = forestName
            };

            int firstKeySize = 64;
            int secondKeySize = 64;

            if (publicKey != null)
            {
                secondKeySize = publicKeySize;
                firstKeySize = 0;
            }
            else if (l2KeyID == 31)
            {
                secondKeySize = 0;
            }
            else
            {
                if (l1KeyID == 0)
                {
                    firstKeySize = 0;
                }
            }
            gke.cbL1Key = firstKeySize;
            gke.cbL2Key = secondKeySize;
            int isPublicKey = 0;
            gke.L1Key = null;
            gke.L2Key = null;
            if (publicKey != null)
            {
                isPublicKey |= 1;
            }
            isPublicKey |= 2;
            gke.isPublicKey = isPublicKey;

            if (firstKeySize != 0)
            {
                gke.L1Key = l1Key.ToArray();
            }

            if (secondKeySize != 0)
            {
                if (publicKey != null)
                {
                    gke.L2Key = publicKey.ToArray();
                }
                else
                {
                    gke.L2Key = l2Key.ToArray();
                }
            }

            gkeSize = 80 + gke.cbKDFAlgorithm +
                gke.cbKDFParameters + gke.cbSecretAgreementAlgorithm +
                gke.cbSecretAgreementParameters +
                gke.cbDomainName + gke.cbForestName +
                gke.cbL1Key + gke.cbL2Key;
        }
    }

}
