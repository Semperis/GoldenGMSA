using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static GoldengMSA.GetKey;

namespace GoldengMSA
{
    class GmsaPassword
    {
        public static void ParseSIDKeyResult(GROUP_KEY_ENVELOPE GKE, int GKESize, byte[] MsdsManagedPasswordID, out byte[] L1Key, ref int L1KeyIDDiff, ref int NewL1KeyID,
            out byte[] L2Key, ref int L2KeyIDDiff, ref int NewL2KeyID, out byte[] PublicKey)
        {
            NewL2KeyID = 31;
            if (MsdsManagedPasswordID != null)
            {
                Msds_ManagedPasswordID msds_ManagedPasswordID = new Msds_ManagedPasswordID(MsdsManagedPasswordID);
                L1KeyIDDiff = GKE.L1Index - msds_ManagedPasswordID.L1Index;
                L2KeyIDDiff = 32 - msds_ManagedPasswordID.L2Index;
                if (GKE.cbL2Key > 0)
                {
                    L1KeyIDDiff--;
                    if (L1KeyIDDiff > 0)
                    {
                        NewL1KeyID = GKE.L1Index - 2;
                    }
                    if (GKE.L1Index <= msds_ManagedPasswordID.L1Index)
                    {
                        L2KeyIDDiff = GKE.L2Index - msds_ManagedPasswordID.L2Index;
                        if (L2KeyIDDiff > 0)
                        {
                            NewL2KeyID = GKE.L2Index - 1;
                        }
                    }
                }
                else if (L1KeyIDDiff > 0)
                {
                    NewL1KeyID = GKE.L1Index - 1;
                }
            }
            else if (GKE.L2Index == 0)
            {
                L2KeyIDDiff = 1;
            }
            if (GKE.cbL1Key > 0)
            {
                L1Key = GKE.L1Key.ToArray();
            }
            else
            {
                L1Key = null;
            }
            if (GKE.cbL2Key > 0)
            {
                L2Key = GKE.L2Key.ToArray();
            }
            else
            {
                L2Key = null;
            }
            PublicKey = null;
        }

        public static void ClientComputeL2Key(GROUP_KEY_ENVELOPE GKE, byte[] MsdsManagedPasswordID, string KDFAlgorithmID, byte[] L1Key, ref byte[] L2Key,
            int L1KeyDiff, int NewL1KeyID, int L2KeyDiff, int NewL2KeyID)
        {
            Msds_ManagedPasswordID msds_ManagedPasswordID = new Msds_ManagedPasswordID(MsdsManagedPasswordID);
            byte[] rootKeyGUID = GKE.RootKeyIdentifier.ToByteArray();
            IntPtr KDFContextL1, KDFContextL2;
            int kdfContextFlagL1, kdfContextFlagL2;
            int KDFContextSizeL1, KDFContextSizeL2;
            uint status;
            long something;
            int KdsRootKeyDataSize = 64; // The reason this is hard coded is that it is also hardcoded in the DLL
            byte[] kdfParam = null;

            if (GKE.cbKDFParameters > 0)
            {
                kdfParam = GKE.KDFParameters.ToArray();
            }

            if (L1KeyDiff > 0)
            {
                status = Utils.GenerateKDFContext(rootKeyGUID, GKE.L0Index, NewL1KeyID, 0xffffffff, 1, out KDFContextL1, out KDFContextSizeL1, out kdfContextFlagL1);
                if (status != 0)
                {
                    throw new Exception("GenerateKDFContext in ClientComputeL2Key failed with error code " + status);
                }

                byte[] KDFContextArrL1 = new byte[KDFContextSizeL1];
                Marshal.Copy(KDFContextL1, KDFContextArrL1, 0, KDFContextSizeL1);

                status = Utils.GenerateDerivedKey(KDFAlgorithmID, kdfParam, GKE.cbKDFParameters, L1Key,
                    64, KDFContextArrL1, KDFContextSizeL1, ref kdfContextFlagL1, null, 0, L1KeyDiff, L1Key, KdsRootKeyDataSize, 0);
                if (status != 0)
                {
                    throw new Exception("GenerateDerivedKey in ClientComputeL2Key failed with error code " + status);
                }
            }

            if ((MsdsManagedPasswordID == null || GKE.L1Index <= msds_ManagedPasswordID.L1Index) && GKE.cbL2Key != 0)
            {
                L1Key = L2Key;
            }

            if (L2KeyDiff > 0)
            {
                if (MsdsManagedPasswordID == null)
                {
                    something = GKE.L1Index;
                }
                else
                {
                    something = msds_ManagedPasswordID.L1Index;
                }

                status = Utils.GenerateKDFContext(rootKeyGUID, GKE.L0Index, something, NewL2KeyID, 2, out KDFContextL2, out KDFContextSizeL2, out kdfContextFlagL2);
                if (status != 0)
                {
                    throw new Exception("GenerateKDFContext in ClientComputeL2Key failed with error code " + status);
                }

                byte[] KDFContextArrL2 = new byte[KDFContextSizeL2];
                Marshal.Copy(KDFContextL2, KDFContextArrL2, 0, KDFContextSizeL2);

                if (L2Key == null)
                {
                    L2Key = new byte[KdsRootKeyDataSize];
                }
                status = Utils.GenerateDerivedKey(KDFAlgorithmID, kdfParam, GKE.cbKDFParameters, L1Key,
                    64, KDFContextArrL2, KDFContextSizeL2, ref kdfContextFlagL2, null, 0, L2KeyDiff, L2Key, KdsRootKeyDataSize, 0);
                if (status != 0)
                {
                    throw new Exception("GenerateDerivedKey in ClientComputeL2Key failed with error code " + status);
                }
            }
        }

        public static void GenerateGMSAPassowrd(GROUP_KEY_ENVELOPE GKE, int GKESize, byte[] MsdsManagedPasswordID, byte[] SID, IntPtr OutOpt, IntPtr OutOptSize, out byte[] PasswordBlob, int PasswordBlobSize)
        {
            uint status;
            byte[] kdfParam = null;
            int newL1KeyID = 0, newL2KeyID = 0, l1KeyDiff = 0, l2KeyDiff = 0, flag = 0;
            byte[] l1Key, l2Key, publicKey;
            string labelStr = "GMSA PASSWORD\x0";
            byte[] label = Encoding.Unicode.GetBytes(labelStr);
            PasswordBlob = new byte[PasswordBlobSize];

            ParseSIDKeyResult(GKE, GKESize, MsdsManagedPasswordID, out l1Key, ref l1KeyDiff, ref newL1KeyID, out l2Key, ref l2KeyDiff, ref newL2KeyID, out publicKey);
            if (l1KeyDiff > 0 || l2KeyDiff > 0)
            {
                ClientComputeL2Key(GKE, MsdsManagedPasswordID, GKE.KDFAlgorithm, l1Key, ref l2Key, l1KeyDiff, newL1KeyID, l2KeyDiff, newL2KeyID);
            }
            if (GKE.cbKDFParameters > 0)
            {
                kdfParam = GKE.KDFParameters;
            }
            status = Utils.GenerateDerivedKey(GKE.KDFAlgorithm, kdfParam, GKE.cbKDFParameters, l2Key,
                64, SID, SID.Length, ref flag, label, 28, 1, PasswordBlob, PasswordBlobSize, 0); // 28 is hardcoded in the dll, should be label.Length
            if (status != 0)
            {
                throw new Exception("GenerateDerivedKey in ClientComputeL2Key failed with error code " + status);
            }
        }
    }
}
