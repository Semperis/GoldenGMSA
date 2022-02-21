using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace GoldenGMSA.Unsafe
{
    public static class KdsCli
    {
        [DllImport(@"kdscli.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern uint GenerateKDFContext(
            byte[] guid,
            int contextInit,
            long contextInit2,
            long contextInit3,
            int flag,
            out IntPtr outContext,
            out int outContextSize,
            out int flag2);


        [DllImport(@"kdscli.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern uint GenerateDerivedKey(
            string kdfAlgorithmId,
            byte[] kdfParam,
            int kdfParamSize,
            byte[] pbSecret,
            long cbSecret,
            byte[] context,
            int contextSize,
            ref int notSure,
            byte[] label,
            int labelSize,
            int notsureFlag,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pbDerivedKey,
            int cbDerivedKey,
            int AlwaysZero);

    }
}
