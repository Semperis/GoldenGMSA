using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GoldenGMSA
{
    public class KdsUtils
    {
        public static readonly long KeyCycleDuration = 360000000000;

        public static long[] GetIntervalId(long TimeStamp)
        {
            int L1_KEY_ITERATION = 32;
            int L2_KEY_ITERATION = 32;
            long L0KeyID = (TimeStamp / KdsUtils.KeyCycleDuration / L2_KEY_ITERATION / L1_KEY_ITERATION);
            long L1KeyID = (TimeStamp / KdsUtils.KeyCycleDuration / L2_KEY_ITERATION) & (L1_KEY_ITERATION - 1);
            long L2KeyID = (TimeStamp / KdsUtils.KeyCycleDuration) & (L2_KEY_ITERATION - 1);

            return new long[] { L0KeyID, L1KeyID, L2KeyID };
        }

        public static void GetCurrentIntervalID(
            long kdsKeyCycleDuration,
            int someFlag,
            ref int l0KeyID,
            ref int l1KeyID,
            ref int l2KeyID)
        {
            long currentTime = DateTime.Now.ToFileTimeUtc();
            if (someFlag != 0)
            {
                currentTime += 3000000000;
            }
            int temp = (int)(currentTime / kdsKeyCycleDuration);
            l0KeyID = temp / 1024;
            l1KeyID = (temp / 32) & 31;
            l2KeyID = temp & 31;

            return;
        }

        public static void GetIntervalStartTime(
            long kdsKeyCycleDuration,
            int l0KeyID,
            int l1KeyID,
            int l2KeyID,
            ref long IntervalStartTime)
        {
            IntervalStartTime = kdsKeyCycleDuration * (l2KeyID + 32 * (l1KeyID + 32 * l0KeyID));
            return;
        }
    }
}
