using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace GoldenGMSA
{
    public class MsdsManagedPasswordId
    {
        public byte[] MsdsManagedPasswordIdBytes { get; private set; }

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

        public MsdsManagedPasswordId(byte[] pwdBlob)
        {
            MsdsManagedPasswordIdBytes = pwdBlob;

            Version = BitConverter.ToInt32(pwdBlob, 0);
            Reserved = BitConverter.ToInt32(pwdBlob, 4);
            isPublicKey = BitConverter.ToInt32(pwdBlob, 8);
            L0Index = BitConverter.ToInt32(pwdBlob, 12);
            L1Index = BitConverter.ToInt32(pwdBlob, 16);
            L2Index = BitConverter.ToInt32(pwdBlob, 20);
            byte[] temp = new byte[16];
            Array.Copy(pwdBlob, 24, temp, 0, 16);
            RootKeyIdentifier = new Guid(temp);
            cbUnknown = BitConverter.ToInt32(pwdBlob, 40);
            cbDomainName = BitConverter.ToInt32(pwdBlob, 44);
            cbForestName = BitConverter.ToInt32(pwdBlob, 48);
            if (cbUnknown > 0)
            {
                Unknown = new byte[cbUnknown];
                Array.Copy(pwdBlob, 52, Unknown, 0, cbUnknown);
            }
            else
            {
                Unknown = null;
            }
            DomainName = System.Text.Encoding.Unicode.GetString(pwdBlob, 52 + cbUnknown, cbDomainName);
            ForestName = System.Text.Encoding.Unicode.GetString(pwdBlob, 52 + cbDomainName + cbUnknown, cbForestName);
        }


        public static MsdsManagedPasswordId GetManagedPasswordIDBySid(string domainName, SecurityIdentifier sid)
        {
            string[] attributes = { "msds-ManagedPasswordID" };
            string ldapFilter = $"(objectSID={sid})";

            var results = Utils.FindInDomain(domainName, ldapFilter, attributes);

            if (results == null || results.Count == 0)
                return null;

            if (!results[0].Properties.Contains("msds-ManagedPasswordID"))
                return null;

            var pwdIdBlob = (byte[])results[0].Properties["msds-ManagedPasswordID"][0];

            return new MsdsManagedPasswordId(pwdIdBlob);
        }
    }
}
