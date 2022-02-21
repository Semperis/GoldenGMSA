using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace GoldenGMSA
{
    public sealed class GmsaAccount
    {
        private static readonly string[] GmsaRequiredLdapAttributes = { "msds-ManagedPasswordID", "samAccountName", "objectSid", "samAccountName", "distinguishedName" };
        private static readonly string MsdsManagedPasswordIDAttributeName = "msds-ManagedPasswordID";
        private static readonly string IsGmsaAccountLdapFilter = "(objectCategory=msDS-GroupManagedServiceAccount)";

        public string DistinguishedName { get; private set; }

        public string SamAccountName { get; private set; }
        public SecurityIdentifier Sid { get; private set; }
        public MsdsManagedPasswordId ManagedPasswordId { get; private set; }


        private GmsaAccount(
            string samAccountName,
            string dn,
            SecurityIdentifier sid,
            MsdsManagedPasswordId pwdId)
        {
            DistinguishedName = dn;
            ManagedPasswordId = pwdId;
            Sid = sid;
            SamAccountName = samAccountName;
        }

        public static GmsaAccount GetGmsaAccountBySid(string domainFqdn, SecurityIdentifier sid)
        {
            if (sid is null)
                throw new ArgumentNullException(nameof(sid));

            if (domainFqdn is null)
                throw new ArgumentNullException(nameof(domainFqdn));

            string ldapFilter = $"(&{IsGmsaAccountLdapFilter}(objectsid={sid}))";
            var results = Utils.FindInDomain(domainFqdn, ldapFilter, GmsaRequiredLdapAttributes);

            if (results == null || results.Count == 0)
                return null;

            return GetGmsaFromSearchResult(results[0]);
        }

        public static IEnumerable<GmsaAccount> FindAllGmsaAccountsInDomain(string domainFqdn)
        {
            if (string.IsNullOrEmpty(domainFqdn))
            {
                throw new ArgumentException($"'{nameof(domainFqdn)}' cannot be null or empty.", nameof(domainFqdn));
            }

            var results = Utils.FindInDomain(domainFqdn, IsGmsaAccountLdapFilter, GmsaRequiredLdapAttributes);

            if (results == null)
                yield break;

            foreach (SearchResult sr in results)
            {
                GmsaAccount gmsa = null;
                try
                {
                    gmsa = GetGmsaFromSearchResult(sr);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"WARNING: {sr.Properties["distinguishedName"][0]}: {ex.Message}");
                }

                if (gmsa != null)
                    yield return gmsa;
            }
        }

        private static GmsaAccount GetGmsaFromSearchResult(SearchResult sr)
        {
            if (sr is null)
            {
                throw new ArgumentNullException(nameof(sr));
            }

            foreach (var attr in GmsaRequiredLdapAttributes)
            {
                if (!sr.Properties.Contains(attr))
                    throw new KeyNotFoundException($"Attribute {attr} was not found");
            }

            string dn = sr.Properties["distinguishedName"][0].ToString();

            var pwdBlob = (byte[])(sr.Properties[MsdsManagedPasswordIDAttributeName][0]);
            var pwdId = new MsdsManagedPasswordId(pwdBlob);

            var sid = new SecurityIdentifier((byte[])sr.Properties["objectSid"][0], 0);

            var samId = sr.Properties["samAccountName"][0].ToString();

            return new GmsaAccount(samId, dn, sid, pwdId);
        }



        public override string ToString()
        {
            string result = $"SamAccountName:\t\t{this.SamAccountName}{Environment.NewLine}";
            result += $"SID:\t\t\t{this.Sid}{Environment.NewLine}";
            result += $"RootKeyGuid:\t\t{this.ManagedPasswordId.RootKeyIdentifier}{Environment.NewLine}";
            result += $"msds-ManagedPasswordID:\t{Convert.ToBase64String(this.ManagedPasswordId.MsdsManagedPasswordIdBytes)}{Environment.NewLine}";
            result += $"----------------------------------------------{Environment.NewLine}";
            
            return result;
        }
    }
}
