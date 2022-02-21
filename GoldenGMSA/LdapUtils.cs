using System;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace GoldenGMSA
{
    public static class LdapUtils
    {
        public static SearchResultCollection FindInConfigPartition(string domainFqdn, string ldapFilter, string[] attributes)
        {
            using (var de = GetConfigNamingContextDe(domainFqdn))
            using (var ds = new DirectorySearcher(de, ldapFilter, attributes))
            {
                ds.PageSize = 100;
                SearchResultCollection results = ds.FindAll();
                if (results == null)
                {
                    throw new Exception($"Could not find any results using LDAP filter: {ldapFilter}");
                }
                return results;
            }
        }
        public static SearchResultCollection FindInDomain(string domainFqdn, string ldapFilter, string[] attributes)
        {
            using (var de = GetDefaultNamingContextDe(domainFqdn))
            using (var ds = new DirectorySearcher(de, ldapFilter, attributes))
            {
                ds.PageSize = 100;
                SearchResultCollection results = ds.FindAll();
                if (results == null)
                {
                    throw new Exception($"Could not find any results using LDAP filter: {ldapFilter}");
                }
                return results;
            }
        }

        private static DirectoryEntry GetDefaultNamingContextDe(string domainName)
        {
            using (var rootDse = GetRootDse(domainName))
            {
                string adsPAth = $"LDAP://{domainName}/{rootDse.Properties["defaultNamingContext"].Value}";
                return new DirectoryEntry(adsPAth);
            }
        }

        private static DirectoryEntry GetConfigNamingContextDe(string domainName)
        {
            using (var rootDse = GetRootDse(domainName))
            {
                string adsPAth = $"LDAP://{domainName}/{rootDse.Properties["configurationNamingContext"].Value}";
                return new DirectoryEntry(adsPAth);
            }
        }

        public static DirectoryEntry GetRootDse(string domainName)
        {
            return new DirectoryEntry($"LDAP://{domainName}/RootDSE");
        }
    }
}
