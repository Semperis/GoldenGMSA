using System;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace GoldenGMSA
{
    public static class Utils
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


        public static void ShowUsage()
        {
            string usage = @"GoldenGMSA usage:
----------------------------------------
Get basic information on all gMSAs in the domain (including GUID of associated KDS root key and msds-managedpasswordID):
GoldenGMSA --info

Get basic information on a specific gMSA based on the SID (including GUID of associated KDS root key and msds-managedpasswordID):
GoldenGMSA --info <gMSA SID>

Dump a specific KDS root key, specified by GUID in base64 format:
GoldenGMSA --dump-key <KDS Root Key GUID>

Generate a gMSA's password. Require Domain Admin privileges:
GoldenGMSA --generate-password --sid <gMSA SID>

Generate a gMSA's password. Require normal domain user and base64 of the relevant KDS root key:
GoldenGMSA --generate-password --sid <gMSA SID> --key <base64 RootKey>

Generate a gMSA's password. Offline mode - require base64 of the relevant KDS root key and an up to date base64 of msds-ManagedPasswordID:
GoldenGMSA --generate-password --sid <gMSA SID> --key <base64 RootKey> --passwordid <base64 ManagedPasswordID>";
            Console.WriteLine(usage);
        }

        //public static void ParseArgs(string[] args)
        //{
        //    RootKey rootKey;
        //    Console.WriteLine();
        //    switch (args[0].ToLower())
        //    {
        //        case ("--info"):
        //            if (args.Length > 2)
        //            {
        //                Utils.ShowUsage();
        //                return;
        //            }
        //            if (args.Length == 2)
        //            {
        //                var domainName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
        //                var gmsa = GmsaAccount.GetGmsaAccountBySid(domainName, args[1]);
        //                Console.WriteLine(gmsa.ToString());
        //            }
        //            else
        //            {
        //                Utils.PrintGMSAsInfo();
        //            }
        //            return;
        //        case ("--generate-password"):
        //            byte[] rootKeyBytes;
        //            switch (args.Length)
        //            {
        //                case 3:
        //                    if (args[1].ToLower() != "--sid")
        //                    {
        //                        Utils.ShowUsage();
        //                        return;
        //                    }
        //                    Program.WriteGmsaPassword(args[2]);
        //                    break;
        //                case 5:
        //                    if (args[1].ToLower() != "--sid" || args[3].ToLower() != "--key")
        //                    {
        //                        Utils.ShowUsage();
        //                        return;
        //                    }
        //                    rootKeyBytes = Convert.FromBase64String(args[4]);
        //                    rootKey = new RootKey(rootKeyBytes);
        //                    Program.WriteGmsaPassword(args[2], rootKey);
        //                    break;
        //                case 7:
        //                    if (args[1].ToLower() != "--sid" || args[3].ToLower() != "--key" || args[5].ToLower() != "--passwordid")
        //                    {
        //                        Utils.ShowUsage();
        //                        return;
        //                    }
        //                    rootKeyBytes = Convert.FromBase64String(args[4]);
        //                    rootKey = new RootKey(rootKeyBytes);
        //                    byte[] managedPasswordIDBytes = Convert.FromBase64String(args[6]);
        //                    Program.WriteGmsaPassword(args[2], rootKey, managedPasswordIDBytes);
        //                    break;
        //                default:
        //                    Utils.ShowUsage();
        //                    break;
        //            }
        //            break;
        //        case ("--dump-key"):
        //            // dump base64 of root key
        //            break;
        //        default:
        //            Utils.ShowUsage();
        //            return;

        //    }
        //}
    }






}
