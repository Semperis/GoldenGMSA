
namespace GoldenGMSA
{
    /// <summary>
    /// This class comes from ComputeL0Key function inside KdsSvc.dll. 
    /// It takes a RootKey structure, adds a field in the begining (L0KeyID) and modifies the KdsRootKeyData field with a value from GenerateDerivedKey. 
    /// </summary>
    public sealed class L0Key : RootKey
    {
        public long L0KeyID { get; set; }

        public L0Key(RootKey rootKey, long l0KeyID, byte[] derivedKey)
         : base(rootKey)
        {
            this.L0KeyID = l0KeyID;
            this.KdsRootKeyData = derivedKey;
        }
    }
}
