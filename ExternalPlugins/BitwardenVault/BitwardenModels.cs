using System.Collections.Generic;

namespace OneIdentity.DevOps.BitwardenVault
{
    internal class BitwardenVaultCredential
    {
        public string clientSecret { get; set; }
        public string masterPassword { get; set; }
    }

    internal class BitwardenResponse<T>
    {
        public bool success { get; set; }
        public T data { get; set; }
    }

    internal class BitwardenListData
    {
        public string @object { get; set; }
        public List<BitwardenItem> data { get; set; }
    }

    internal class BitwardenItem
    {
        public string id { get; set; }
        public int type { get; set; }
        public string name { get; set; }
        public string folderId { get; set; }
        public string organizationId { get; set; }
        public List<string> collectionIds { get; set; }
        public BitwardenLogin login { get; set; }
        public string notes { get; set; }
        public List<BitwardenCustomField> fields { get; set; }
    }

    internal class BitwardenLogin
    {
        public string username { get; set; }
        public string password { get; set; }
        public List<BitwardenUri> uris { get; set; }
    }

    internal class BitwardenUri
    {
        public string uri { get; set; }
        public int? match { get; set; }
    }

    internal class BitwardenCustomField
    {
        public string name { get; set; }
        public string value { get; set; }
        public int type { get; set; }
    }

    internal class BitwardenStatus
    {
        public string status { get; set; }
        public string userEmail { get; set; }
        public string serverUrl { get; set; }
    }

    internal class BitwardenFolder
    {
        public string id { get; set; }
        public string name { get; set; }
    }
}
