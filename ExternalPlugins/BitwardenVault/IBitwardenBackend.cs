using System;
using Serilog;

namespace OneIdentity.DevOps.BitwardenVault
{
    internal interface IBitwardenBackend : IDisposable
    {
        bool Initialize(string clientId, string clientSecret, string masterPassword,
            string organizationId, string collectionId, string folderName, int servePort, ILogger logger);
        bool StoreCredential(string itemName, string username, string password);
        string FetchCredential(string itemName);
        bool TestConnection();
        void Shutdown();
    }
}
