using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using OneIdentity.DevOps.Common;
using Serilog;

namespace OneIdentity.DevOps.BitwardenVault
{
    internal class BitwardenCliBackend : IBitwardenBackend
    {
        private BitwardenProcessManager _processManager;
        private ILogger _logger;
        private string _sessionKey;
        private string _clientId;
        private string _clientSecret;
        private string _masterPassword;
        private string _organizationId;
        private string _collectionId;
        private string _folderName;
        private string _folderId;
        private readonly object _operationLock = new object();

        public bool Initialize(string clientId, string clientSecret, string masterPassword,
            string organizationId, string collectionId, string folderName, int servePort, ILogger logger)
        {
            _logger = logger;
            _clientId = clientId;
            _clientSecret = clientSecret;
            _masterPassword = masterPassword;
            _organizationId = organizationId;
            _collectionId = collectionId;
            _folderName = folderName;

            try
            {
                _processManager = new BitwardenProcessManager(logger);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to initialize Bitwarden CLI backend: {Message}", ex.Message);
                return false;
            }

            if (!_processManager.Login(_clientId, _clientSecret))
                return false;

            _sessionKey = _processManager.Unlock(_masterPassword);
            if (_sessionKey == null)
                return false;

            if (!string.IsNullOrEmpty(_folderName))
                _folderId = ResolveOrCreateFolder(_folderName);

            return true;
        }

        public bool StoreCredential(string itemName, string username, string password)
        {
            lock (_operationLock)
            {
                if (!EnsureUnlocked())
                    return false;

                try
                {
                    var existingId = FindExistingItem(itemName);

                    var item = new BitwardenItem
                    {
                        type = 1,
                        name = itemName,
                        folderId = _folderId,
                        login = new BitwardenLogin
                        {
                            username = username,
                            password = password
                        }
                    };

                    if (!string.IsNullOrEmpty(_organizationId))
                        item.organizationId = _organizationId;
                    if (!string.IsNullOrEmpty(_collectionId))
                        item.collectionIds = new List<string> { _collectionId };

                    var itemJson = JsonConvert.SerializeObject(item,
                        new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
                    var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(itemJson));

                    if (existingId != null)
                    {
                        var (exitCode, stdout, stderr) = _processManager.ExecuteCommand(
                            $"edit item {existingId} {encoded} --session {_sessionKey} --raw");

                        if (exitCode != 0)
                        {
                            _logger.Error("Failed to update item {ItemName}: {Error}", itemName, stderr);
                            return false;
                        }
                    }
                    else
                    {
                        var (exitCode, stdout, stderr) = _processManager.ExecuteCommand(
                            $"create item {encoded} --session {_sessionKey} --raw");

                        if (exitCode != 0)
                        {
                            _logger.Error("Failed to create item {ItemName}: {Error}", itemName, stderr);
                            return false;
                        }
                    }

                    _logger.Information("Successfully stored credential for {ItemName} in Bitwarden.", itemName);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to store credential for {ItemName}: {Message}", itemName, ex.Message);
                    return false;
                }
            }
        }

        public string FetchCredential(string itemName)
        {
            lock (_operationLock)
            {
                if (!EnsureUnlocked())
                    return null;

                try
                {
                    var (exitCode, stdout, stderr) = _processManager.ExecuteCommand(
                        $"list items --search \"{itemName}\" --session {_sessionKey} --raw");

                    if (exitCode != 0)
                    {
                        _logger.Error("Failed to search for item {ItemName}: {Error}", itemName, stderr);
                        return null;
                    }

                    var items = JsonConvert.DeserializeObject<List<BitwardenItem>>(stdout);
                    var match = items?.FirstOrDefault(i =>
                        i.name.Equals(itemName, StringComparison.OrdinalIgnoreCase));

                    if (match?.login?.password == null)
                    {
                        _logger.Error("Item {ItemName} not found in Bitwarden vault.", itemName);
                        return null;
                    }

                    _logger.Information("Successfully fetched credential for {ItemName} from Bitwarden.", itemName);
                    return match.login.password;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to fetch credential for {ItemName}: {Message}", itemName, ex.Message);
                    return null;
                }
            }
        }

        public bool TestConnection()
        {
            lock (_operationLock)
            {
                return EnsureUnlocked();
            }
        }

        public void Shutdown()
        {
            if (_processManager == null)
                return;

            try
            {
                if (_sessionKey != null)
                {
                    _processManager.ExecuteCommand($"lock --session {_sessionKey}");
                }
                _processManager.Logout();
            }
            catch (Exception ex)
            {
                _logger.Debug("Error during CLI backend shutdown: {Message}", ex.Message);
            }
        }

        public void Dispose()
        {
            _processManager?.Dispose();
            _processManager = null;
        }

        private bool EnsureUnlocked()
        {
            if (_processManager == null)
                return false;

            var (exitCode, stdout, stderr) = _processManager.ExecuteCommand(
                $"status --session {_sessionKey}");

            if (exitCode == 0)
            {
                var status = JsonConvert.DeserializeObject<BitwardenStatus>(stdout);
                if (status?.status == "unlocked")
                    return true;
            }

            _logger.Information("Vault is locked, re-unlocking...");
            _sessionKey = _processManager.Unlock(_masterPassword);

            if (_sessionKey == null)
            {
                _logger.Error("Failed to re-unlock Bitwarden vault.");
                return false;
            }

            return true;
        }

        private string FindExistingItem(string itemName)
        {
            var (exitCode, stdout, stderr) = _processManager.ExecuteCommand(
                $"list items --search \"{itemName}\" --session {_sessionKey} --raw");

            if (exitCode != 0)
                return null;

            var items = JsonConvert.DeserializeObject<List<BitwardenItem>>(stdout);
            var match = items?.FirstOrDefault(i =>
                i.name.Equals(itemName, StringComparison.OrdinalIgnoreCase));

            return match?.id;
        }

        private string ResolveOrCreateFolder(string folderName)
        {
            var (exitCode, stdout, stderr) = _processManager.ExecuteCommand(
                $"list folders --session {_sessionKey} --raw");

            if (exitCode == 0)
            {
                var folders = JsonConvert.DeserializeObject<List<BitwardenFolder>>(stdout);
                var existing = folders?.FirstOrDefault(f =>
                    f.name.Equals(folderName, StringComparison.OrdinalIgnoreCase));

                if (existing != null)
                {
                    _logger.Information("Using existing Bitwarden folder '{FolderName}' ({FolderId}).", folderName, existing.id);
                    return existing.id;
                }
            }

            var folderJson = JsonConvert.SerializeObject(new { name = folderName });
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(folderJson));

            var (createExit, createOut, createErr) = _processManager.ExecuteCommand(
                $"create folder {encoded} --session {_sessionKey} --raw");

            if (createExit == 0)
            {
                var created = JsonConvert.DeserializeObject<BitwardenFolder>(createOut);
                if (created?.id != null)
                {
                    _logger.Information("Created Bitwarden folder '{FolderName}' ({FolderId}).", folderName, created.id);
                    return created.id;
                }
            }

            _logger.Error("Failed to resolve or create folder '{FolderName}': {Error}", folderName, createErr);
            return null;
        }
    }
}
