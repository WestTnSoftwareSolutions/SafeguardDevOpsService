using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using Newtonsoft.Json;
using Serilog;

namespace OneIdentity.DevOps.BitwardenVault
{
    internal class BitwardenServeBackend : IBitwardenBackend
    {
        private BitwardenProcessManager _processManager;
        private HttpClient _httpClient;
        private ILogger _logger;
        private string _clientId;
        private string _clientSecret;
        private string _masterPassword;
        private string _organizationId;
        private string _collectionId;
        private string _folderName;
        private string _folderId;
        private int _port;
        private string _sessionKey;
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
            _port = servePort;

            try
            {
                _processManager = new BitwardenProcessManager(logger);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to initialize Bitwarden serve backend: {Message}", ex.Message);
                return false;
            }

            _httpClient = new HttpClient
            {
                BaseAddress = new Uri($"http://127.0.0.1:{_port}"),
                Timeout = TimeSpan.FromSeconds(30)
            };

            _logger.Information("Bitwarden serve backend initialized (lazy-start, port {Port}).", _port);
            return true;
        }

        public bool StoreCredential(string itemName, string username, string password)
        {
            lock (_operationLock)
            {
                if (!EnsureReady())
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

                    if (existingId != null)
                    {
                        item.id = existingId;
                        itemJson = JsonConvert.SerializeObject(item);
                        var response = InvokeApi(HttpMethod.Put, $"/object/item/{existingId}", itemJson);
                        if (response == null)
                        {
                            _logger.Error("Failed to update item {ItemName} in Bitwarden.", itemName);
                            return false;
                        }
                    }
                    else
                    {
                        var response = InvokeApi(HttpMethod.Post, "/object/item", itemJson);
                        if (response == null)
                        {
                            _logger.Error("Failed to create item {ItemName} in Bitwarden.", itemName);
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
                if (!EnsureReady())
                    return null;

                try
                {
                    var items = SearchItems(itemName);
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
                return EnsureReady();
            }
        }

        public void Shutdown()
        {
            if (_processManager == null)
                return;

            try
            {
                if (_processManager.IsServeRunning)
                {
                    InvokeApi(HttpMethod.Post, "/lock");
                }

                _processManager.StopServe();
                _processManager.Logout();
            }
            catch (Exception ex)
            {
                _logger.Debug("Error during serve backend shutdown: {Message}", ex.Message);
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _httpClient = null;
            _processManager?.Dispose();
            _processManager = null;
        }

        private bool EnsureReady()
        {
            if (_processManager == null)
                return false;

            bool started = false;

            if (!_processManager.IsServeRunning)
            {
                _logger.Information("bw serve is not running, performing full startup...");
                if (!FullStartup())
                    return false;
                started = true;
            }
            else
            {
                var status = GetStatus();

                if (status == null)
                {
                    _logger.Warning("bw serve is unresponsive, restarting...");
                    _processManager.StopServe();
                    if (!FullStartup())
                        return false;
                    started = true;
                }
                else if (status.status == "locked")
                {
                    _logger.Information("Vault is locked, re-unlocking via API...");
                    if (!UnlockViaApi())
                        return false;
                }
                else if (status.status != "unlocked")
                {
                    _logger.Warning("Unexpected vault status: {Status}, restarting...", status.status);
                    _processManager.StopServe();
                    if (!FullStartup())
                        return false;
                    started = true;
                }
            }

            if (started && !string.IsNullOrEmpty(_folderName) && _folderId == null)
                _folderId = ResolveOrCreateFolder(_folderName);

            return true;
        }

        private bool FullStartup()
        {
            if (!_processManager.Login(_clientId, _clientSecret))
                return false;

            _sessionKey = _processManager.Unlock(_masterPassword);
            if (_sessionKey == null)
                return false;

            if (!_processManager.StartServe(_port, _sessionKey))
                return false;

            return WaitForServeReady();
        }

        private bool WaitForServeReady()
        {
            var delays = new[] { 50, 100, 200, 400, 800, 1600, 3200 };
            var totalWaited = 0;
            const int maxWaitMs = 10000;

            foreach (var delay in delays)
            {
                Thread.Sleep(delay);
                totalWaited += delay;

                var status = GetStatus();
                if (status != null)
                {
                    _logger.Information("bw serve is ready (status: {Status}) after {Ms}ms.", status.status, totalWaited);
                    return status.status == "unlocked" || UnlockViaApi();
                }

                if (totalWaited >= maxWaitMs)
                    break;
            }

            while (totalWaited < maxWaitMs)
            {
                Thread.Sleep(500);
                totalWaited += 500;

                var status = GetStatus();
                if (status != null)
                {
                    _logger.Information("bw serve is ready (status: {Status}) after {Ms}ms.", status.status, totalWaited);
                    return status.status == "unlocked" || UnlockViaApi();
                }
            }

            _logger.Error("bw serve failed to become ready within {MaxWait}ms.", maxWaitMs);
            return false;
        }

        private bool UnlockViaApi()
        {
            try
            {
                var body = JsonConvert.SerializeObject(new { password = _masterPassword });
                var response = InvokeApi(HttpMethod.Post, "/unlock", body);

                if (response != null)
                {
                    _logger.Information("Successfully unlocked vault via serve API.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to unlock vault via serve API: {Message}", ex.Message);
            }

            return false;
        }

        private BitwardenStatus GetStatus()
        {
            try
            {
                var response = InvokeApi(HttpMethod.Get, "/status");
                if (response == null)
                    return null;

                var parsed = JsonConvert.DeserializeObject<BitwardenResponse<BitwardenStatus>>(response);
                return parsed?.success == true ? parsed.data : null;
            }
            catch
            {
                return null;
            }
        }

        private List<BitwardenItem> SearchItems(string searchTerm)
        {
            var response = InvokeApi(HttpMethod.Get, $"/list/object/items?search={Uri.EscapeDataString(searchTerm)}");
            if (response == null)
                return null;

            var parsed = JsonConvert.DeserializeObject<BitwardenResponse<BitwardenListData>>(response);
            return parsed?.success == true ? parsed.data?.data : null;
        }

        private string FindExistingItem(string itemName)
        {
            var items = SearchItems(itemName);
            var match = items?.FirstOrDefault(i =>
                i.name.Equals(itemName, StringComparison.OrdinalIgnoreCase));
            return match?.id;
        }

        private string ResolveOrCreateFolder(string folderName)
        {
            var response = InvokeApi(HttpMethod.Get, "/list/object/folders");
            if (response != null)
            {
                var parsed = JsonConvert.DeserializeObject<BitwardenResponse<BitwardenListData>>(response);
                if (parsed?.success == true && parsed.data?.data != null)
                {
                    var folders = JsonConvert.DeserializeObject<List<BitwardenFolder>>(
                        JsonConvert.SerializeObject(parsed.data.data));

                    var existing = folders?.FirstOrDefault(f =>
                        f.name.Equals(folderName, StringComparison.OrdinalIgnoreCase));

                    if (existing != null)
                    {
                        _logger.Information("Using existing Bitwarden folder '{FolderName}' ({FolderId}).", folderName, existing.id);
                        return existing.id;
                    }
                }
            }

            var createBody = JsonConvert.SerializeObject(new { name = folderName });
            var createResponse = InvokeApi(HttpMethod.Post, "/object/folder", createBody);

            if (createResponse != null)
            {
                var created = JsonConvert.DeserializeObject<BitwardenResponse<BitwardenFolder>>(createResponse);
                if (created?.success == true && created.data?.id != null)
                {
                    _logger.Information("Created Bitwarden folder '{FolderName}' ({FolderId}).", folderName, created.data.id);
                    return created.data.id;
                }
            }

            _logger.Error("Failed to resolve or create folder '{FolderName}'.", folderName);
            return null;
        }

        private string InvokeApi(HttpMethod method, string path, string body = null)
        {
            try
            {
                var request = new HttpRequestMessage(method, path);

                if (body != null)
                {
                    request.Content = new StringContent(body, Encoding.UTF8, "application/json");
                }

                using var response = _httpClient.SendAsync(request).GetAwaiter().GetResult();
                var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.Debug("bw serve API {Method} {Path} returned {StatusCode}: {Body}",
                        method, path, response.StatusCode, content);
                    return null;
                }

                return content;
            }
            catch (Exception ex)
            {
                _logger.Debug("bw serve API {Method} {Path} failed: {Message}", method, path, ex.Message);
                return null;
            }
        }
    }
}
