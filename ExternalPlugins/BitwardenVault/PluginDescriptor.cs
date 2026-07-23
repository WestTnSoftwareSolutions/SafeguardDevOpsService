using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using OneIdentity.DevOps.Common;
using Serilog;

namespace OneIdentity.DevOps.BitwardenVault
{
    public class PluginDescriptor : ILoadablePlugin
    {
        private IBitwardenBackend _backend;
        private Dictionary<string, string> _configuration;
        private Regex _rgx;

        private const string ClientIdKey = "clientId";
        private const string ExecutionModeKey = "executionMode";
        private const string ServePortKey = "servePort";
        private const string OrganizationIdKey = "organizationId";
        private const string CollectionIdKey = "collectionId";
        private const string FolderNameKey = "folderName";

        private const string DefaultExecutionMode = "serve";
        private const string DefaultServePort = "8087";
        private const string DefaultFolderName = "Safeguard";

        private string FormatAccountName(string altAccountName, string asset, string account)
            => _rgx.Replace(altAccountName ?? $"{asset}-{account}", "-");

        public string Name => "BitwardenVault";
        public string DisplayName => "Bitwarden Vault";
        public string Description => "This is the Bitwarden Vault plugin for pushing and pulling credentials";
        public bool SupportsReverseFlow => true;
        public CredentialType[] SupportedCredentialTypes => new[] { CredentialType.Password, CredentialType.SshKey, CredentialType.ApiKey };

        public CredentialType AssignedCredentialType { get; set; } = CredentialType.Password;
        public bool ReverseFlowEnabled { get; set; } = false;
        public ILogger Logger { get; set; }

        public Dictionary<string, string> GetPluginInitialConfiguration()
        {
            return _configuration ??= new Dictionary<string, string>
            {
                { ClientIdKey, "" },
                { ExecutionModeKey, DefaultExecutionMode },
                { ServePortKey, DefaultServePort },
                { OrganizationIdKey, "" },
                { CollectionIdKey, "" },
                { FolderNameKey, DefaultFolderName }
            };
        }

        public void SetPluginConfiguration(Dictionary<string, string> configuration)
        {
            if (configuration != null && configuration.ContainsKey(ClientIdKey))
            {
                _configuration = configuration;
                _rgx = new Regex("[^a-zA-Z0-9-]");
                Logger.Information($"Plugin {Name} has been successfully configured.");
            }
            else
            {
                Logger.Error("Some parameters are missing from the configuration. The clientId is required.");
            }
        }

        public void SetVaultCredential(string credential)
        {
            if (_configuration == null || credential == null)
            {
                Logger.Error("The plugin configuration or credential is missing.");
                return;
            }

            try
            {
                var vaultCred = JsonConvert.DeserializeObject<BitwardenVaultCredential>(credential);

                if (string.IsNullOrEmpty(vaultCred?.clientSecret) || string.IsNullOrEmpty(vaultCred?.masterPassword))
                {
                    Logger.Error("The vault credential must be a JSON object with 'clientSecret' and 'masterPassword' fields.");
                    return;
                }

                var clientId = _configuration[ClientIdKey];
                var executionMode = _configuration.ContainsKey(ExecutionModeKey)
                    ? _configuration[ExecutionModeKey] : DefaultExecutionMode;
                var servePort = int.Parse(_configuration.ContainsKey(ServePortKey)
                    ? _configuration[ServePortKey] : DefaultServePort);
                var organizationId = _configuration.ContainsKey(OrganizationIdKey)
                    ? _configuration[OrganizationIdKey] : "";
                var collectionId = _configuration.ContainsKey(CollectionIdKey)
                    ? _configuration[CollectionIdKey] : "";
                var folderName = _configuration.ContainsKey(FolderNameKey)
                    ? _configuration[FolderNameKey] : DefaultFolderName;

                _backend?.Shutdown();
                (_backend as IDisposable)?.Dispose();

                _backend = executionMode.Equals("cli", StringComparison.OrdinalIgnoreCase)
                    ? new BitwardenCliBackend()
                    : new BitwardenServeBackend();

                if (_backend.Initialize(clientId, vaultCred.clientSecret, vaultCred.masterPassword,
                    organizationId, collectionId, folderName, servePort, Logger))
                {
                    Logger.Information($"Plugin {Name} successfully initialized with {executionMode} backend.");
                }
                else
                {
                    Logger.Error($"Failed to initialize {Name} with {executionMode} backend.");
                    _backend.Dispose();
                    _backend = null;
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Invalid credential for {Name}. Expected JSON with 'clientSecret' and 'masterPassword'. {ex.Message}");
            }
        }

        public bool TestVaultConnection()
        {
            if (_backend == null)
                return false;

            try
            {
                var result = _backend.TestConnection();
                Logger.Information($"Test vault connection for {DisplayName}: Result = {result}");
                return result;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed the connection test for {DisplayName}: {ex.Message}.");
                return false;
            }
        }

        public string GetCredential(CredentialType credentialType, string asset, string account, string altAccountName)
        {
            switch (credentialType)
            {
                case CredentialType.Password:
                    return GetPassword(asset, account, altAccountName);
                case CredentialType.SshKey:
                    return GetSshKey(asset, account, altAccountName);
                case CredentialType.ApiKey:
                    Logger.Error($"The {DisplayName} plugin instance does not fetch the ApiKey credential type.");
                    break;
                default:
                    Logger.Error($"Invalid credential type requested from the {DisplayName} plugin instance.");
                    break;
            }

            return null;
        }

        public string SetCredential(CredentialType credentialType, string asset, string account, string[] credential, string altAccountName)
        {
            switch (credentialType)
            {
                case CredentialType.Password:
                    return SetPassword(asset, account, credential, altAccountName);
                case CredentialType.SshKey:
                    return SetSshKey(asset, account, credential, altAccountName);
                case CredentialType.ApiKey:
                    return SetApiKey(asset, account, credential, altAccountName);
                default:
                    Logger.Error($"Invalid credential type sent to the {DisplayName} plugin instance.");
                    break;
            }

            return null;
        }

        public void Unload()
        {
            _backend?.Shutdown();
            (_backend as IDisposable)?.Dispose();
            _backend = null;
            Logger = null;
            _configuration?.Clear();
            _configuration = null;
        }

        private string GetPassword(string asset, string account, string altAccountName)
        {
            if (!ValidationHelper.CanReverseFlow(this) || !ValidationHelper.CanHandlePassword(this))
                return null;

            if (_backend == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            var name = FormatAccountName(altAccountName, asset, account);
            return _backend.FetchCredential(name);
        }

        private string GetSshKey(string asset, string account, string altAccountName)
        {
            if (!ValidationHelper.CanReverseFlow(this) || !ValidationHelper.CanHandleSshKey(this))
                return null;

            if (_backend == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            var name = FormatAccountName(altAccountName, asset, account);
            return _backend.FetchCredential(name);
        }

        private string SetPassword(string asset, string account, string[] password, string altAccountName)
        {
            if (!ValidationHelper.CanHandlePassword(this))
                return null;

            if (_backend == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            if (password is not { Length: 1 })
            {
                Logger.Error($"Invalid or null credential sent to {DisplayName} plugin.");
                return null;
            }

            var name = FormatAccountName(altAccountName, asset, account);
            return _backend.StoreCredential(name, account, password[0]) ? password[0] : null;
        }

        private string SetSshKey(string asset, string account, string[] sshKey, string altAccountName)
        {
            if (!ValidationHelper.CanHandleSshKey(this))
                return null;

            if (_backend == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            if (sshKey is not { Length: 1 })
            {
                Logger.Error($"Invalid or null credential sent to {DisplayName} plugin.");
                return null;
            }

            var name = FormatAccountName(altAccountName, asset, account);
            return _backend.StoreCredential(name, "sshkey", sshKey[0]) ? sshKey[0] : null;
        }

        private string SetApiKey(string asset, string account, string[] apiKeys, string altAccountName)
        {
            if (!ValidationHelper.CanHandleApiKey(this))
                return null;

            if (_backend == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            if (apiKeys == null || apiKeys.Length == 0)
            {
                Logger.Error($"Invalid or null credential sent to {DisplayName} plugin.");
                return null;
            }

            var name = FormatAccountName(altAccountName, asset, account);
            var retval = true;

            foreach (var apiKeyJson in apiKeys)
            {
                var apiKey = JsonHelper.DeserializeObject<ApiKey>(apiKeyJson);
                if (apiKey != null)
                {
                    if (!_backend.StoreCredential($"{name}-{apiKey.Name}", apiKey.ClientId, apiKey.ClientSecret))
                    {
                        Logger.Error($"The ApiKey {name}-{apiKey.Name} failed to save to the {DisplayName} vault.");
                        retval = false;
                    }
                }
                else
                {
                    Logger.Error($"Failed to deserialize ApiKey for {name} in the {DisplayName} plugin.");
                    retval = false;
                }
            }

            return retval ? "" : null;
        }
    }
}
