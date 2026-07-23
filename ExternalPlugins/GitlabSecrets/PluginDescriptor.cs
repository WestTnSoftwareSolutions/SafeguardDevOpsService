using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using OneIdentity.DevOps.Common;
using Serilog;

namespace OneIdentity.DevOps.GitlabSecrets
{
    public class PluginDescriptor : ILoadablePlugin
    {
        private HttpClient _httpClient;
        private Dictionary<string, string> _configuration;
        private Regex _rgx;
        private string _token;

        private const string ServerUrlKey = "serverUrl";
        private const string ProjectIdKey = "projectId";
        private const string ProtectedKey = "protected";
        private const string MaskedKey = "masked";
        private const string EnvironmentScopeKey = "environmentScope";

        private const string DefaultServerUrl = "https://gitlab.com";
        private const string DefaultProtected = "false";
        private const string DefaultMasked = "true";
        private const string DefaultEnvironmentScope = "*";

        private string FormatVariableName(string altAccountName, string asset, string account)
        {
            var raw = altAccountName ?? $"{asset}_{account}";
            return _rgx.Replace(raw, "_").ToUpperInvariant();
        }

        public string Name => "GitlabSecrets";
        public string DisplayName => "GitLab CI/CD Variables";
        public string Description => "This is the GitLab CI/CD Variables plugin for pushing and pulling credentials";
        public bool SupportsReverseFlow => true;
        public CredentialType[] SupportedCredentialTypes => new[] { CredentialType.Password, CredentialType.SshKey, CredentialType.ApiKey };

        public CredentialType AssignedCredentialType { get; set; } = CredentialType.Password;
        public bool ReverseFlowEnabled { get; set; } = false;
        public ILogger Logger { get; set; }

        public Dictionary<string, string> GetPluginInitialConfiguration()
        {
            return _configuration ??= new Dictionary<string, string>
            {
                { ServerUrlKey, DefaultServerUrl },
                { ProjectIdKey, "" },
                { ProtectedKey, DefaultProtected },
                { MaskedKey, DefaultMasked },
                { EnvironmentScopeKey, DefaultEnvironmentScope }
            };
        }

        public void SetPluginConfiguration(Dictionary<string, string> configuration)
        {
            if (configuration != null && configuration.ContainsKey(ProjectIdKey) &&
                !string.IsNullOrEmpty(configuration[ProjectIdKey]))
            {
                _configuration = configuration;
                _rgx = new Regex("[^a-zA-Z0-9_]");
                Logger.Information($"Plugin {Name} has been successfully configured.");
            }
            else
            {
                Logger.Error("Some parameters are missing from the configuration. The projectId is required.");
            }
        }

        public void SetVaultCredential(string credential)
        {
            if (_configuration == null || string.IsNullOrEmpty(credential))
            {
                Logger.Error("The plugin configuration or credential is missing.");
                return;
            }

            try
            {
                _token = credential;

                var serverUrl = _configuration.ContainsKey(ServerUrlKey)
                    ? _configuration[ServerUrlKey] : DefaultServerUrl;

                _httpClient?.Dispose();
                _httpClient = new HttpClient
                {
                    BaseAddress = new Uri(serverUrl.TrimEnd('/')),
                    Timeout = TimeSpan.FromSeconds(30)
                };
                _httpClient.DefaultRequestHeaders.Add("PRIVATE-TOKEN", _token);

                Logger.Information($"Plugin {Name} successfully authenticated to GitLab.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Invalid configuration for {Name}: {ex.Message}");
            }
        }

        public bool TestVaultConnection()
        {
            if (_httpClient == null)
                return false;

            try
            {
                var projectId = Uri.EscapeDataString(_configuration[ProjectIdKey]);
                var response = InvokeApi(HttpMethod.Get, $"/api/v4/projects/{projectId}/variables");

                if (response != null)
                {
                    Logger.Information($"Test vault connection for {DisplayName}: Success.");
                    return true;
                }

                Logger.Error($"Failed the connection test for {DisplayName}.");
                return false;
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
            _httpClient?.Dispose();
            _httpClient = null;
            _token = null;
            Logger = null;
            _configuration?.Clear();
            _configuration = null;
        }

        private string GetPassword(string asset, string account, string altAccountName)
        {
            if (!ValidationHelper.CanReverseFlow(this) || !ValidationHelper.CanHandlePassword(this))
                return null;

            return FetchVariable(FormatVariableName(altAccountName, asset, account));
        }

        private string GetSshKey(string asset, string account, string altAccountName)
        {
            if (!ValidationHelper.CanReverseFlow(this) || !ValidationHelper.CanHandleSshKey(this))
                return null;

            return FetchVariable(FormatVariableName(altAccountName, asset, account));
        }

        private string SetPassword(string asset, string account, string[] password, string altAccountName)
        {
            if (!ValidationHelper.CanHandlePassword(this))
                return null;

            if (_httpClient == null || _configuration == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            if (password is not { Length: 1 })
            {
                Logger.Error($"Invalid or null credential sent to {DisplayName} plugin.");
                return null;
            }

            var key = FormatVariableName(altAccountName, asset, account);
            return StoreVariable(key, password[0], "env_var") ? password[0] : null;
        }

        private string SetSshKey(string asset, string account, string[] sshKey, string altAccountName)
        {
            if (!ValidationHelper.CanHandleSshKey(this))
                return null;

            if (_httpClient == null || _configuration == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            if (sshKey is not { Length: 1 })
            {
                Logger.Error($"Invalid or null credential sent to {DisplayName} plugin.");
                return null;
            }

            var key = FormatVariableName(altAccountName, asset, account);
            return StoreVariable(key, sshKey[0], "file") ? sshKey[0] : null;
        }

        private string SetApiKey(string asset, string account, string[] apiKeys, string altAccountName)
        {
            if (!ValidationHelper.CanHandleApiKey(this))
                return null;

            if (_httpClient == null || _configuration == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            if (apiKeys == null || apiKeys.Length == 0)
            {
                Logger.Error($"Invalid or null credential sent to {DisplayName} plugin.");
                return null;
            }

            var baseName = FormatVariableName(altAccountName, asset, account);
            var retval = true;

            foreach (var apiKeyJson in apiKeys)
            {
                var apiKey = JsonHelper.DeserializeObject<ApiKey>(apiKeyJson);
                if (apiKey != null)
                {
                    var key = $"{baseName}_{_rgx.Replace(apiKey.Name, "_").ToUpperInvariant()}";
                    if (!StoreVariable(key, $"{apiKey.ClientId}:{apiKey.ClientSecret}", "env_var"))
                    {
                        Logger.Error($"The ApiKey {key} failed to save to the {DisplayName} vault.");
                        retval = false;
                    }
                }
                else
                {
                    Logger.Error($"Failed to deserialize ApiKey for {baseName} in the {DisplayName} plugin.");
                    retval = false;
                }
            }

            return retval ? "" : null;
        }

        private bool StoreVariable(string key, string value, string variableType)
        {
            var projectId = Uri.EscapeDataString(_configuration[ProjectIdKey]);
            var masked = _configuration.ContainsKey(MaskedKey)
                ? _configuration[MaskedKey] : DefaultMasked;
            var isProtected = _configuration.ContainsKey(ProtectedKey)
                ? _configuration[ProtectedKey] : DefaultProtected;
            var envScope = _configuration.ContainsKey(EnvironmentScopeKey)
                ? _configuration[EnvironmentScopeKey] : DefaultEnvironmentScope;

            var body = JsonConvert.SerializeObject(new
            {
                key,
                value,
                variable_type = variableType,
                masked = masked.Equals("true", StringComparison.OrdinalIgnoreCase),
                @protected = isProtected.Equals("true", StringComparison.OrdinalIgnoreCase),
                environment_scope = envScope
            });

            var encodedKey = Uri.EscapeDataString(key);

            // Try PUT (update) first — most operations are rotations of existing secrets
            var response = InvokeApi(HttpMethod.Put,
                $"/api/v4/projects/{projectId}/variables/{encodedKey}", body);

            if (response != null)
            {
                Logger.Information($"Updated variable {key} in GitLab project {_configuration[ProjectIdKey]}.");
                return true;
            }

            // PUT failed (likely 404 — variable doesn't exist yet), try POST (create)
            response = InvokeApi(HttpMethod.Post,
                $"/api/v4/projects/{projectId}/variables", body);

            if (response != null)
            {
                Logger.Information($"Created variable {key} in GitLab project {_configuration[ProjectIdKey]}.");
                return true;
            }

            Logger.Error($"Failed to store variable {key} in GitLab project {_configuration[ProjectIdKey]}.");
            return false;
        }

        private string FetchVariable(string key)
        {
            if (_httpClient == null || _configuration == null)
            {
                Logger.Error($"No vault connection. Make sure that the {DisplayName} plugin has been configured.");
                return null;
            }

            var projectId = Uri.EscapeDataString(_configuration[ProjectIdKey]);
            var encodedKey = Uri.EscapeDataString(key);

            var response = InvokeApi(HttpMethod.Get,
                $"/api/v4/projects/{projectId}/variables/{encodedKey}");

            if (response == null)
            {
                Logger.Error($"Failed to fetch variable {key} from GitLab project {_configuration[ProjectIdKey]}.");
                return null;
            }

            try
            {
                dynamic variable = JsonConvert.DeserializeObject(response);
                string value = variable?.value;

                if (value != null)
                {
                    Logger.Information($"Fetched variable {key} from GitLab project {_configuration[ProjectIdKey]}.");
                    return value;
                }

                Logger.Error($"Variable {key} has no value in GitLab project {_configuration[ProjectIdKey]}.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to parse variable {key}: {ex.Message}.");
            }

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

                if (response.IsSuccessStatusCode)
                    return content;

                Logger.Debug("GitLab API {Method} {Path} returned {StatusCode}: {Body}",
                    method, path, response.StatusCode, content);
                return null;
            }
            catch (Exception ex)
            {
                Logger.Debug("GitLab API {Method} {Path} failed: {Message}", method, path, ex.Message);
                return null;
            }
        }
    }
}
