using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Serilog;

namespace OneIdentity.DevOps.BitwardenVault
{
    internal class BitwardenProcessManager : IDisposable
    {
        private readonly string _bwPath;
        private readonly ILogger _logger;
        private Process _serveProcess;
        private readonly object _serveLock = new object();

        public BitwardenProcessManager(ILogger logger)
        {
            _logger = logger;
            _bwPath = FindBwExecutable();
        }

        public bool IsServeRunning
        {
            get
            {
                lock (_serveLock)
                {
                    return _serveProcess != null && !_serveProcess.HasExited;
                }
            }
        }

        public static string FindBwExecutable()
        {
            var assemblyDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var binaryName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "bw.exe" : "bw";
            var path = Path.Combine(assemblyDir, "tools", binaryName);

            if (!File.Exists(path))
                throw new FileNotFoundException($"Bitwarden CLI not found at: {path}");

            return path;
        }

        public (int exitCode, string stdout, string stderr) ExecuteCommand(
            string arguments,
            Dictionary<string, string> envVars = null,
            TimeSpan? timeout = null)
        {
            var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(30);

            var startInfo = new ProcessStartInfo
            {
                FileName = _bwPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            if (envVars != null)
            {
                foreach (var kv in envVars)
                {
                    startInfo.Environment[kv.Key] = kv.Value;
                }
            }

            _logger.Debug("Executing bw command: bw {Arguments}", arguments);

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();

            if (!process.WaitForExit((int)effectiveTimeout.TotalMilliseconds))
            {
                process.Kill();
                _logger.Error("Bitwarden CLI command timed out after {Timeout}s: bw {Arguments}",
                    effectiveTimeout.TotalSeconds, arguments);
                return (-1, stdout, "Command timed out");
            }

            if (process.ExitCode != 0)
            {
                _logger.Debug("bw command exited with code {ExitCode}: {Stderr}", process.ExitCode, stderr);
            }

            return (process.ExitCode, stdout, stderr);
        }

        public bool Login(string clientId, string clientSecret)
        {
            var envVars = new Dictionary<string, string>
            {
                { "BW_CLIENTID", clientId },
                { "BW_CLIENTSECRET", clientSecret }
            };

            var (exitCode, stdout, stderr) = ExecuteCommand("login --apikey", envVars);

            if (exitCode == 0)
            {
                _logger.Information("Successfully logged in to Bitwarden.");
                return true;
            }

            if (stderr.Contains("You are already logged in"))
            {
                _logger.Information("Already logged in to Bitwarden.");
                return true;
            }

            _logger.Error("Failed to log in to Bitwarden: {Error}", stderr);
            return false;
        }

        public string Unlock(string masterPassword)
        {
            var envVars = new Dictionary<string, string>
            {
                { "BW_PASSWORD", masterPassword }
            };

            var (exitCode, stdout, stderr) = ExecuteCommand("unlock --passwordenv BW_PASSWORD --raw", envVars);

            if (exitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
            {
                _logger.Information("Successfully unlocked Bitwarden vault.");
                return stdout.Trim();
            }

            _logger.Error("Failed to unlock Bitwarden vault: {Error}", stderr);
            return null;
        }

        public bool StartServe(int port, string sessionKey)
        {
            lock (_serveLock)
            {
                if (_serveProcess != null && !_serveProcess.HasExited)
                {
                    _logger.Debug("bw serve is already running on port {Port}.", port);
                    return true;
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = _bwPath,
                    Arguments = $"serve --port {port} --hostname 127.0.0.1",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                startInfo.Environment["BW_SESSION"] = sessionKey;

                _serveProcess = new Process { StartInfo = startInfo };

                try
                {
                    _serveProcess.Start();
                    _logger.Information("Started bw serve on port {Port} (PID: {Pid}).", port, _serveProcess.Id);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to start bw serve: {Message}", ex.Message);
                    _serveProcess = null;
                    return false;
                }
            }
        }

        public void StopServe()
        {
            lock (_serveLock)
            {
                if (_serveProcess == null)
                    return;

                try
                {
                    if (!_serveProcess.HasExited)
                    {
                        _serveProcess.Kill();
                        _serveProcess.WaitForExit(5000);
                        _logger.Information("Stopped bw serve process.");
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error stopping bw serve: {Message}", ex.Message);
                }
                finally
                {
                    _serveProcess.Dispose();
                    _serveProcess = null;
                }
            }
        }

        public void Logout()
        {
            ExecuteCommand("logout");
        }

        public void Dispose()
        {
            StopServe();
        }
    }
}
