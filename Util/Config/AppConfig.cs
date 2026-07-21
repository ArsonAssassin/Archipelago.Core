using Serilog;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Archipelago.Core.Util.Config
{
    public class AppConfig
    {
        private const string DefaultFileName = "config.ini";

        private static AppConfig? _instance;
        private static readonly object _lock = new();
        private static string? _customFilePath;

        private readonly string _filePath;
        private Dictionary<string, Dictionary<string, string>> _rawData;

        private readonly Dictionary<string, object> _customSections = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Func<Dictionary<string, string>, object>> _sectionLoaders = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Func<object, Dictionary<string, string>>> _sectionSerializers = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Logging settings ([Logging] section).
        /// </summary>
        public LoggingConfig Logging { get; private set; } = new();

        /// <summary>
        /// Connection settings ([Connection] section).
        /// </summary>
        public ConnectionConfig Connection { get; private set; } = new();

        /// <summary>
        /// Overlay settings ([Overlay] section).
        /// </summary>
        public OverlayConfig Overlay { get; private set; } = new();

        /// <summary>
        /// Gets the singleton instance, lazy-loaded from config.ini next to the executable.
        /// Thread-safe.
        /// </summary>
        public static AppConfig Current
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance ??= new AppConfig(
                            _customFilePath ?? Path.Combine(AppContext.BaseDirectory, DefaultFileName));
                    }
                }
                return _instance;
            }
        }

        /// <summary>
        /// Sets a custom file path. Must be called before any access to Current.
        /// </summary>
        public static void SetFilePath(string filePath)
        {
            lock (_lock)
            {
                if (_instance != null)
                    throw new InvalidOperationException(
                        "Cannot change file path after config has been loaded. Call SetFilePath before accessing AppConfig.Current.");
                _customFilePath = filePath;
            }
        }

        /// <summary>
        /// Loads (or reloads) config from the specified path, or the default location.
        /// Replaces the singleton instance.
        /// </summary>
        public static AppConfig Load(string? filePath = null)
        {
            var resolvedPath = filePath
                ?? _customFilePath
                ?? Path.Combine(AppContext.BaseDirectory, DefaultFileName);

            var config = new AppConfig(resolvedPath);

            lock (_lock)
            {
                _instance = config;
            }

            return config;
        }

        /// <summary>
        /// Re-reads the config file from disk and re-populates all sections,
        /// including any registered custom sections.
        /// </summary>
        public void Reload()
        {
            _rawData = IniParser.Parse(_filePath);
            Logging = LoadLoggingSection();
            Connection = LoadConnectionSection();
            Overlay = LoadOverlaySection();
            ReloadCustomSections();
        }

        /// <summary>
        /// Saves the current config state back to the INI file.
        /// Includes both built-in and registered custom sections.
        /// Creates the file if it does not exist.
        /// </summary>
        public void Save()
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(directory) && !IsDirectoryWritable(directory))
            {
                Log.Warning("Config directory {Directory} is not writable. Config will not be saved. Run as administrator or choose a different config path.", directory);
                return;
            }

            var sections = new Dictionary<string, Dictionary<string, string>>(
                StringComparer.OrdinalIgnoreCase)
            {
                ["Logging"] = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["LogLevel"] = Logging.LogLevel.ToString()
                },
                ["Connection"] = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["Host"] = Connection.Host,
                    ["Slot"] = Connection.Slot,
                    ["Password"] = Connection.Password
                },
                ["Overlay"] = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["XOffset"] = Overlay.XOffset.ToString(CultureInfo.InvariantCulture),
                    ["YOffset"] = Overlay.YOffset.ToString(CultureInfo.InvariantCulture),
                    ["FontSize"] = Overlay.FontSize.ToString(CultureInfo.InvariantCulture),
                    ["FadeDuration"] = Overlay.FadeDuration.ToString(CultureInfo.InvariantCulture),
                    ["DefaultTextColorR"] = Overlay.DefaultTextColorR.ToString(),
                    ["DefaultTextColorG"] = Overlay.DefaultTextColorG.ToString(),
                    ["DefaultTextColorB"] = Overlay.DefaultTextColorB.ToString(),
                    ["DefaultTextColorA"] = Overlay.DefaultTextColorA.ToString()
                }
            };

            foreach (var kvp in _customSections)
            {
                if (_sectionSerializers.TryGetValue(kvp.Key, out var serializer))
                {
                    sections[kvp.Key] = new Dictionary<string, string>(
                        serializer(kvp.Value), StringComparer.OrdinalIgnoreCase);
                }
            }

            IniParser.Write(_filePath, sections);
        }

        /// <summary>
        /// Registers a custom config section with a loader and serializer.
        /// If the config file has already been parsed, the loader runs immediately
        /// against the existing raw data.
        /// </summary>
        /// <typeparam name="T">The section POCO type.</typeparam>
        /// <param name="sectionName">The INI section name (e.g. "MyGame").</param>
        /// <param name="loader">Converts the raw key-value dictionary into a T instance.</param>
        /// <param name="serializer">Converts a T instance back into a key-value dictionary for saving.</param>
        public void RegisterSection<T>(string sectionName,
            Func<Dictionary<string, string>, T> loader,
            Func<T, Dictionary<string, string>> serializer) where T : class
        {
            _sectionLoaders[sectionName] = raw => loader(raw);
            _sectionSerializers[sectionName] = obj => serializer((T)obj);

            var raw = GetRawSection(sectionName) ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _customSections[sectionName] = loader(raw);
        }

        /// <summary>
        /// Retrieves a previously registered custom section by name.
        /// Returns null if the section has not been registered.
        /// </summary>
        public T? GetSection<T>(string sectionName) where T : class
        {
            if (_customSections.TryGetValue(sectionName, out var section))
                return section as T;
            return null;
        }

        /// <summary>
        /// Returns the raw key-value pairs for any section in the INI file.
        /// No registration required. Returns null if the section does not exist.
        /// </summary>
        public Dictionary<string, string>? GetRawSection(string sectionName)
        {
            if (_rawData.TryGetValue(sectionName, out var section))
                return new Dictionary<string, string>(section, StringComparer.OrdinalIgnoreCase);
            return null;
        }

        private AppConfig(string filePath)
        {
            _filePath = filePath;
            _rawData = IniParser.Parse(filePath);
            Logging = LoadLoggingSection();
            Connection = LoadConnectionSection();
            Overlay = LoadOverlaySection();

            if (!File.Exists(filePath))
                Save();
        }

        private void ReloadCustomSections()
        {
            foreach (var kvp in _sectionLoaders)
            {
                var raw = GetRawSection(kvp.Key)
                    ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                _customSections[kvp.Key] = kvp.Value(raw);
            }
        }

        private LoggingConfig LoadLoggingSection()
        {
            var config = new LoggingConfig();
            if (_rawData.TryGetValue("Logging", out var section))
            {
                if (section.TryGetValue("LogLevel", out var levelStr)
                    && Enum.TryParse<LogEventLevel>(levelStr, true, out var level))
                {
                    config.LogLevel = level;
                }
            }
            return config;
        }

        private ConnectionConfig LoadConnectionSection()
        {
            var config = new ConnectionConfig();
            if (_rawData.TryGetValue("Connection", out var section))
            {
                if (section.TryGetValue("Host", out var host) && !string.IsNullOrWhiteSpace(host))
                    config.Host = host;
                if (section.TryGetValue("Slot", out var slot))
                    config.Slot = slot;
                if (section.TryGetValue("Password", out var password))
                    config.Password = password;
            }
            return config;
        }

        private OverlayConfig LoadOverlaySection()
        {
            var config = new OverlayConfig();
            if (_rawData.TryGetValue("Overlay", out var section))
            {
                if (section.TryGetValue("XOffset", out var xo)
                    && float.TryParse(xo, NumberStyles.Float, CultureInfo.InvariantCulture, out var xVal))
                    config.XOffset = xVal;
                if (section.TryGetValue("YOffset", out var yo)
                    && float.TryParse(yo, NumberStyles.Float, CultureInfo.InvariantCulture, out var yVal))
                    config.YOffset = yVal;
                if (section.TryGetValue("FontSize", out var fs)
                    && float.TryParse(fs, NumberStyles.Float, CultureInfo.InvariantCulture, out var fsVal))
                    config.FontSize = fsVal;
                if (section.TryGetValue("FadeDuration", out var fd)
                    && float.TryParse(fd, NumberStyles.Float, CultureInfo.InvariantCulture, out var fdVal))
                    config.FadeDuration = fdVal;
                if (section.TryGetValue("DefaultTextColorR", out var r) && byte.TryParse(r, out var rVal))
                    config.DefaultTextColorR = rVal;
                if (section.TryGetValue("DefaultTextColorG", out var g) && byte.TryParse(g, out var gVal))
                    config.DefaultTextColorG = gVal;
                if (section.TryGetValue("DefaultTextColorB", out var b) && byte.TryParse(b, out var bVal))
                    config.DefaultTextColorB = bVal;
                if (section.TryGetValue("DefaultTextColorA", out var a) && byte.TryParse(a, out var aVal))
                    config.DefaultTextColorA = aVal;
            }
            return config;
        }

        private static bool IsDirectoryWritable(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }
                var testFile = Path.Combine(path, $".write_test_{Guid.NewGuid():N}");
                File.WriteAllText(testFile, "");
                File.Delete(testFile);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }
    }
}
