using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Archipelago.Core.Util.Config
{
    internal static class IniParser
    {
        /// <summary>
        /// Parses an INI file into a dictionary of section name to key-value pairs.
        /// Section and key names are case-insensitive.
        /// Returns an empty dictionary if the file does not exist.
        /// </summary>
        public static Dictionary<string, Dictionary<string, string>> Parse(string filePath)
        {
            var sections = new Dictionary<string, Dictionary<string, string>>(
                StringComparer.OrdinalIgnoreCase);

            if (!File.Exists(filePath))
                return sections;

            var currentSection = string.Empty;

            foreach (var rawLine in File.ReadAllLines(filePath))
            {
                var line = rawLine.Trim();

                if (string.IsNullOrEmpty(line) || line[0] == ';' || line[0] == '#')
                    continue;

                if (line[0] == '[' && line[^1] == ']')
                {
                    currentSection = line[1..^1].Trim();
                    if (!sections.ContainsKey(currentSection))
                        sections[currentSection] = new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase);
                    continue;
                }

                var eqIndex = line.IndexOf('=');
                if (eqIndex > 0)
                {
                    var key = line[..eqIndex].Trim();
                    var value = line[(eqIndex + 1)..].Trim();

                    if (!sections.ContainsKey(currentSection))
                        sections[currentSection] = new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase);

                    sections[currentSection][key] = value;
                }
            }

            return sections;
        }

        /// <summary>
        /// Writes sections to an INI file, overwriting any existing content.
        /// </summary>
        public static void Write(string filePath,
            Dictionary<string, Dictionary<string, string>> sections)
        {
            using var writer = new StreamWriter(filePath, false, Encoding.UTF8);
            var first = true;
            foreach (var section in sections)
            {
                if (!first) writer.WriteLine();
                first = false;

                writer.WriteLine($"[{section.Key}]");
                foreach (var kvp in section.Value)
                {
                    writer.WriteLine($"{kvp.Key}={kvp.Value}");
                }
            }
        }
    }
}
