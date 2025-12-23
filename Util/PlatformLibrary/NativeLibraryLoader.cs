using Archipelago.Core.Models;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.PlatformLibrary
{
    public static class NativeLibraryLoader
    {
        private static readonly Dictionary<string, Libfile> _libFiles = new()
        {
            ["glfw3"] = new Libfile
            {
                linuxx64 = "libglfw.so",
                osxx64 = "libglfw.3.dylib",
                winx64 = "glfw3.dll",
                winx86 = "glfw3.dll"
            }
        };
        static NativeLibraryLoader()
        {
            NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), DllImportResolver);
            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    NativeLibrary.SetDllImportResolver(assembly, DllImportResolver);
                }
                catch
                {
                    // Some assemblies might not allow this, ignore them
                }
            }
        }
        public static void Initialize()
        {
            foreach (var lib in _libFiles.Values)
            {
                ExtractLibrary(lib, Assembly.GetExecutingAssembly());
            }
        }
        private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            // Normalize library name (remove extensions, lib prefixes)
            var normalizedName = NormalizeLibraryName(libraryName);

            if (!_libFiles.TryGetValue(normalizedName, out var libFile))
                return IntPtr.Zero;

            return ExtractLibrary(libFile, assembly);
        }

        private static string NormalizeLibraryName(string libraryName)
        {
            // Remove common extensions and prefixes
            var name = libraryName
                .Replace(".dll", "")
                .Replace(".so", "")
                .Replace(".dylib", "");

            if (name.StartsWith("lib"))
                name = name.Substring(3);

            return name;
        }
        private static IntPtr ExtractLibrary(Libfile libFile, Assembly assembly)
        {
            var rid = GetRuntimeIdentifier();
            var platformLibName = GetPlatformLibraryName(libFile, rid);

            if (string.IsNullOrEmpty(platformLibName))
                return IntPtr.Zero;

            var resourceName = $"Archipelago.Core.Libfiles.{rid}.{platformLibName}";
            var targetPath = Path.Combine(Path.GetTempPath(), "Archipelago.Core.Libfiles", rid, platformLibName);

            if (!File.Exists(targetPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);

                using var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream == null)
                {
                    // Fallback: let the system try to find it
                    return IntPtr.Zero;
                }

                using var fileStream = File.Create(targetPath);
                stream.CopyTo(fileStream);
            }

            return NativeLibrary.Load(targetPath);
        }
        private static string? GetPlatformLibraryName(Libfile libFile, string rid)
        {
            return rid switch
            {
                "win-x64" => libFile.winx64,
                "win-x86" => libFile.winx86,
                "linux-x64" => libFile.linuxx64,
                "osx-x64" => libFile.osxx64,
                _ => null
            };
        }

        private static string GetRuntimeIdentifier()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "win-x64" : "win-x86";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return "linux-x64";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return "osx-x64";
            throw new PlatformNotSupportedException();
        }
    }
}
