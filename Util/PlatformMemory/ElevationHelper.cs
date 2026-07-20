using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Archipelago.Core.Util.PlatformMemory
{
    public static class ElevationHelper
    {
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint ERROR_ACCESS_DENIED = 5;
        private const int ERROR_CANCELLED = 1223;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetLastError();

        [DllImport("libc.so.6", EntryPoint = "geteuid", SetLastError = false)]
        private static extern uint geteuid_linux();

        /// <summary>
        /// Returns true if the current process is running with elevated (admin/root) privileges.
        /// </summary>
        public static bool IsElevated()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }

            // Linux/macOS: check effective user id
            try
            {
                return geteuid_linux() == 0;
            }
            catch
            {
                // If the native call fails (e.g. wrong libc path on macOS), fall back
                return false;
            }
        }

        /// <summary>
        /// Probes whether opening the target process requires elevation.
        /// Returns true if OpenProcess fails with ERROR_ACCESS_DENIED, false otherwise.
        /// </summary>
        public static bool RequiresElevation(int processId)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // On Linux/macOS, check if /proc/{pid}/mem is readable
                try
                {
                    Process.GetProcessById(processId);
                    string memPath = $"/proc/{processId}/mem";
                    if (System.IO.File.Exists(memPath))
                    {
                        // Try opening for read to check permissions
                        using var fs = new System.IO.FileStream(memPath, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                        return false;
                    }
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            IntPtr handle = OpenProcess(PROCESS_VM_READ, false, processId);
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                return false;
            }

            uint error = GetLastError();
            return error == ERROR_ACCESS_DENIED;
        }

        /// <summary>
        /// Relaunches the current process with administrator privileges (UAC prompt on Windows).
        /// Calls Environment.Exit(0) on success. Returns false if the user cancels the UAC prompt.
        /// </summary>
        public static bool RestartElevated(string[]? args = null)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // On Linux/macOS, elevation restart is not directly supported from managed code.
                // Callers should instruct the user to re-run with sudo.
                return false;
            }

            try
            {
                string[] passArgs = args ?? Environment.GetCommandLineArgs()[1..];
                var startInfo = new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath,
                    Arguments = string.Join(" ", passArgs),
                    Verb = "runas",
                    UseShellExecute = true
                };

                Process.Start(startInfo);
                Environment.Exit(0);
                return true; // unreachable, but satisfies the compiler
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == ERROR_CANCELLED)
            {
                // User cancelled the UAC prompt
                return false;
            }
        }
    }
}
