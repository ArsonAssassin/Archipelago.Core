using Archipelago.Core.Util.PlatformMemory;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util.PlatformMemory
{
    public class PlatformMemory
    {
        private static nint _currentHandle;
        private static int _currentProcessId = 0;
        internal static IInvocableMemory PlatformImpl { get; }

        #region Constants
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_SUSPEND_RESUME = 0x0800;

        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        public const uint MEM_RELEASE = 0x00008000;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_TOP_DOWN = 0x00100000;
        #endregion

        #region Process Management
        public static int CurrentProcId { get; set; }
        public static ulong GlobalOffset { get; set; } = 0;
        static PlatformMemory()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                PlatformImpl = new LinuxMemory();
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                PlatformImpl = new MacOSMemory();
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                PlatformImpl = new WindowsMemory();
            else
                throw new PlatformNotSupportedException();
        }
        public static IntPtr CurrentHandle()
        {
            if (_currentHandle == IntPtr.Zero || _currentProcessId != CurrentProcId)
            {
                _currentHandle = GetProcessH(CurrentProcId);
                _currentProcessId = CurrentProcId;
            }
            return (nint)_currentHandle;
        }
        public static void CloseCurrentHandle()
        {
            if (_currentHandle != IntPtr.Zero)
            {
                PlatformImpl.CloseHandle(_currentHandle);
            }
        }
        internal static IntPtr GetProcessH(int proc)
        {
            if (proc == 0) throw new ArgumentException("CurrentProcId has not been set");
            uint flags = PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD;
            var handle = PlatformImpl.OpenProcess(flags, false, proc);
            if (handle == IntPtr.Zero)
            {
                uint error = PlatformImpl.GetLastError();
                if (error == 5) // ERROR_ACCESS_DENIED
                    throw new ElevationRequiredException(proc);
                throw new InvalidOperationException(
                    $"Failed to open process {proc}: {PlatformImpl.GetLastErrorMessage()}");
            }
            return handle;
        }

        public static int GetProcessID(string procName)
        {
            int procPID = PlatformImpl.GetPID(procName);
            if (procPID > 0)
            {
                return procPID;
            }
            else
            {
                return GetProcFromIdFromPartial(procName);
            }
        }
        public static List<int> GetProcessIDs(string procName)
        {
            List<int> procPIDlist = PlatformImpl.GetPIDs(procName);
            if (procPIDlist.Count > 0)
            {
                return procPIDlist;
            }
            else
            {
                return GetProcFromIdsFromPartial(procName);
            }
        }
        public static int GetProcFromIdFromPartial(string procPartialName)
        {
            Log.Debug("Find Process ID {ProcessName}", procPartialName);
            Process[] allProcesses = Process.GetProcesses();

            List<Process> foundProcesses = allProcesses
                .Where(p => p.ProcessName.Contains(procPartialName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (foundProcesses.Count >= 1)
            {
                return foundProcesses[0].Id;
            }
            else
            {
                PlatformImpl.CloseHandle(CurrentHandle());
                return 0;
            }

        }
        public static List<int> GetProcFromIdsFromPartial(string procPartialName)
        {
            Log.Debug("Find Process ID {ProcessName}", procPartialName);
            Process[] allProcesses = Process.GetProcesses();

            List<Process> foundProcesses = allProcesses
                .Where(p => p.ProcessName.Contains(procPartialName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (foundProcesses.Count >= 1)
            {
                return foundProcesses.Select(x => x.Id).ToList();
            }
            else
            {
                PlatformImpl.CloseHandle(CurrentHandle());
                return [];
            }

        }
        public static ulong GetPCSX2Offset()
        {
            return PCSX2.Helpers.GetEEmemOffset();
        }
        public static ulong GetDuckstationOffset()
        {
            return Duckstation.Helpers.GetEEmemOffset();
        }
        public static Process GetProcessById(int id)
        {
            return Process.GetProcessById(id);
        }

        public static Process GetCurrentProcess()
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return GetProcessById(CurrentProcId);
        }

        public static ulong GetBaseAddress(string modName)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            var process = Process.GetProcessById(CurrentProcId);
            return (ulong)(process.Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(x => x.ModuleName.Contains(modName, StringComparison.OrdinalIgnoreCase))
                ?.BaseAddress ?? IntPtr.Zero);
        }

        public static string GetLastErrorMessage()
        {
            return PlatformImpl.GetLastErrorMessage();
        }
        #endregion

        #region Memory Operations
        public static bool FreezeAddress(ulong address, int length)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.VirtualProtectEx(CurrentHandle(), (IntPtr)address, (IntPtr)length, PAGE_READONLY, out var oldProtect);
        }

        public static bool UnfreezeAddress(ulong address, int length)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.VirtualProtectEx(CurrentHandle(), (IntPtr)address, (IntPtr)length, PAGE_READWRITE, out var oldProtect);
        }

        public static IntPtr Allocate(uint size, uint flProtect = PAGE_READWRITE)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.VirtualAllocEx(CurrentHandle(), IntPtr.Zero, (IntPtr)size, MEM_COMMIT, flProtect);
        }

        public static IntPtr AllocateAbove(uint size)
        {
            IntPtr freeAddress = PlatformImpl.FindFreeRegionBelow4GB(CurrentHandle(), size);
            return PlatformImpl.VirtualAllocEx(CurrentHandle(), freeAddress, (IntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        public static bool FreeMemory(IntPtr address)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.VirtualFreeEx(CurrentHandle(), address, IntPtr.Zero, MEM_RELEASE);
        }
        #endregion
        #region Remote Execution
        private static uint Execute(IntPtr address, uint timeoutSeconds = 0xFFFFFFFF)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.Execute(CurrentHandle(), address, timeoutSeconds);
        }

        public static uint ExecuteCommand(byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.ExecuteCommand(CurrentHandle(), bytes, timeoutSeconds);
        }
        #endregion

        #region Module Information
        public static MODULEINFO GetModuleInfo(string moduleName)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.GetModuleInfo(CurrentHandle(), moduleName);
        }
        public static IntPtr GetModuleBaseAddress(int pid, string moduleName)
        {
            return PlatformImpl.GetModuleBaseAddress(pid, moduleName);
        }
        public static IntPtr GetExportAddress(int pid, IntPtr moduleBase, string exportName)
        {
            return PlatformImpl.GetExportAddress(pid, moduleBase, exportName);
        }
        #endregion

        #region Common Process IDs
        public static int BIZHAWK_PROCESSID => GetProcessID("EmuHawk");
        public static int EPSXE_PROCESSID => GetProcessID("ePSXe");
        public static int PCSX2_PROCESSID
        {
            get
            {
                var pid = GetProcessID("pcsx2");
                if (pid == 0)
                {
                    pid = GetProcessID("pcsx2-qt");
                }
                return pid;
            }
        }
        public static int XENIA_PROCESSID => GetProcessID("Xenia");

        public static int GetProcIdFromExe(string exe) => GetProcessID(exe);
        public static List<int> GetProcIdsFromExe(string exe) => GetProcessIDs(exe);
        #endregion
    }
}
