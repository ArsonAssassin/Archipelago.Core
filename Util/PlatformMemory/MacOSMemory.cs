using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util.PlatformMemory
{
    public class MacOSMemory : IMemory
    {
        #region Constants
        // ptrace requests (BSD-style)
        private const int PT_TRACE_ME = 0;
        private const int PT_READ_I = 1;
        private const int PT_READ_D = 2;
        private const int PT_WRITE_I = 3;
        private const int PT_WRITE_D = 4;
        private const int PT_CONTINUE = 7;
        private const int PT_KILL = 8;
        private const int PT_STEP = 9;
        private const int PT_ATTACH = 10;
        private const int PT_DETACH = 11;
        private const int PT_SIGEXC = 12;
        private const int PT_THUPDATE = 13;
        private const int PT_ATTACHEXC = 14;

        // Memory protection flags
        private const int VM_PROT_NONE = 0x00;
        private const int VM_PROT_READ = 0x01;
        private const int VM_PROT_WRITE = 0x02;
        private const int VM_PROT_EXECUTE = 0x04;
        private const int VM_PROT_ALL = 0x07;

        // Mach kernel return codes
        private const int KERN_SUCCESS = 0;
        private const int KERN_INVALID_ADDRESS = 1;
        private const int KERN_PROTECTION_FAILURE = 2;
        private const int KERN_NO_SPACE = 3;
        private const int KERN_INVALID_ARGUMENT = 4;
        private const int KERN_FAILURE = 5;

        // Memory allocation flags
        private const int VM_FLAGS_ANYWHERE = 0x0001;
        private const int VM_FLAGS_FIXED = 0x0000;

        // Windows compatibility constants
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_READONLY = 0x02;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RELEASE = 0x00008000;

        // Mach port types
        private const int MACH_PORT_NULL = 0;
        #endregion

        #region Structures
        [StructLayout(LayoutKind.Sequential)]
        public struct vm_region_basic_info_64
        {
            public int protection;
            public int max_protection;
            public uint inheritance;
            public uint shared;
            public uint reserved;
            public ulong offset;
            public int behavior;
            public ushort user_wired_count;
        }

        // x86_64 thread state
        [StructLayout(LayoutKind.Sequential)]
        public struct x86_thread_state64_t
        {
            public ulong rax, rbx, rcx, rdx;
            public ulong rdi, rsi, rbp, rsp;
            public ulong r8, r9, r10, r11;
            public ulong r12, r13, r14, r15;
            public ulong rip, rflags;
            public ulong cs, fs, gs;
        }

        // ARM64 thread state (for Apple Silicon)
        [StructLayout(LayoutKind.Sequential)]
        public struct arm_thread_state64_t
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 29)]
            public ulong[] x;
            public ulong fp;
            public ulong lr;
            public ulong sp;
            public ulong pc;
            public ulong cpsr;
            public uint flags;
        }

        [Flags]
        public enum MemoryState : uint
        {
            Free = 0x10000,
            Reserve = 0x2000,
            Commit = 0x1000,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        #endregion

        #region Native Methods - Mach VM
        [DllImport("libSystem.dylib", EntryPoint = "mach_task_self", SetLastError = false)]
        private static extern int mach_task_self();

        [DllImport("libSystem.dylib", EntryPoint = "task_for_pid", SetLastError = false)]
        private static extern int task_for_pid(int target_tport, int pid, out int task);

        [DllImport("libSystem.dylib", EntryPoint = "mach_vm_read_overwrite", SetLastError = false)]
        private static extern int mach_vm_read_overwrite(int target_task, ulong address, ulong size,
            IntPtr data, out ulong outsize);

        [DllImport("libSystem.dylib", EntryPoint = "mach_vm_write", SetLastError = false)]
        private static extern int mach_vm_write(int target_task, ulong address, IntPtr data, uint dataCnt);

        [DllImport("libSystem.dylib", EntryPoint = "mach_vm_allocate", SetLastError = false)]
        private static extern int mach_vm_allocate(int target_task, ref ulong address, ulong size, int flags);

        [DllImport("libSystem.dylib", EntryPoint = "mach_vm_deallocate", SetLastError = false)]
        private static extern int mach_vm_deallocate(int target_task, ulong address, ulong size);

        [DllImport("libSystem.dylib", EntryPoint = "mach_vm_protect", SetLastError = false)]
        private static extern int mach_vm_protect(int target_task, ulong address, ulong size,
            bool set_maximum, int new_protection);

        [DllImport("libSystem.dylib", EntryPoint = "mach_vm_region", SetLastError = false)]
        private static extern int mach_vm_region(int target_task, ref ulong address, ref ulong size,
            int flavor, ref vm_region_basic_info_64 info, ref uint infoCnt, ref int object_name);

        [DllImport("libSystem.dylib", EntryPoint = "mach_error_string", SetLastError = false)]
        private static extern IntPtr mach_error_string(int error_value);
        #endregion

        #region Native Methods - ptrace
        [DllImport("libSystem.dylib", EntryPoint = "ptrace", SetLastError = true)]
        private static extern int ptrace(int request, int pid, IntPtr addr, int data);

        [DllImport("libSystem.dylib", EntryPoint = "ptrace", SetLastError = true)]
        private static extern int ptrace_attach(int request, int pid, IntPtr addr, IntPtr data);
        #endregion

        #region Native Methods - Thread State
        [DllImport("libSystem.dylib", EntryPoint = "thread_get_state", SetLastError = false)]
        private static extern int thread_get_state(int target_act, int flavor, ref x86_thread_state64_t state,
            ref uint state_count);

        [DllImport("libSystem.dylib", EntryPoint = "thread_set_state", SetLastError = false)]
        private static extern int thread_set_state(int target_act, int flavor, ref x86_thread_state64_t state,
            uint state_count);

        [DllImport("libSystem.dylib", EntryPoint = "task_threads", SetLastError = false)]
        private static extern int task_threads(int target_task, out IntPtr act_list, out uint act_listCnt);
        #endregion

        #region Native Methods - Error Handling
        [DllImport("libSystem.dylib", EntryPoint = "__error", SetLastError = false)]
        private static extern IntPtr __error();

        [DllImport("libSystem.dylib", EntryPoint = "strerror", SetLastError = false)]
        private static extern IntPtr strerror(int errnum);
        #endregion

        #region Native Methods - Process Operations
        [DllImport("libSystem.dylib", EntryPoint = "waitpid", SetLastError = true)]
        private static extern int waitpid(int pid, out int status, int options);

        [DllImport("libSystem.dylib", EntryPoint = "kill", SetLastError = true)]
        private static extern int kill(int pid, int sig);
        #endregion

        #region Native Methods - Dynamic Loading
        [DllImport("libSystem.dylib", EntryPoint = "dlopen", SetLastError = true)]
        private static extern IntPtr dlopen(string filename, int flags);

        [DllImport("libSystem.dylib", EntryPoint = "dlsym", SetLastError = true)]
        private static extern IntPtr dlsym(IntPtr handle, string symbol);

        [DllImport("libSystem.dylib", EntryPoint = "dlclose", SetLastError = true)]
        private static extern int dlclose(IntPtr handle);

        [DllImport("libSystem.dylib", EntryPoint = "dlerror", SetLastError = false)]
        private static extern IntPtr dlerror();
        #endregion

        #region Error Handling
        private int GetErrno()
        {
            IntPtr errnoPtr = __error();
            return Marshal.ReadInt32(errnoPtr);
        }

        public string GetLastErrorMessage()
        {
            int errno = GetErrno();
            IntPtr errorString = strerror(errno);
            string message = Marshal.PtrToStringAnsi(errorString);
            return $"Error {errno}: {message}";
        }

        public uint GetLastError()
        {
            return (uint)GetErrno();
        }

        private string GetMachErrorMessage(int machError)
        {
            if (machError == KERN_SUCCESS)
                return "Success";

            IntPtr errorString = mach_error_string(machError);
            string message = Marshal.PtrToStringAnsi(errorString);
            return $"Mach error {machError}: {message}";
        }
        #endregion

        #region Task Management
        private Dictionary<int, int> _pidToTaskMap = new Dictionary<int, int>();

        private int GetTaskForPid(int pid)
        {
            if (_pidToTaskMap.ContainsKey(pid))
                return _pidToTaskMap[pid];

            int task;
            int result = task_for_pid(mach_task_self(), pid, out task);

            if (result != KERN_SUCCESS)
            {
                Log.Logger.Error($"Failed to get task for PID {pid}: {GetMachErrorMessage(result)}");
                Log.Logger.Warning("Note: task_for_pid requires root privileges or 'com.apple.security.cs.debugger' entitlement");
                return MACH_PORT_NULL;
            }

            _pidToTaskMap[pid] = task;
            return task;
        }
        #endregion

        #region Memory Operations
        public bool ReadProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead)
        {
            lpNumberOfBytesRead = IntPtr.Zero;
            int pid = processH.ToInt32();

            if (pid <= 0)
            {
                Log.Logger.Error("Invalid process handle");
                return false;
            }

            int task = GetTaskForPid(pid);
            if (task == MACH_PORT_NULL)
            {
                return false;
            }

            try
            {
                GCHandle bufferHandle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
                try
                {
                    ulong outSize;
                    int result = mach_vm_read_overwrite(task, lpBaseAddress, (ulong)dwSize,
                        bufferHandle.AddrOfPinnedObject(), out outSize);

                    if (result != KERN_SUCCESS)
                    {
                        Log.Logger.Error($"Failed to read process memory: {GetMachErrorMessage(result)}");
                        return false;
                    }

                    lpNumberOfBytesRead = new IntPtr((long)outSize);
                    return true;
                }
                finally
                {
                    bufferHandle.Free();
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Exception reading process memory: {ex.Message}");
                return false;
            }
        }

        public bool WriteProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten)
        {
            lpNumberOfBytesWritten = IntPtr.Zero;
            int pid = processH.ToInt32();

            if (pid <= 0)
            {
                Log.Logger.Error("Invalid process handle");
                return false;
            }

            int task = GetTaskForPid(pid);
            if (task == MACH_PORT_NULL)
            {
                return false;
            }

            try
            {
                GCHandle bufferHandle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
                try
                {
                    int result = mach_vm_write(task, lpBaseAddress, bufferHandle.AddrOfPinnedObject(), (uint)dwSize);

                    if (result != KERN_SUCCESS)
                    {
                        Log.Logger.Error($"Failed to write process memory: {GetMachErrorMessage(result)}");
                        return false;
                    }

                    lpNumberOfBytesWritten = new IntPtr(dwSize);
                    return true;
                }
                finally
                {
                    bufferHandle.Free();
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Exception writing process memory: {ex.Message}");
                return false;
            }
        }

        public IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId)
        {
            try
            {
                // Verify process exists
                Process.GetProcessById(dwProcessId);

                // Attempt to get task port to verify access
                int task = GetTaskForPid(dwProcessId);
                if (task == MACH_PORT_NULL)
                {
                    Log.Logger.Error($"Failed to get task port for process {dwProcessId}");
                    return IntPtr.Zero;
                }

                return new IntPtr(dwProcessId);
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Failed to open process {dwProcessId}: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        public bool VirtualProtectEx(IntPtr processH, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            lpflOldProtect = 0;
            int pid = processH.ToInt32();

            int task = GetTaskForPid(pid);
            if (task == MACH_PORT_NULL)
            {
                return false;
            }

            // Convert Windows protection flags to Mach protection flags
            int protection = ConvertWindowsProtectionToMach(flNewProtect);

            int result = mach_vm_protect(task, (ulong)lpAddress.ToInt64(), (ulong)dwSize.ToInt64(),
                false, protection);

            if (result != KERN_SUCCESS)
            {
                Log.Logger.Error($"Failed to change memory protection: {GetMachErrorMessage(result)}");
                return false;
            }

            return true;
        }

        private int ConvertWindowsProtectionToMach(uint windowsProtect)
        {
            int prot = VM_PROT_NONE;

            if ((windowsProtect & 0x02) != 0) prot = VM_PROT_READ; // PAGE_READONLY
            if ((windowsProtect & 0x04) != 0) prot = VM_PROT_READ | VM_PROT_WRITE; // PAGE_READWRITE
            if ((windowsProtect & 0x10) != 0) prot = VM_PROT_READ | VM_PROT_EXECUTE; // PAGE_EXECUTE_READ
            if ((windowsProtect & 0x20) != 0) prot = VM_PROT_ALL; // PAGE_EXECUTE_READWRITE
            if ((windowsProtect & 0x40) != 0) prot = VM_PROT_ALL; // PAGE_EXECUTE_READWRITE (alternate)

            return prot;
        }

        private uint ConvertMachProtectionToWindows(int machProtect)
        {
            uint prot = 0x01; // PAGE_NOACCESS

            if ((machProtect & VM_PROT_READ) != 0 && (machProtect & VM_PROT_WRITE) == 0 && (machProtect & VM_PROT_EXECUTE) == 0)
                prot = 0x02; // PAGE_READONLY
            else if ((machProtect & VM_PROT_READ) != 0 && (machProtect & VM_PROT_WRITE) != 0 && (machProtect & VM_PROT_EXECUTE) == 0)
                prot = 0x04; // PAGE_READWRITE
            else if ((machProtect & VM_PROT_READ) != 0 && (machProtect & VM_PROT_EXECUTE) != 0 && (machProtect & VM_PROT_WRITE) == 0)
                prot = 0x10; // PAGE_EXECUTE_READ
            else if ((machProtect & VM_PROT_ALL) == VM_PROT_ALL)
                prot = 0x40; // PAGE_EXECUTE_READWRITE

            return prot;
        }

        public IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect)
        {
            int pid = hProcess.ToInt32();
            int task = GetTaskForPid(pid);

            if (task == MACH_PORT_NULL)
            {
                return IntPtr.Zero;
            }

            ulong address = lpAddress == IntPtr.Zero ? 0 : (ulong)lpAddress.ToInt64();
            int flags = lpAddress == IntPtr.Zero ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED;

            int result = mach_vm_allocate(task, ref address, (ulong)dwSize.ToInt64(), flags);

            if (result != KERN_SUCCESS)
            {
                Log.Logger.Error($"Failed to allocate memory: {GetMachErrorMessage(result)}");
                return IntPtr.Zero;
            }

            // Set protection if needed
            int protection = ConvertWindowsProtectionToMach(flProtect);
            if (protection != (VM_PROT_READ | VM_PROT_WRITE))
            {
                result = mach_vm_protect(task, address, (ulong)dwSize.ToInt64(), false, protection);
                if (result != KERN_SUCCESS)
                {
                    Log.Logger.Warning($"Failed to set memory protection: {GetMachErrorMessage(result)}");
                }
            }

            return new IntPtr((long)address);
        }

        public bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint dwFreeType)
        {
            int pid = hProcess.ToInt32();
            int task = GetTaskForPid(pid);

            if (task == MACH_PORT_NULL)
            {
                return false;
            }

            int result = mach_vm_deallocate(task, (ulong)lpAddress.ToInt64(), (ulong)dwSize.ToInt64());

            if (result != KERN_SUCCESS)
            {
                Log.Logger.Error($"Failed to deallocate memory: {GetMachErrorMessage(result)}");
                return false;
            }

            return true;
        }

        public IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength)
        {
            lpBuffer = new MEMORY_BASIC_INFORMATION();
            int pid = hProcess.ToInt32();
            int task = GetTaskForPid(pid);

            if (task == MACH_PORT_NULL)
            {
                return IntPtr.Zero;
            }

            ulong address = (ulong)lpAddress.ToInt64();
            ulong size = 0;
            vm_region_basic_info_64 info = new vm_region_basic_info_64();
            uint infoCnt = (uint)(Marshal.SizeOf(typeof(vm_region_basic_info_64)) / sizeof(int));
            int objectName = 0;

            int result = mach_vm_region(task, ref address, ref size, 1, ref info, ref infoCnt, ref objectName);

            if (result != KERN_SUCCESS)
            {
                // If we can't query, the region is likely free
                lpBuffer.State = (uint)MemoryState.Free;
                return IntPtr.Zero;
            }

            lpBuffer.BaseAddress = new IntPtr((long)address);
            lpBuffer.RegionSize = new IntPtr((long)size);
            lpBuffer.State = (uint)MemoryState.Commit;
            lpBuffer.Protect = ConvertMachProtectionToWindows(info.protection);
            lpBuffer.AllocationProtect = ConvertMachProtectionToWindows(info.max_protection);

            return new IntPtr(1); // Success
        }

        public IntPtr FindFreeRegionBelow4GB(IntPtr processHandle, uint size)
        {
            int pid = processHandle.ToInt32();
            int task = GetTaskForPid(pid);

            if (task == MACH_PORT_NULL)
            {
                return IntPtr.Zero;
            }

            const ulong MAX_32BIT = 0x7FFE0000;
            ulong address = 0x10000; // Start from a reasonable base
            ulong lastEnd = address;

            while (address < MAX_32BIT)
            {
                ulong regionSize = 0;
                vm_region_basic_info_64 info = new vm_region_basic_info_64();
                uint infoCnt = (uint)(Marshal.SizeOf(typeof(vm_region_basic_info_64)) / sizeof(int));
                int objectName = 0;

                int result = mach_vm_region(task, ref address, ref regionSize, 1, ref info, ref infoCnt, ref objectName);

                if (result != KERN_SUCCESS)
                {
                    // No more regions, check if we have space at the end
                    if (MAX_32BIT - lastEnd >= size)
                    {
                        ulong alignedAddress = (lastEnd + 0xFFF) & ~0xFFFul;
                        if (alignedAddress + size <= MAX_32BIT)
                        {
                            return new IntPtr((long)alignedAddress);
                        }
                    }
                    break;
                }

                // Check gap before this region
                if (address > lastEnd)
                {
                    ulong gapSize = address - lastEnd;
                    if (gapSize >= size)
                    {
                        ulong alignedAddress = (lastEnd + 0xFFF) & ~0xFFFul;
                        if (alignedAddress + size <= address && alignedAddress < MAX_32BIT)
                        {
                            return new IntPtr((long)alignedAddress);
                        }
                    }
                }

                lastEnd = address + regionSize;
                address = lastEnd;
            }

            Log.Logger.Warning($"Could not find free region of size {size} below 4GB");
            return IntPtr.Zero;
        }

        public bool CloseHandle(IntPtr handle)
        {
            // On macOS, we cache task ports, so just return success
            // The ports will be cleaned up when the object is disposed
            return true;
        }

        public int GetPID(string procName)
        {
            Process[] processes = Process.GetProcessesByName(procName);
            if (processes.Length < 1)
            {
                Log.Logger.Debug($"Process '{procName}' not found");
                return 0;
            }
            return processes[0].Id;
        }
        public List<int> GetPIDs(string procName)
        {
            Process[] processes = Process.GetProcessesByName(procName);
            if (processes.Length < 1)
            {
                Log.Logger.Debug($"Process '{procName}' not found");
                return [];
            }
            return processes.Select(x => x.Id).ToList();
        }
        #endregion

        #region Module Information
        public MODULEINFO GetModuleInfo(IntPtr processHandle, string moduleName)
        {
            MODULEINFO moduleInfo = new MODULEINFO();
            int pid = processHandle.ToInt32();
            int task = GetTaskForPid(pid);

            if (task == MACH_PORT_NULL)
            {
                return moduleInfo;
            }

            try
            {
                ulong address = 0;
                ulong firstStart = 0;
                ulong lastEnd = 0;
                bool foundFirst = false;

                while (true)
                {
                    ulong regionSize = 0;
                    vm_region_basic_info_64 info = new vm_region_basic_info_64();
                    uint infoCnt = (uint)(Marshal.SizeOf(typeof(vm_region_basic_info_64)) / sizeof(int));
                    int objectName = 0;

                    int result = mach_vm_region(task, ref address, ref regionSize, 1, ref info, ref infoCnt, ref objectName);

                    if (result != KERN_SUCCESS)
                        break;

                    if (!foundFirst && (info.protection & VM_PROT_EXECUTE) != 0 && regionSize > 0x1000)
                    {
                        firstStart = address;
                        foundFirst = true;
                    }

                    if (foundFirst)
                    {
                        lastEnd = address + regionSize;
                    }

                    address += regionSize;
                }

                if (foundFirst)
                {
                    moduleInfo.lpBaseOfDll = new IntPtr((long)firstStart);
                    moduleInfo.SizeOfImage = (uint)(lastEnd - firstStart);
                    moduleInfo.EntryPoint = IntPtr.Zero;
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error getting module info: {ex.Message}");
            }

            return moduleInfo;
        }

        public IntPtr GetModuleHandle(string moduleName)
        {
            try
            {
                // Use dlopen to get the module handle
                const int RTLD_NOLOAD = 0x10;
                const int RTLD_LAZY = 0x1;

                IntPtr handle = dlopen(moduleName, RTLD_NOLOAD | RTLD_LAZY);

                if (handle == IntPtr.Zero)
                {
                    IntPtr error = dlerror();
                    string errorMsg = Marshal.PtrToStringAnsi(error);
                    Log.Logger.Debug($"Module '{moduleName}' not loaded: {errorMsg}");
                    return IntPtr.Zero;
                }

                return handle;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error getting module handle: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        public nint GetModuleBaseAddress(int pid, string moduleName)
        {
            // On macOS, we need to use task_for_pid and iterate through loaded images
            // For now, provide a basic implementation that searches memory maps

            int task = GetTaskForPid(pid);
            if (task == MACH_PORT_NULL)
            {
                Log.Logger.Error($"Failed to get task for PID {pid}");
                return nint.Zero;
            }

            try
            {
                // Iterate through memory regions to find the module
                ulong address = 0;

                while (address < 0x7FFFFFFFFFFF)
                {
                    ulong regionSize = 0;
                    vm_region_basic_info_64 info = new vm_region_basic_info_64();
                    uint infoCnt = (uint)(Marshal.SizeOf(typeof(vm_region_basic_info_64)) / sizeof(int));
                    int objectName = 0;

                    int result = mach_vm_region(task, ref address, ref regionSize, 1, ref info, ref infoCnt, ref objectName);

                    if (result != KERN_SUCCESS)
                        break;

                    // Check if this region has execute permissions (likely code)
                    if ((info.protection & VM_PROT_EXECUTE) != 0)
                    {
                        // This is a code region - could be our module
                        // We'd need to read the Mach-O header to verify
                        // For now, return the first executable region (simplified)
                        // In a real implementation, we'd parse headers to match module name

                        Log.Logger.Debug($"Found executable region at 0x{address:X} (size: 0x{regionSize:X})");

                        // Try to verify it's a Mach-O file
                        byte[] header = new byte[4];
                        nint processHandle = new nint(pid);
                        if (ReadProcessMemory(processHandle, address, header, 4, out nint bytesRead))
                        {
                            uint magic = BitConverter.ToUInt32(header, 0);
                            // MH_MAGIC_64 = 0xFEEDFACF, MH_CIGAM_64 = 0xCFFAEDFE
                            if (magic == 0xFEEDFACF || magic == 0xCFFAEDFE)
                            {
                                // This is a Mach-O file, likely the main executable or a library
                                // In a full implementation, we'd read the load commands to find LC_ID_DYLIB
                                // and match against moduleName
                                return new nint((long)address);
                            }
                        }
                    }

                    address += regionSize;
                }

                Log.Logger.Warning($"Module '{moduleName}' not found in process {pid}");
                return nint.Zero;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error getting module base address on macOS: {ex.Message}");
                return nint.Zero;
            }
        }
        #endregion

        #region Remote Execution
        public uint Execute(IntPtr processHandle, IntPtr address, uint timeoutSeconds = 0xFFFFFFFF)
        {
            int pid = processHandle.ToInt32();
            int task = GetTaskForPid(pid);

            if (task == MACH_PORT_NULL)
            {
                return 0;
            }

            try
            {
                // Get the first thread of the task
                IntPtr threadList;
                uint threadCount;
                int result = task_threads(task, out threadList, out threadCount);

                if (result != KERN_SUCCESS || threadCount == 0)
                {
                    Log.Logger.Error($"Failed to get threads: {GetMachErrorMessage(result)}");
                    return 0;
                }

                // Get the first thread
                int thread = Marshal.ReadInt32(threadList);

                // Determine architecture and get thread state
                bool isArm = IsAppleSilicon();

                if (isArm)
                {
                    Log.Logger.Error("ARM64 thread execution not yet implemented");
                    return 0;
                }

                // x86_64 implementation
                x86_thread_state64_t state = new x86_thread_state64_t();
                uint stateCount = (uint)(Marshal.SizeOf(typeof(x86_thread_state64_t)) / sizeof(int));

                result = thread_get_state(thread, 4, ref state, ref stateCount); // x86_THREAD_STATE64 = 4

                if (result != KERN_SUCCESS)
                {
                    Log.Logger.Error($"Failed to get thread state: {GetMachErrorMessage(result)}");
                    return 0;
                }

                // Save original RIP
                ulong originalRip = state.rip;

                // Set RIP to our code
                state.rip = (ulong)address.ToInt64();

                // Set thread state
                result = thread_set_state(thread, 4, ref state, stateCount);

                if (result != KERN_SUCCESS)
                {
                    Log.Logger.Error($"Failed to set thread state: {GetMachErrorMessage(result)}");
                    return 0;
                }

                // Resume the thread (using ptrace)
                if (ptrace(PT_CONTINUE, pid, new IntPtr(1), 0) == -1)
                {
                    Log.Logger.Error($"Failed to continue process: {GetLastErrorMessage()}");
                    return 0;
                }

                // Wait for execution
                int status;
                if (waitpid(pid, out status, 0) == -1)
                {
                    Log.Logger.Error($"Failed to wait for process: {GetLastErrorMessage()}");
                    return 0;
                }

                // Restore original RIP
                result = thread_get_state(thread, 4, ref state, ref stateCount);
                if (result == KERN_SUCCESS)
                {
                    state.rip = originalRip;
                    thread_set_state(thread, 4, ref state, stateCount);
                }

                return 1;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error executing remote code: {ex.Message}");
                return 0;
            }
        }

        public uint ExecuteCommand(IntPtr processHandle, byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
        {
            IntPtr address = VirtualAllocEx(processHandle, IntPtr.Zero, new IntPtr(bytes.Length),
                MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            if (address == IntPtr.Zero)
            {
                Log.Logger.Error($"Failed to allocate memory: {GetLastErrorMessage()}");
                return 0;
            }

            try
            {
                if (!WriteProcessMemory(processHandle, (ulong)address, bytes, bytes.Length, out IntPtr bytesWritten))
                {
                    Log.Logger.Error($"Failed to write bytes to memory: {GetLastErrorMessage()}");
                    VirtualFreeEx(processHandle, address, new IntPtr(bytes.Length), MEM_RELEASE);
                    return 0;
                }

                uint result = Execute(processHandle, address, timeoutSeconds);

                VirtualFreeEx(processHandle, address, new IntPtr(bytes.Length), MEM_RELEASE);
                return result;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error executing command: {ex.Message}");
                VirtualFreeEx(processHandle, address, new IntPtr(bytes.Length), MEM_RELEASE);
                return 0;
            }
        }
        #endregion

        #region Helper Methods
        public IntPtr GetSymbolAddress(string libraryPath, string symbolName)
        {
            const int RTLD_LAZY = 1;

            IntPtr handle = dlopen(libraryPath, RTLD_LAZY);
            if (handle == IntPtr.Zero)
            {
                IntPtr error = dlerror();
                string errorMsg = Marshal.PtrToStringAnsi(error);
                Log.Logger.Error($"Failed to load library {libraryPath}: {errorMsg}");
                return IntPtr.Zero;
            }

            try
            {
                IntPtr symbol = dlsym(handle, symbolName);
                if (symbol == IntPtr.Zero)
                {
                    IntPtr error = dlerror();
                    string errorMsg = Marshal.PtrToStringAnsi(error);
                    Log.Logger.Error($"Failed to find symbol {symbolName} in {libraryPath}: {errorMsg}");
                }
                return symbol;
            }
            finally
            {
                dlclose(handle);
            }
        }

        private bool IsAppleSilicon()
        {
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
        }
        private string GetNullTerminatedString(byte[] buffer, int offset)
        {
            int length = 0;
            while (offset + length < buffer.Length && buffer[offset + length] != 0)
            {
                length++;
            }
            return System.Text.Encoding.UTF8.GetString(buffer, offset, length);
        }

        private uint SwapUInt32(uint value)
        {
            return ((value & 0x000000FF) << 24) |
                   ((value & 0x0000FF00) << 8) |
                   ((value & 0x00FF0000) >> 8) |
                   ((value & 0xFF000000) >> 24);
        }

        private ulong SwapUInt64(ulong value)
        {
            return ((value & 0x00000000000000FF) << 56) |
                   ((value & 0x000000000000FF00) << 40) |
                   ((value & 0x0000000000FF0000) << 24) |
                   ((value & 0x00000000FF000000) << 8) |
                   ((value & 0x000000FF00000000) >> 8) |
                   ((value & 0x0000FF0000000000) >> 24) |
                   ((value & 0x00FF000000000000) >> 40) |
                   ((value & 0xFF00000000000000) >> 56);
        }
        #endregion

        #region export info
        public nint GetExportAddress(int pid, nint moduleBase, string exportName)
        {
            // macOS implementation requires parsing Mach-O headers

            nint processHandle = OpenProcess(0x0010 | 0x0008, false, pid); // Equivalent access
            if (processHandle == nint.Zero)
            {
                Log.Logger.Error($"Failed to open process {pid}");
                return nint.Zero;
            }

            try
            {
                return FindMachOExport(processHandle, moduleBase, exportName);
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        private nint FindMachOExport(nint processHandle, nint moduleBase, string exportName)
        {
            try
            {
                // Read Mach-O header
                byte[] header = new byte[32]; // mach_header_64 size
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase, header, header.Length, out nint bytesRead))
                {
                    Log.Logger.Warning("Failed to read Mach-O header");
                    return nint.Zero;
                }

                uint magic = BitConverter.ToUInt32(header, 0);

                // Check for 64-bit Mach-O magic numbers
                if (magic != 0xFEEDFACF && magic != 0xCFFAEDFE) // MH_MAGIC_64 or MH_CIGAM_64 (byte-swapped)
                {
                    Log.Logger.Warning("Invalid Mach-O magic number");
                    return nint.Zero;
                }

                bool needsSwap = (magic == 0xCFFAEDFE);

                uint ncmds = BitConverter.ToUInt32(header, 16);
                uint sizeofcmds = BitConverter.ToUInt32(header, 20);

                if (needsSwap)
                {
                    ncmds = SwapUInt32(ncmds);
                    sizeofcmds = SwapUInt32(sizeofcmds);
                }

                // Read load commands
                byte[] loadCommands = new byte[sizeofcmds];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase + 32, loadCommands, (int)sizeofcmds, out bytesRead))
                {
                    Log.Logger.Warning("Failed to read load commands");
                    return nint.Zero;
                }

                // Search for LC_SYMTAB (0x2)
                uint offset = 0;
                uint symoff = 0;
                uint nsyms = 0;
                uint stroff = 0;
                uint strsize = 0;

                for (uint i = 0; i < ncmds; i++)
                {
                    uint cmd = BitConverter.ToUInt32(loadCommands, (int)offset);
                    uint cmdsize = BitConverter.ToUInt32(loadCommands, (int)offset + 4);

                    if (needsSwap)
                    {
                        cmd = SwapUInt32(cmd);
                        cmdsize = SwapUInt32(cmdsize);
                    }

                    if (cmd == 0x2) // LC_SYMTAB
                    {
                        symoff = BitConverter.ToUInt32(loadCommands, (int)offset + 8);
                        nsyms = BitConverter.ToUInt32(loadCommands, (int)offset + 12);
                        stroff = BitConverter.ToUInt32(loadCommands, (int)offset + 16);
                        strsize = BitConverter.ToUInt32(loadCommands, (int)offset + 20);

                        if (needsSwap)
                        {
                            symoff = SwapUInt32(symoff);
                            nsyms = SwapUInt32(nsyms);
                            stroff = SwapUInt32(stroff);
                            strsize = SwapUInt32(strsize);
                        }
                        break;
                    }

                    offset += cmdsize;
                }

                if (symoff == 0 || stroff == 0)
                {
                    Log.Logger.Warning("Could not find symbol table in Mach-O");
                    return nint.Zero;
                }

                // Read string table
                byte[] stringTable = new byte[strsize];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase + stroff, stringTable, (int)strsize, out bytesRead))
                {
                    Log.Logger.Warning("Failed to read string table");
                    return nint.Zero;
                }

                // Read and search symbol table
                const int NLIST_64_SIZE = 16; // sizeof(nlist_64)

                for (uint i = 0; i < nsyms; i++)
                {
                    byte[] nlist = new byte[NLIST_64_SIZE];
                    if (!ReadProcessMemory(processHandle, (ulong)moduleBase + symoff + (i * NLIST_64_SIZE),
                        nlist, NLIST_64_SIZE, out bytesRead))
                    {
                        continue;
                    }

                    uint n_strx = BitConverter.ToUInt32(nlist, 0);
                    byte n_type = nlist[4];
                    ulong n_value = BitConverter.ToUInt64(nlist, 8);

                    if (needsSwap)
                    {
                        n_strx = SwapUInt32(n_strx);
                        n_value = SwapUInt64(n_value);
                    }

                    // Check if this is an external symbol (N_EXT = 0x01, in n_type)
                    if ((n_type & 0x01) == 0)
                        continue;

                    // Get symbol name
                    if (n_strx >= strsize) continue;

                    string symbolName = GetNullTerminatedString(stringTable, (int)n_strx);

                    // Mach-O symbols usually have an underscore prefix
                    if (symbolName == $"_{exportName}" || symbolName == exportName)
                    {
                        return (nint)((ulong)moduleBase + n_value);
                    }
                }

                Log.Logger.Warning($"Export '{exportName}' not found in Mach-O symbol table");
                return nint.Zero;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error parsing Mach-O: {ex.Message}");
                return nint.Zero;
            }
        }
        #endregion
    }
}