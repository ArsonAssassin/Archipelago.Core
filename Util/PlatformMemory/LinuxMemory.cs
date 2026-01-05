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
    public class LinuxMemory : IMemory
    {
        #region Constants
        // ptrace requests
        private const int PTRACE_PEEKDATA = 2;
        private const int PTRACE_POKEDATA = 4;
        private const int PTRACE_GETREGS = 12;
        private const int PTRACE_SETREGS = 13;
        private const int PTRACE_ATTACH = 16;
        private const int PTRACE_DETACH = 17;
        private const int PTRACE_CONT = 7;

        // Memory protection flags
        private const int PROT_NONE = 0x0;
        private const int PROT_READ = 0x1;
        private const int PROT_WRITE = 0x2;
        private const int PROT_EXEC = 0x4;

        // mmap flags
        private const int MAP_PRIVATE = 0x02;
        private const int MAP_ANONYMOUS = 0x20;
        private const int MAP_FAILED = -1;

        // Wait status
        private const int WNOHANG = 1;
        private const int WUNTRACED = 2;

        // Windows compatibility constants (for interface compatibility)
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_READONLY = 0x02;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RELEASE = 0x00008000;
        #endregion

        #region Structures
        [StructLayout(LayoutKind.Sequential)]
        public struct iovec
        {
            public nint iov_base;
            public nint iov_len;
        }

        // x86_64 register structure
        [StructLayout(LayoutKind.Sequential)]
        public struct user_regs_struct
        {
            public ulong r15, r14, r13, r12, rbp, rbx, r11, r10;
            public ulong r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
            public ulong rip, cs, eflags, rsp, ss;
            public ulong fs_base, gs_base, ds, es, fs, gs;
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
            public nint BaseAddress;
            public nint AllocationBase;
            public uint AllocationProtect;
            public nint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        #endregion

        #region Native Methods
        // Error handling
        [DllImport("libc.so.6", EntryPoint = "__errno_location", SetLastError = false)]
        private static extern nint __errno_location();

        [DllImport("libc.so.6", EntryPoint = "strerror", SetLastError = false)]
        private static extern nint strerror(int errnum);

        // Process memory operations
        [DllImport("libc.so.6", EntryPoint = "process_vm_readv", SetLastError = true)]
        private static extern nint process_vm_readv(int pid, ref iovec local_iov, ulong liovcnt,
            ref iovec remote_iov, ulong riovcnt, ulong flags);

        [DllImport("libc.so.6", EntryPoint = "process_vm_writev", SetLastError = true)]
        private static extern nint process_vm_writev(int pid, ref iovec local_iov, ulong liovcnt,
            ref iovec remote_iov, ulong riovcnt, ulong flags);

        // ptrace operations
        [DllImport("libc.so.6", EntryPoint = "ptrace", SetLastError = true)]
        private static extern long ptrace(int request, int pid, nint addr, nint data);

        [DllImport("libc.so.6", EntryPoint = "ptrace", SetLastError = true)]
        private static extern long ptrace_setregs(int request, int pid, nint addr, ref user_regs_struct data);

        [DllImport("libc.so.6", EntryPoint = "ptrace", SetLastError = true)]
        private static extern long ptrace_getregs(int request, int pid, nint addr, out user_regs_struct data);

        // Wait operations
        [DllImport("libc.so.6", EntryPoint = "waitpid", SetLastError = true)]
        private static extern int waitpid(int pid, out int status, int options);

        // Memory protection (local process only)
        [DllImport("libc.so.6", EntryPoint = "mprotect", SetLastError = true)]
        private static extern int mprotect(nint addr, ulong len, int prot);

        // Memory mapping (local process only)
        [DllImport("libc.so.6", EntryPoint = "mmap", SetLastError = true)]
        private static extern nint mmap(nint addr, ulong length, int prot, int flags, int fd, long offset);

        [DllImport("libc.so.6", EntryPoint = "munmap", SetLastError = true)]
        private static extern int munmap(nint addr, ulong length);

        // Dynamic loading
        [DllImport("libc.so.6", EntryPoint = "dlopen", SetLastError = true)]
        private static extern nint dlopen(string filename, int flags);

        [DllImport("libc.so.6", EntryPoint = "dlsym", SetLastError = true)]
        private static extern nint dlsym(nint handle, string symbol);

        [DllImport("libc.so.6", EntryPoint = "dlclose", SetLastError = true)]
        private static extern int dlclose(nint handle);
        #endregion

        #region Error Handling
        private int GetErrno()
        {
            nint errnoPtr = __errno_location();
            return Marshal.ReadInt32(errnoPtr);
        }

        public string GetLastErrorMessage()
        {
            int errno = GetErrno();
            nint errorString = strerror(errno);
            string message = Marshal.PtrToStringAnsi(errorString);
            return $"Error {errno}: {message}";
        }

        public uint GetLastError()
        {
            return (uint)GetErrno();
        }
        #endregion

        #region Process Attachment
        private Dictionary<int, bool> _attachedProcesses = new Dictionary<int, bool>();

        private bool AttachToProcess(int pid)
        {
            if (_attachedProcesses.ContainsKey(pid) && _attachedProcesses[pid])
                return true;

            if (ptrace(PTRACE_ATTACH, pid, nint.Zero, nint.Zero) == -1)
            {
                Log.Logger.Error($"Failed to attach to process {pid}: {GetLastErrorMessage()}");
                return false;
            }

            // Wait for the process to stop
            int status;
            if (waitpid(pid, out status, WUNTRACED) == -1)
            {
                Log.Logger.Error($"Failed to wait for process {pid}: {GetLastErrorMessage()}");
                ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero);
                return false;
            }

            _attachedProcesses[pid] = true;
            return true;
        }

        private bool DetachFromProcess(int pid)
        {
            if (!_attachedProcesses.ContainsKey(pid) || !_attachedProcesses[pid])
                return true;

            if (ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero) == -1)
            {
                Log.Logger.Error($"Failed to detach from process {pid}: {GetLastErrorMessage()}");
                return false;
            }

            _attachedProcesses[pid] = false;
            return true;
        }
        #endregion

        #region Memory Operations
        public bool ReadProcessMemory(nint processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesRead)
        {
            lpNumberOfBytesRead = nint.Zero;
            int pid = processH.ToInt32();

            if (pid <= 0)
            {
                Log.Logger.Error("Invalid process handle");
                return false;
            }

            try
            {
                // Try process_vm_readv first (more efficient)
                GCHandle bufferHandle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
                try
                {
                    iovec local = new iovec
                    {
                        iov_base = bufferHandle.AddrOfPinnedObject(),
                        iov_len = new nint(dwSize)
                    };

                    iovec remote = new iovec
                    {
                        iov_base = new nint((long)lpBaseAddress),
                        iov_len = new nint(dwSize)
                    };

                    nint bytesRead = process_vm_readv(pid, ref local, 1, ref remote, 1, 0);

                    if (bytesRead.ToInt64() > 0)
                    {
                        lpNumberOfBytesRead = bytesRead;
                        return true;
                    }

                    // If process_vm_readv fails, fall back to /proc/pid/mem
                    Log.Logger.Debug($"process_vm_readv failed: {GetLastErrorMessage()}, falling back to /proc/{pid}/mem");
                }
                finally
                {
                    bufferHandle.Free();
                }

                // Fallback: Use /proc/pid/mem
                string memPath = $"/proc/{pid}/mem";
                if (File.Exists(memPath))
                {
                    using (FileStream fs = new FileStream(memPath, FileMode.Open, FileAccess.Read))
                    {
                        fs.Seek((long)lpBaseAddress, SeekOrigin.Begin);
                        int bytesRead = fs.Read(lpBuffer, 0, dwSize);
                        lpNumberOfBytesRead = new nint(bytesRead);
                        return bytesRead > 0;
                    }
                }

                Log.Logger.Error($"Could not access memory for process {pid}");
                return false;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Failed to read process memory: {ex.Message}");
                return false;
            }
        }

        public bool WriteProcessMemory(nint processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesWritten)
        {
            lpNumberOfBytesWritten = nint.Zero;
            int pid = processH.ToInt32();

            if (pid <= 0)
            {
                Log.Logger.Error("Invalid process handle");
                return false;
            }

            try
            {
                // Try process_vm_writev first (more efficient)
                GCHandle bufferHandle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
                try
                {
                    iovec local = new iovec
                    {
                        iov_base = bufferHandle.AddrOfPinnedObject(),
                        iov_len = new nint(dwSize)
                    };

                    iovec remote = new iovec
                    {
                        iov_base = new nint((long)lpBaseAddress),
                        iov_len = new nint(dwSize)
                    };

                    nint bytesWritten = process_vm_writev(pid, ref local, 1, ref remote, 1, 0);

                    if (bytesWritten.ToInt64() > 0)
                    {
                        lpNumberOfBytesWritten = bytesWritten;
                        return true;
                    }

                    Log.Logger.Debug($"process_vm_writev failed: {GetLastErrorMessage()}, falling back to /proc/{pid}/mem");
                }
                finally
                {
                    bufferHandle.Free();
                }

                // Fallback: Use /proc/pid/mem
                string memPath = $"/proc/{pid}/mem";
                if (File.Exists(memPath))
                {
                    using (FileStream fs = new FileStream(memPath, FileMode.Open, FileAccess.Write))
                    {
                        fs.Seek((long)lpBaseAddress, SeekOrigin.Begin);
                        fs.Write(lpBuffer, 0, dwSize);
                        lpNumberOfBytesWritten = new nint(dwSize);
                        return true;
                    }
                }

                Log.Logger.Error($"Could not access memory for process {pid}");
                return false;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Failed to write process memory: {ex.Message}");
                return false;
            }
        }

        public nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId)
        {
            // On Linux, we just verify the process exists and return the PID
            try
            {
                Process.GetProcessById(dwProcessId);
                return new nint(dwProcessId);
            }
            catch
            {
                Log.Logger.Error($"Process {dwProcessId} does not exist");
                return nint.Zero;
            }
        }

        public bool VirtualProtectEx(nint processH, nint lpAddress, nint dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            lpflOldProtect = 0;
            int pid = processH.ToInt32();

            // This is problematic on Linux - mprotect only works on the current process
            // For remote processes, we would need to inject code to call mprotect
            // For now, we'll log a warning and return true (assuming permissions are sufficient)
            Log.Logger.Warning($"VirtualProtectEx called for remote process {pid} - this operation has limited support on Linux");

            // Convert Windows protection flags to Linux flags
            int prot = ConvertWindowsProtectionToLinux(flNewProtect);

            // If this is the current process, we can use mprotect directly
            if (pid == Process.GetCurrentProcess().Id)
            {
                return mprotect(lpAddress, (ulong)dwSize.ToInt64(), prot) == 0;
            }

            // For remote processes, we can't easily change protection without code injection
            // Return true and hope the memory is already accessible
            return true;
        }

        private int ConvertWindowsProtectionToLinux(uint windowsProtect)
        {
            int prot = 0;

            if ((windowsProtect & 0x02) != 0) prot |= PROT_READ; // PAGE_READONLY
            if ((windowsProtect & 0x04) != 0) prot |= PROT_READ | PROT_WRITE; // PAGE_READWRITE
            if ((windowsProtect & 0x10) != 0) prot |= PROT_READ | PROT_EXEC; // PAGE_EXECUTE_READ
            if ((windowsProtect & 0x20) != 0) prot |= PROT_READ | PROT_WRITE | PROT_EXEC; // PAGE_EXECUTE_READWRITE
            if ((windowsProtect & 0x40) != 0) prot |= PROT_READ | PROT_WRITE | PROT_EXEC; // PAGE_EXECUTE_READWRITE (alternate)

            return prot;
        }

        public nint VirtualAllocEx(nint hProcess, nint lpAddress, nint dwSize, uint flAllocationType, uint flProtect)
        {
            int pid = hProcess.ToInt32();

            // For remote process memory allocation, we have limited options on Linux:
            // 1. The target process must allocate memory itself
            // 2. We can try to find existing free memory regions
            // 3. We can inject code to call mmap

            // For simplicity, we'll try to find a suitable free region
            // This is a limitation compared to Windows VirtualAllocEx
            Log.Logger.Warning($"VirtualAllocEx called for process {pid} - finding existing free region instead of allocating");

            uint size = (uint)dwSize.ToInt64();
            nint freeRegion = FindFreeRegionBelow4GB(hProcess, size);

            if (freeRegion == nint.Zero)
            {
                Log.Logger.Error($"Could not find suitable free memory region in process {pid}");
            }

            return freeRegion;
        }

        public bool VirtualFreeEx(nint hProcess, nint lpAddress, nint dwSize, uint dwFreeType)
        {
            // On Linux, we can't directly free memory in another process
            // This would require code injection to call munmap
            // For now, just return true (memory will be reclaimed when process exits)
            Log.Logger.Debug($"VirtualFreeEx called - no-op on Linux (memory will be reclaimed on process exit)");
            return true;
        }

        public nint FindFreeRegionBelow4GB(nint processHandle, uint size)
        {
            int pid = processHandle.ToInt32();
            string mapsPath = $"/proc/{pid}/maps";

            if (!File.Exists(mapsPath))
            {
                Log.Logger.Error($"Could not find memory maps for process {pid}");
                return nint.Zero;
            }

            try
            {
                const ulong MAX_32BIT = 0x7FFE0000;
                var lines = File.ReadAllLines(mapsPath);

                // Parse memory regions
                List<(ulong start, ulong end)> regions = new List<(ulong, ulong)>();
                foreach (var line in lines)
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 1) continue;

                    var addresses = parts[0].Split('-');
                    if (addresses.Length != 2) continue;

                    ulong start = Convert.ToUInt64(addresses[0], 16);
                    ulong end = Convert.ToUInt64(addresses[1], 16);

                    // Only consider regions below 4GB
                    if (start < MAX_32BIT)
                    {
                        regions.Add((start, Math.Min(end, MAX_32BIT)));
                    }
                }

                // Sort regions by start address
                regions.Sort();

                // Find gaps between regions
                ulong lastEnd = 0x10000; // Start searching from a reasonable base
                foreach (var (start, end) in regions)
                {
                    if (start > lastEnd)
                    {
                        ulong gapSize = start - lastEnd;
                        if (gapSize >= size)
                        {
                            // Found a suitable gap
                            // Align to page boundary (4KB)
                            ulong alignedAddress = lastEnd + 0xFFF & ~0xFFFul;
                            if (alignedAddress + size <= start)
                            {
                                return new nint((long)alignedAddress);
                            }
                        }
                    }
                    lastEnd = end;
                }

                Log.Logger.Warning($"Could not find free region of size {size} below 4GB");
                return nint.Zero;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error parsing memory maps: {ex.Message}");
                return nint.Zero;
            }
        }

        public bool CloseHandle(nint handle)
        {
            // Detach from process if we were attached
            int pid = handle.ToInt32();
            if (_attachedProcesses.ContainsKey(pid) && _attachedProcesses[pid])
            {
                return DetachFromProcess(pid);
            }
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
        #endregion

        #region Module Information
        public MODULEINFO GetModuleInfo(nint processHandle, string moduleName)
        {
            MODULEINFO moduleInfo = new MODULEINFO();
            int pid = processHandle.ToInt32();

            string mapsPath = $"/proc/{pid}/maps";
            try
            {
                if (!File.Exists(mapsPath))
                {
                    Log.Logger.Error($"Could not find memory maps for process {pid}");
                    return moduleInfo;
                }

                var lines = File.ReadAllLines(mapsPath);
                ulong firstStart = 0;
                ulong lastEnd = 0;
                bool foundFirst = false;

                foreach (var line in lines)
                {
                    if (line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var addresses = parts[0].Split('-');

                        ulong start = Convert.ToUInt64(addresses[0], 16);
                        ulong end = Convert.ToUInt64(addresses[1], 16);

                        if (!foundFirst)
                        {
                            firstStart = start;
                            foundFirst = true;
                        }
                        lastEnd = end;
                    }
                }

                if (foundFirst)
                {
                    moduleInfo.lpBaseOfDll = new nint((long)firstStart);
                    moduleInfo.SizeOfImage = (uint)(lastEnd - firstStart);
                    moduleInfo.EntryPoint = nint.Zero; // Not easily available on Linux
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error getting module info: {ex.Message}");
            }

            return moduleInfo;
        }

        public nint GetModuleHandle(string moduleName)
        {
            try
            {
                var lines = File.ReadAllLines("/proc/self/maps");
                foreach (var line in lines)
                {
                    if (line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        var address = line.Split('-')[0];
                        return new nint((long)Convert.ToUInt64(address, 16));
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error getting module handle: {ex.Message}");
            }

            return nint.Zero;
        }
        public nint GetModuleBaseAddress(int pid, string moduleName)
        {
            try
            {
                string mapsPath = $"/proc/{pid}/maps";
                if (!File.Exists(mapsPath))
                {
                    Log.Logger.Warning($"Could not find memory maps for process {pid}");
                    return nint.Zero;
                }

                var lines = File.ReadAllLines(mapsPath);
                foreach (var line in lines)
                {
                    // Look for lines containing the module name
                    if (line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Parse the address range (format: "start-end perms offset dev:inode pathname")
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 1) continue;

                        var addresses = parts[0].Split('-');
                        if (addresses.Length != 2) continue;

                        // Return the start address (base address)
                        ulong baseAddress = Convert.ToUInt64(addresses[0], 16);
                        return new nint((long)baseAddress);
                    }
                }

                Log.Logger.Warning($"Module '{moduleName}' not found in process {pid}");
                return nint.Zero;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error getting module base address on Linux: {ex.Message}");
                return nint.Zero;
            }
        }
        #endregion

        #region Remote Execution
        public uint Execute(nint processHandle, nint address, uint timeoutSeconds = 0xFFFFFFFF)
        {
            int pid = processHandle.ToInt32();

            // Remote thread execution on Linux is complex and requires ptrace manipulation
            // This is a simplified implementation

            if (!AttachToProcess(pid))
            {
                Log.Logger.Error($"Failed to attach to process {pid} for execution");
                return 0;
            }

            try
            {
                // Get current registers
                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out user_regs_struct regs) == -1)
                {
                    Log.Logger.Error($"Failed to get registers: {GetLastErrorMessage()}");
                    return 0;
                }

                // Save original instruction pointer
                ulong originalRip = regs.rip;

                // Set instruction pointer to our code
                regs.rip = (ulong)address.ToInt64();

                // Set registers
                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref regs) == -1)
                {
                    Log.Logger.Error($"Failed to set registers: {GetLastErrorMessage()}");
                    return 0;
                }

                // Continue execution
                if (ptrace(PTRACE_CONT, pid, nint.Zero, nint.Zero) == -1)
                {
                    Log.Logger.Error($"Failed to continue process: {GetLastErrorMessage()}");
                    return 0;
                }

                // Wait for execution to complete
                // Note: This is simplified - in reality you'd need to handle signals and breakpoints
                int status;
                if (waitpid(pid, out status, 0) == -1)
                {
                    Log.Logger.Error($"Failed to wait for process: {GetLastErrorMessage()}");
                    return 0;
                }

                // Restore original instruction pointer
                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out regs) == -1)
                {
                    Log.Logger.Error($"Failed to get registers after execution: {GetLastErrorMessage()}");
                    return 0;
                }

                regs.rip = originalRip;
                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref regs) == -1)
                {
                    Log.Logger.Error($"Failed to restore registers: {GetLastErrorMessage()}");
                    return 0;
                }

                return 1;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error executing remote code: {ex.Message}");
                return 0;
            }
            finally
            {
                // Note: We intentionally don't detach here since the caller might want to do more operations
                // Detachment should happen when CloseHandle is called
            }
        }

        public uint ExecuteCommand(nint processHandle, byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
        {
            int pid = processHandle.ToInt32();

            // Find a suitable memory region
            nint address = FindFreeRegionBelow4GB(processHandle, (uint)bytes.Length);
            if (address == nint.Zero)
            {
                Log.Logger.Error($"Failed to find memory region for execution");
                return 0;
            }

            try
            {
                // Write the code to memory
                if (!WriteProcessMemory(processHandle, (ulong)address, bytes, bytes.Length, out nint bytesWritten))
                {
                    Log.Logger.Error($"Failed to write bytes to memory: {GetLastErrorMessage()}");
                    return 0;
                }

                // Execute the code
                uint result = Execute(processHandle, address, timeoutSeconds);

                return result;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error executing command: {ex.Message}");
                return 0;
            }
            finally
            {
                // Note: We can't easily free the memory on Linux without code injection
                // The memory will be reclaimed when the process exits
            }
        }
        #endregion

        #region Helper Methods
        public nint GetSymbolAddress(string libraryPath, string symbolName)
        {
            const int RTLD_LAZY = 1;

            nint handle = dlopen(libraryPath, RTLD_LAZY);
            if (handle == nint.Zero)
            {
                Log.Logger.Error($"Failed to load library {libraryPath}");
                return nint.Zero;
            }

            try
            {
                nint symbol = dlsym(handle, symbolName);
                if (symbol == nint.Zero)
                {
                    Log.Logger.Error($"Failed to find symbol {symbolName} in {libraryPath}");
                }
                return symbol;
            }
            finally
            {
                dlclose(handle);
            }
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
        #endregion

        #region export info
        public nint GetExportAddress(int pid, nint moduleBase, string exportName)
        {
            // Linux implementation requires parsing ELF headers
            // This is a complex operation that would need full ELF parsing

            nint processHandle = OpenProcess(0x0010 | 0x0008, false, pid); // VM_READ | VM_OPERATION
            if (processHandle == nint.Zero)
            {
                Log.Logger.Error($"Failed to open process {pid}");
                return nint.Zero;
            }

            try
            {
                return FindELFExport(processHandle, moduleBase, exportName);
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        private nint FindELFExport(nint processHandle, nint moduleBase, string exportName)
        {
            try
            {
                // Read ELF header
                byte[] elfHeader = new byte[64]; // ELF64 header size
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase, elfHeader, elfHeader.Length, out nint bytesRead))
                {
                    Log.Logger.Warning("Failed to read ELF header");
                    return nint.Zero;
                }

                // Check ELF magic number
                if (elfHeader[0] != 0x7F || elfHeader[1] != 'E' || elfHeader[2] != 'L' || elfHeader[3] != 'F')
                {
                    Log.Logger.Warning("Invalid ELF magic number");
                    return nint.Zero;
                }

                // Determine if 32-bit or 64-bit
                bool is64Bit = elfHeader[4] == 2;
                if (!is64Bit)
                {
                    Log.Logger.Warning("32-bit ELF not fully supported");
                    return nint.Zero;
                }

                // Read section header offset and count
                ulong shoff = BitConverter.ToUInt64(elfHeader, 40);    // e_shoff (section header table offset)
                ushort shentsize = BitConverter.ToUInt16(elfHeader, 58); // e_shentsize (section header entry size)
                ushort shnum = BitConverter.ToUInt16(elfHeader, 60);   // e_shnum (number of section headers)
                ushort shstrndx = BitConverter.ToUInt16(elfHeader, 62); // e_shstrndx (section name string table index)

                // Read section headers
                byte[] sectionHeaders = new byte[shentsize * shnum];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase + shoff, sectionHeaders, sectionHeaders.Length, out bytesRead))
                {
                    Log.Logger.Warning("Failed to read section headers");
                    return nint.Zero;
                }

                // Find .dynsym and .dynstr sections
                ulong dynsymOffset = 0;
                ulong dynsymSize = 0;
                ulong dynstrOffset = 0;
                ulong dynstrSize = 0;

                for (int i = 0; i < shnum; i++)
                {
                    int offset = i * shentsize;

                    uint sh_name = BitConverter.ToUInt32(sectionHeaders, offset);      // Section name (string table index)
                    uint sh_type = BitConverter.ToUInt32(sectionHeaders, offset + 4);   // Section type
                    ulong sh_offset = BitConverter.ToUInt64(sectionHeaders, offset + 24); // Section file offset
                    ulong sh_size = BitConverter.ToUInt64(sectionHeaders, offset + 32);   // Section size

                    // SHT_DYNSYM = 11, SHT_STRTAB = 3
                    if (sh_type == 11) // .dynsym
                    {
                        dynsymOffset = sh_offset;
                        dynsymSize = sh_size;
                    }
                    else if (sh_type == 3 && i != shstrndx) // .dynstr (but not .shstrtab)
                    {
                        // We need to verify this is actually .dynstr, not .strtab
                        // For simplicity, assume the first non-shstrtab string table is .dynstr
                        if (dynstrOffset == 0)
                        {
                            dynstrOffset = sh_offset;
                            dynstrSize = sh_size;
                        }
                    }
                }

                if (dynsymOffset == 0 || dynstrOffset == 0)
                {
                    Log.Logger.Warning("Could not find .dynsym or .dynstr sections");
                    return nint.Zero;
                }

                // Read .dynstr (string table)
                byte[] dynstr = new byte[dynstrSize];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase + dynstrOffset, dynstr, (int)dynstrSize, out bytesRead))
                {
                    Log.Logger.Warning("Failed to read .dynstr");
                    return nint.Zero;
                }

                // Read and search .dynsym (symbol table)
                const int SYM_ENTRY_SIZE = 24; // sizeof(Elf64_Sym)
                int numSymbols = (int)(dynsymSize / SYM_ENTRY_SIZE);

                for (int i = 0; i < numSymbols; i++)
                {
                    byte[] symEntry = new byte[SYM_ENTRY_SIZE];
                    if (!ReadProcessMemory(processHandle, (ulong)moduleBase + dynsymOffset + (ulong)(i * SYM_ENTRY_SIZE),
                        symEntry, SYM_ENTRY_SIZE, out bytesRead))
                    {
                        continue;
                    }

                    uint st_name = BitConverter.ToUInt32(symEntry, 0);      // Symbol name (string table index)
                    ulong st_value = BitConverter.ToUInt64(symEntry, 8);    // Symbol value/address

                    // Get symbol name from string table
                    if (st_name >= dynstrSize) continue;

                    string symbolName = GetNullTerminatedString(dynstr, (int)st_name);

                    if (symbolName == exportName)
                    {
                        // Found the symbol
                        return (nint)((ulong)moduleBase + st_value);
                    }
                }

                Log.Logger.Warning($"Export '{exportName}' not found in ELF symbol table");
                return nint.Zero;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error parsing ELF: {ex.Message}");
                return nint.Zero;
            }
        }

        #endregion
    }
}