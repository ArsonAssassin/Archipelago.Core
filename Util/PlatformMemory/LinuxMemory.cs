using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        private const int PTRACE_SINGLESTEP = 9;

        // signals
        private const int SIGTRAP = 5;
        private const int SIGSTOP = 19;
        private const int SIGSEGV = 11;
        private const int SIGILL = 4;
        private const int SIGBUS = 7;
        private const int EINTR = 4;

        // Memory protection flags
        private const int PROT_NONE = 0x0;
        private const int PROT_READ = 0x1;
        private const int PROT_WRITE = 0x2;
        private const int PROT_EXEC = 0x4;

        // mmap flags
        private const int MAP_PRIVATE = 0x02;
        private const int MAP_ANONYMOUS = 0x20;

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

        #region WINE / ptrace-scope Detection
        private bool IsWineProcess(int pid)
        {
            try
            {
                string exePath = File.ReadAllText($"/proc/{pid}/comm").Trim();
                if (exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    return true;

                string mapsPath = $"/proc/{pid}/maps";
                if (File.Exists(mapsPath))
                {
                    string maps = File.ReadAllText(mapsPath);
                    if (maps.Contains("wine", StringComparison.OrdinalIgnoreCase) ||
                        maps.Contains("proton", StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                string exeLink = $"/proc/{pid}/exe";
                if (File.Exists(exeLink))
                {
                    string exeTarget = new FileInfo(exeLink).LinkTarget ?? string.Empty;
                    if (exeTarget.Contains("wine", StringComparison.OrdinalIgnoreCase) ||
                        exeTarget.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch {  }
            return false;
        }

        private bool CheckPtraceScope(int pid)
        {
            const string ptraceScopePath = "/proc/sys/kernel/yama/ptrace_scope";
            if (!File.Exists(ptraceScopePath))
                return true; 

            if (!int.TryParse(File.ReadAllText(ptraceScopePath).Trim(), out int scope))
                return true;

            switch (scope)
            {
                case 0:
                    return true;
                case 1:
                    Log.Logger.Warning(
                        $"ptrace_scope=1: ptrace is restricted to parent processes. " +
                        $"To allow tracing process {pid}, either run as root, " +
                        $"grant CAP_SYS_PTRACE, or set: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope");
                    return true;
                case 2:
                    Log.Logger.Error(
                        $"ptrace_scope=2: ptrace is restricted to root/CAP_SYS_PTRACE only. " +
                        $"Remote execution will not work without elevated privileges.");
                    return false;
                case 3:
                    Log.Logger.Error(
                        $"ptrace_scope=3: ptrace is completely disabled on this system. " +
                        $"Remote execution cannot function.");
                    return false;
                default:
                    return true;
            }
        }

        #endregion

        #region Process Attachment
        private Dictionary<int, bool> _attachedProcesses = new Dictionary<int, bool>();

        // These are common op-codes that are guaranteed to be at least 3 bytes long
        private byte[][] saveInstructions =
        [
            [0xB8, 0xBF],
            [0xC6],
            [0xC7],
            [0x80],
            [0x81],
            [0x83],
            [0x48, 0x88],
            [0x48, 0x89],
            [0x48, 0x8A],
            [0x48, 0x8B],
            [0x48, 0x8C],
            [0x48, 0x8E],
            [0x48, 0x3D],
            [0x3D],
        ];

        private bool AttachToProcess(int pid)
        {
            if (_attachedProcesses.ContainsKey(pid) && _attachedProcesses[pid])
                return true;

            if (IsWineProcess(pid))
            {
                Log.Logger.Error(
                    $"Process {pid} appears to be a WINE/Proton process. " +
                    $"ptrace-based code injection does not work against WINE processes from a native Linux host.");
                return false;
            }

            if (!CheckPtraceScope(pid))
                return false;

            bool saveInstruction = false;

            while (!saveInstruction)
            {
                if (ptrace(PTRACE_ATTACH, pid, nint.Zero, nint.Zero) == -1)
                {
                    Log.Logger.Error($"Failed to attach to process {pid}: {GetLastErrorMessage()}");
                    return false;
                }

                // Wait for the process to stop
                int status;
                if (waitpid(pid, out status, 0) != pid)
                {
                    Log.Logger.Error($"Failed to wait for process {pid}: {GetLastErrorMessage()}");
                    ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero);
                    return false;
                }

                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out user_regs_struct regs) == -1)
                {
                    Log.Logger.Error($"Failed to get registers: {GetLastErrorMessage()}");
                    ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero);
                    return false;
                }

                byte[] bytes = new byte[3];
                if (!ReadProcessMemory(pid, regs.rip, bytes, 3, out _))
                {
                    Log.Logger.Error("Failed to read current bytes");
                    ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero);
                    return false;
                }

                if (saveInstructions.Any(instr => bytes.Take(instr.Length).SequenceEqual(instr)))
                {
                    Log.Logger.Debug($"Stopped bytes: {BitConverter.ToString(bytes)}");
                    saveInstruction = true;
                }
                else
                {
                    // Detach and reattach trying to get to a different instruction
                    if (ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero) == -1)
                    {
                        Log.Logger.Error($"Failed to detach from process {pid}: {GetLastErrorMessage()}");
                        return false;
                    }
                    Thread.Sleep(50);
                }
            }

            _attachedProcesses[pid] = true;
            Log.Logger.Debug($"Attached to process: {pid}");
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
            Log.Logger.Debug($"Detached from process: {pid}");
            return true;
        }

        private static bool WaitForInt3(int pid)
        {
            static bool WIFSTOPPED(int status) => (status & 0xFF) == 0x7F;
            static int WSTOPSIG(int status) => (status >> 8) & 0xFF;

            int status;

            while (true)
            {
                int r = waitpid(pid, out status, WUNTRACED);
                if (r < 0)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == EINTR) continue; // interrupted by signal, retry
                    throw new Win32Exception(err, $"waitpid failed: error {err}");
                }

                if (!WIFSTOPPED(status))
                    continue;

                int sig = WSTOPSIG(status);

                if (sig == SIGTRAP)
                    return true; // hit our int3

                // Fatal signal in the remote process — log and bail to avoid hanging
                if (sig == SIGSEGV || sig == SIGILL || sig == SIGBUS)
                {
                    Log.Logger.Error(
                        $"Remote process received fatal signal {sig} during Execute. " +
                        $"The injected code likely crashed (stack misalignment or bad address). " +
                        $"Detaching to allow the OS to handle the signal.");
                    return false;
                }

                // Other signals (e.g. SIGSTOP from an external debugger) — log but keep waiting
                Log.Logger.Warning($"Remote process received unexpected signal {sig} during Execute — continuing to wait.");
            }
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
                // Try process_vm_readv first (more efficient, no ptrace needed)
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

                    Log.Logger.Debug($"process_vm_readv failed: {GetLastErrorMessage()}, falling back to /proc/{pid}/mem");
                }
                finally
                {
                    bufferHandle.Free();
                }

                // Fallback: /proc/pid/mem
                string memPath = $"/proc/{pid}/mem";
                if (File.Exists(memPath))
                {
                    using FileStream fs = new FileStream(memPath, FileMode.Open, FileAccess.Read);
                    fs.Seek((long)lpBaseAddress, SeekOrigin.Begin);
                    int bytesRead = fs.Read(lpBuffer, 0, dwSize);
                    lpNumberOfBytesRead = new nint(bytesRead);
                    return bytesRead > 0;
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

                // Fallback: /proc/pid/mem
                string memPath = $"/proc/{pid}/mem";
                if (File.Exists(memPath))
                {
                    using FileStream fs = new FileStream(memPath, FileMode.Open, FileAccess.Write);
                    fs.Seek((long)lpBaseAddress, SeekOrigin.Begin);
                    fs.Write(lpBuffer, 0, dwSize);
                    lpNumberOfBytesWritten = new nint(dwSize);
                    return true;
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

            Log.Logger.Warning($"VirtualProtectEx called for remote process {pid} - this operation has limited support on Linux");

            int prot = ConvertWindowsProtectionToLinux(flNewProtect);

            if (pid == Process.GetCurrentProcess().Id)
                return mprotect(lpAddress, (ulong)dwSize.ToInt64(), prot) == 0;

            // For remote processes we rely on the memory already being accessible via mmap injection
            return true;
        }

        private int ConvertWindowsProtectionToLinux(uint windowsProtect)
        {
            int prot = 0;
            if ((windowsProtect & 0x02) != 0) prot |= PROT_READ;                      // PAGE_READONLY
            if ((windowsProtect & 0x04) != 0) prot |= PROT_READ | PROT_WRITE;         // PAGE_READWRITE
            if ((windowsProtect & 0x10) != 0) prot |= PROT_READ | PROT_EXEC;          // PAGE_EXECUTE_READ
            if ((windowsProtect & 0x20) != 0) prot |= PROT_READ | PROT_WRITE | PROT_EXEC; // PAGE_EXECUTE_READWRITE
            if ((windowsProtect & 0x40) != 0) prot |= PROT_READ | PROT_WRITE | PROT_EXEC; // PAGE_EXECUTE_READWRITE (alt)
            return prot;
        }

        // syscall; — used to inject mmap/munmap via single-step
        private readonly byte[] syscallBytes = [0x0f, 0x05];
        // call rax; int3; — used to invoke an arbitrary function then trap back
        private readonly byte[] callRaxBytes = [0xff, 0xd0, 0xcc];

        public nint VirtualAllocEx(nint hProcess, nint lpAddress, nint dwSize, uint flAllocationType, uint flProtect)
        {
            int pid = hProcess.ToInt32();

            Log.Logger.Debug($"Injecting mmap for allocation in process {pid}");
            if (!AttachToProcess(pid)) return nint.Zero;

            try
            {
                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out user_regs_struct originalRegs) == -1)
                {
                    Log.Logger.Error($"Failed to get original registers: {GetLastErrorMessage()}");
                    return nint.Zero;
                }

                ulong originalRip = originalRegs.rip;

                byte[] originalBytes = new byte[syscallBytes.Length];
                if (!ReadProcessMemory(hProcess, originalRip, originalBytes, syscallBytes.Length, out _))
                {
                    Log.Logger.Error("Failed to read original instruction bytes");
                    return nint.Zero;
                }

                if (!WriteProcessMemory(hProcess, originalRip, syscallBytes, syscallBytes.Length, out _))
                {
                    Log.Logger.Error("Failed to write syscall bytes");
                    return nint.Zero;
                }

                // Set up registers for mmap (syscall number 9)
                user_regs_struct regs = originalRegs;
                regs.rax = 9;                                                          // SYS_mmap
                regs.rdi = (ulong)lpAddress.ToInt64();                                 // addr hint (0 = any)
                regs.rsi = (ulong)dwSize.ToInt64();                                    // length
                regs.rdx = (ulong)ConvertWindowsProtectionToLinux(flProtect);          // prot
                regs.r10 = (ulong)(MAP_PRIVATE | MAP_ANONYMOUS);                       // flags
                regs.r8 = ulong.MaxValue;                                             // fd = -1
                regs.r9 = 0;                                                          // offset
                regs.rip = originalRip;

                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref regs) == -1)
                {
                    Log.Logger.Error($"Failed to set registers: {GetLastErrorMessage()}");
                    return nint.Zero;
                }

                if (ptrace(PTRACE_SINGLESTEP, pid, nint.Zero, nint.Zero) == -1)
                {
                    Log.Logger.Error($"Failed to single-step process: {GetLastErrorMessage()}");
                    return nint.Zero;
                }

                int status;
                if (waitpid(pid, out status, 0) != pid)
                {
                    Log.Logger.Error($"Failed to wait for process {pid}: {GetLastErrorMessage()}");
                    ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero);
                    return nint.Zero;
                }

                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out regs) == -1)
                {
                    Log.Logger.Error($"Failed to get registers after mmap: {GetLastErrorMessage()}");
                    return nint.Zero;
                }

                long allocatedAddr = (long)regs.rax;
                Log.Logger.Debug($"mmap result: 0x{allocatedAddr:X}");

                // mmap returns a small negative errno on failure (e.g. -12 for ENOMEM)
                if (allocatedAddr < 0 || allocatedAddr < 0x1000)
                {
                    Log.Logger.Error($"mmap failed in remote process (return: {allocatedAddr})");
                    return nint.Zero;
                }

                // Restore original bytes then registers so the thread re-executes from where it paused
                if (!WriteProcessMemory(hProcess, originalRip, originalBytes, syscallBytes.Length, out _))
                    Log.Logger.Error("Failed to restore original bytes after mmap");

                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref originalRegs) == -1)
                    Log.Logger.Error($"Failed to restore registers after mmap: {GetLastErrorMessage()}");

                return new nint(allocatedAddr);
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"VirtualAllocEx failed: {ex.Message}");
                return nint.Zero;
            }
            finally
            {
                DetachFromProcess(pid);
            }
        }

        public bool VirtualFreeEx(nint hProcess, nint lpAddress, nint dwSize, uint dwFreeType)
        {
            int pid = hProcess.ToInt32();

            Log.Logger.Debug($"Injecting munmap to free memory in process {pid}");
            if (!AttachToProcess(pid)) return false;

            try
            {
                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out user_regs_struct originalRegs) == -1)
                {
                    Log.Logger.Error($"Failed to get original registers: {GetLastErrorMessage()}");
                    return false;
                }

                ulong originalRip = originalRegs.rip;

                byte[] originalBytes = new byte[syscallBytes.Length];
                if (!ReadProcessMemory(hProcess, originalRip, originalBytes, syscallBytes.Length, out _))
                {
                    Log.Logger.Error("Failed to read original instruction bytes");
                    return false;
                }

                if (!WriteProcessMemory(hProcess, originalRip, syscallBytes, syscallBytes.Length, out _))
                {
                    Log.Logger.Error("Failed to write syscall bytes");
                    return false;
                }

                user_regs_struct regs = originalRegs;
                regs.rax = 11;                              // SYS_munmap
                regs.rdi = (ulong)lpAddress.ToInt64();      // addr
                regs.rsi = (ulong)dwSize.ToInt64();         // length
                regs.rip = originalRip;

                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref regs) == -1)
                {
                    Log.Logger.Error($"Failed to set registers: {GetLastErrorMessage()}");
                    return false;
                }

                if (ptrace(PTRACE_SINGLESTEP, pid, nint.Zero, nint.Zero) == -1)
                {
                    Log.Logger.Error($"Failed to single-step process: {GetLastErrorMessage()}");
                    return false;
                }

                int status;
                if (waitpid(pid, out status, 0) != pid)
                {
                    Log.Logger.Error($"Failed to wait for process {pid}: {GetLastErrorMessage()}");
                    ptrace(PTRACE_DETACH, pid, nint.Zero, nint.Zero);
                    return false;
                }

                if (!WriteProcessMemory(hProcess, originalRip, originalBytes, syscallBytes.Length, out _))
                    Log.Logger.Error("Failed to restore original bytes after munmap");

                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref originalRegs) == -1)
                    Log.Logger.Error($"Failed to restore registers after munmap: {GetLastErrorMessage()}");

                return true;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"VirtualFreeEx failed: {ex.Message}");
                return false;
            }
            finally
            {
                DetachFromProcess(pid);
            }
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

                List<(ulong start, ulong end)> regions = new List<(ulong, ulong)>();
                foreach (var line in lines)
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 1) continue;

                    var addresses = parts[0].Split('-');
                    if (addresses.Length != 2) continue;

                    ulong start = Convert.ToUInt64(addresses[0], 16);
                    ulong end = Convert.ToUInt64(addresses[1], 16);

                    if (start < MAX_32BIT)
                        regions.Add((start, Math.Min(end, MAX_32BIT)));
                }

                regions.Sort();

                ulong lastEnd = 0x10000;
                foreach (var (start, end) in regions)
                {
                    if (start > lastEnd)
                    {
                        ulong gapSize = start - lastEnd;
                        if (gapSize >= size)
                        {
                            ulong alignedAddress = (lastEnd + 0xFFF) & ~0xFFFul;
                            if (alignedAddress + size <= start)
                                return new nint((long)alignedAddress);
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
            int pid = handle.ToInt32();
            if (_attachedProcesses.ContainsKey(pid) && _attachedProcesses[pid])
                return DetachFromProcess(pid);
            return true;
        }

        public int GetPID(string procName)
        {
            // On Linux, process names are capped at 15 chars + null terminator
            procName = procName[..Math.Min(15, procName.Length)];
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
            procName = procName[..Math.Min(15, procName.Length)];
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
                    moduleInfo.EntryPoint = nint.Zero;
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
                    if (line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 1) continue;

                        var addresses = parts[0].Split('-');
                        if (addresses.Length != 2) continue;

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

            Log.Logger.Debug($"Injecting function call to 0x{address:X} in process {pid}");
            if (!AttachToProcess(pid)) return 0;

            try
            {
                if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out user_regs_struct originalRegs) == -1)
                {
                    Log.Logger.Error($"Failed to get original registers: {GetLastErrorMessage()}");
                    return 0;
                }

                ulong originalRip = originalRegs.rip;

                byte[] originalBytes = new byte[callRaxBytes.Length];
                if (!ReadProcessMemory(processHandle, originalRip, originalBytes, callRaxBytes.Length, out _))
                {
                    Log.Logger.Error("Failed to read original instruction bytes");
                    return 0;
                }

                // Write:  call rax  (ff d0)
                //         int3      (cc)       ← trap so we know the call returned
                if (!WriteProcessMemory(processHandle, originalRip, callRaxBytes, callRaxBytes.Length, out _))
                {
                    Log.Logger.Error("Failed to write call+int3 shellcode");
                    return 0;
                }

                user_regs_struct regs = originalRegs;
                regs.rax = (ulong)address.ToInt64(); // function to call

                ulong alignedRsp = (originalRegs.rsp - 128UL) & ~0xFUL;
                regs.rsp = alignedRsp - 8UL; // (alignedRsp - 8) % 16 == 8 ✓

                regs.rip = originalRip;
                regs.eflags = 0;

                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref regs) == -1)
                {
                    Log.Logger.Error($"Failed to set registers: {GetLastErrorMessage()}");
                    return 0;
                }

                if (ptrace(PTRACE_CONT, pid, nint.Zero, nint.Zero) == -1)
                {
                    Log.Logger.Error($"Failed to continue process: {GetLastErrorMessage()}");
                    return 0;
                }

                bool hitBreakpoint = WaitForInt3(pid);

                // Capture the return value from rax before restoring anything
                uint returnValue = 0;
                if (hitBreakpoint)
                {
                    if (ptrace_getregs(PTRACE_GETREGS, pid, nint.Zero, out user_regs_struct postCallRegs) == 0)
                    {
                        returnValue = (uint)(postCallRegs.rax & 0xFFFFFFFF);
                        Log.Logger.Debug($"Remote call returned rax=0x{postCallRegs.rax:X}");
                    }
                    else
                    {
                        Log.Logger.Warning($"Could not read post-call registers: {GetLastErrorMessage()}");
                    }
                }

                if (!WriteProcessMemory(processHandle, originalRip, originalBytes, callRaxBytes.Length, out _))
                    Log.Logger.Error("Failed to restore original bytes after Execute");

                if (ptrace_setregs(PTRACE_SETREGS, pid, nint.Zero, ref originalRegs) == -1)
                    Log.Logger.Error($"Failed to restore registers after Execute: {GetLastErrorMessage()}");

                if (!hitBreakpoint)
                {
                    Log.Logger.Error("Execute failed: remote function did not return cleanly");
                    return 0;
                }

                return returnValue;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Execute failed with exception: {ex.Message}");
                return 0;
            }
            finally
            {
                DetachFromProcess(pid);
            }
        }

        public uint ExecuteCommand(nint processHandle, byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
        {
            nint address = VirtualAllocEx(processHandle, nint.Zero, bytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (address == nint.Zero)
            {
                Log.Logger.Error($"Failed to allocate memory for ExecuteCommand: {GetLastErrorMessage()}");
                return 0;
            }

            try
            {
                if (!WriteProcessMemory(processHandle, (ulong)address, bytes, bytes.Length, out _))
                {
                    Log.Logger.Error($"Failed to write command bytes to memory: {GetLastErrorMessage()}");
                    return 0;
                }

                return Execute(processHandle, address, timeoutSeconds);
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"ExecuteCommand failed: {ex.Message}");
                return 0;
            }
            finally
            {
                if (!VirtualFreeEx(processHandle, address, new nint(bytes.Length), MEM_RELEASE))
                    Log.Logger.Warning($"Failed to free command memory: {GetLastErrorMessage()}");
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
                    Log.Logger.Error($"Failed to find symbol {symbolName} in {libraryPath}");
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
                length++;
            return Encoding.UTF8.GetString(buffer, offset, length);
        }
        #endregion

        #region Export Info
        public nint GetExportAddress(int pid, nint moduleBase, string exportName)
        {
            nint processHandle = OpenProcess(0x0010 | 0x0008, false, pid);
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
                // Read ELF64 header (64 bytes)
                byte[] elfHeader = new byte[64];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase, elfHeader, elfHeader.Length, out _))
                {
                    Log.Logger.Warning("Failed to read ELF header");
                    return nint.Zero;
                }

                if (elfHeader[0] != 0x7F || elfHeader[1] != 'E' || elfHeader[2] != 'L' || elfHeader[3] != 'F')
                {
                    Log.Logger.Warning("Invalid ELF magic number");
                    return nint.Zero;
                }

                bool is64Bit = elfHeader[4] == 2;
                if (!is64Bit)
                {
                    Log.Logger.Warning("32-bit ELF not supported");
                    return nint.Zero;
                }

                ulong shoff = BitConverter.ToUInt64(elfHeader, 40);
                ushort shentsize = BitConverter.ToUInt16(elfHeader, 58);
                ushort shnum = BitConverter.ToUInt16(elfHeader, 60);
                ushort shstrndx = BitConverter.ToUInt16(elfHeader, 62);

                byte[] sectionHeaders = new byte[shentsize * shnum];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase + shoff, sectionHeaders, sectionHeaders.Length, out _))
                {
                    Log.Logger.Warning("Failed to read section headers");
                    return nint.Zero;
                }

                ulong dynsymOffset = 0, dynsymSize = 0;
                ulong dynstrOffset = 0, dynstrSize = 0;

                for (int i = 0; i < shnum; i++)
                {
                    int offset = i * shentsize;
                    uint sh_type = BitConverter.ToUInt32(sectionHeaders, offset + 4);
                    ulong sh_offset = BitConverter.ToUInt64(sectionHeaders, offset + 24);
                    ulong sh_size = BitConverter.ToUInt64(sectionHeaders, offset + 32);

                    if (sh_type == 11) // SHT_DYNSYM
                    {
                        dynsymOffset = sh_offset;
                        dynsymSize = sh_size;
                    }
                    else if (sh_type == 3 && i != shstrndx && dynstrOffset == 0) // SHT_STRTAB (first non-shstrtab)
                    {
                        dynstrOffset = sh_offset;
                        dynstrSize = sh_size;
                    }
                }

                if (dynsymOffset == 0 || dynstrOffset == 0)
                {
                    Log.Logger.Warning("Could not find .dynsym or .dynstr sections");
                    return nint.Zero;
                }

                byte[] dynstr = new byte[dynstrSize];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBase + dynstrOffset, dynstr, (int)dynstrSize, out _))
                {
                    Log.Logger.Warning("Failed to read .dynstr");
                    return nint.Zero;
                }

                const int SYM_ENTRY_SIZE = 24; // sizeof(Elf64_Sym)
                int numSymbols = (int)(dynsymSize / SYM_ENTRY_SIZE);

                for (int i = 0; i < numSymbols; i++)
                {
                    byte[] symEntry = new byte[SYM_ENTRY_SIZE];
                    if (!ReadProcessMemory(processHandle,
                            (ulong)moduleBase + dynsymOffset + (ulong)(i * SYM_ENTRY_SIZE),
                            symEntry, SYM_ENTRY_SIZE, out _))
                        continue;

                    uint st_name = BitConverter.ToUInt32(symEntry, 0);
                    ulong st_value = BitConverter.ToUInt64(symEntry, 8);

                    if (st_name >= dynstrSize) continue;

                    string symbolName = GetNullTerminatedString(dynstr, (int)st_name);
                    if (symbolName == exportName)
                        return (nint)((ulong)moduleBase + st_value);
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