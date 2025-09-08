using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util
{
    public class LinuxMemory : IMemory
    {
        #region Constants
        private const int PTRACE_PEEKDATA = 2;
        private const int PTRACE_POKEDATA = 4;
        private const int PTRACE_ATTACH = 16;
        private const int PTRACE_DETACH = 17;

        private const int PROT_READ = 0x1;
        private const int PROT_WRITE = 0x2;
        private const int PROT_EXEC = 0x4;

        private const int MAP_PRIVATE = 0x02;
        private const int MAP_ANONYMOUS = 0x20;
        #endregion

        #region Native Methods
        [DllImport("libc", SetLastError = true)]
        private static extern int get_errno();

        [DllImport("libc")]
        private static extern IntPtr strerror(int errnum);

        [DllImport("libc", SetLastError = true)]
        private static extern long ptrace(int request, int pid, IntPtr addr, IntPtr data);

        [DllImport("libc", SetLastError = true)]
        private static extern int mprotect(IntPtr addr, ulong len, int prot);

        [DllImport("libc", SetLastError = true)]
        private static extern IntPtr mmap(IntPtr addr, ulong length, int prot, int flags, int fd, long offset);

        [DllImport("libc", SetLastError = true)]
        private static extern int munmap(IntPtr addr, ulong length);
        #endregion

        #region Error Handling
        public string GetLastErrorMessage()
        {
            IntPtr errorString = strerror(get_errno());
            return $"Error {get_errno()}: {Marshal.PtrToStringAnsi(errorString)}";
        }
        public uint GetLastError()
        {
            return (uint)get_errno();
        }
        #endregion

        #region Memory Operations
        public bool ReadProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead)
        {
            lpNumberOfBytesRead = IntPtr.Zero;
            int pid = processH.ToInt32();

            try
            {
                for (int i = 0; i < dwSize; i += 8)
                {
                    long data = ptrace(PTRACE_PEEKDATA, pid, (IntPtr)(lpBaseAddress + (ulong)i), IntPtr.Zero);
                    if (data == -1 && get_errno() != 0)
                        return false;

                    byte[] chunk = BitConverter.GetBytes(data);
                    int bytesToCopy = Math.Min(8, dwSize - i);
                    Array.Copy(chunk, 0, lpBuffer, i, bytesToCopy);
                    lpNumberOfBytesRead = new IntPtr(i + bytesToCopy);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool WriteProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten)
        {
            lpNumberOfBytesWritten = IntPtr.Zero;
            int pid = processH.ToInt32();

            try
            {
                for (int i = 0; i < dwSize; i += 8)
                {
                    int remainingBytes = dwSize - i;
                    long data;

                    if (remainingBytes >= 8)
                    {
                        data = BitConverter.ToInt64(lpBuffer, i);
                    }
                    else
                    {
                        byte[] existing = new byte[8];
                        IntPtr bytesRead;
                        ReadProcessMemory(processH, lpBaseAddress + (ulong)i, existing, 8, out bytesRead);
                        Array.Copy(lpBuffer, i, existing, 0, remainingBytes);
                        data = BitConverter.ToInt64(existing, 0);
                    }

                    if (ptrace(PTRACE_POKEDATA, pid, (IntPtr)(lpBaseAddress + (ulong)i), (IntPtr)data) == -1 && get_errno() != 0)
                    {
                        return false;
                    }
                    lpNumberOfBytesWritten = new IntPtr(i + Math.Min(8, remainingBytes));
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId)
        {
            // On Linux, we just use the PID directly
            return new IntPtr(dwProcessId);
        }

        public bool VirtualProtectEx(IntPtr processH, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            lpflOldProtect = 0;
            int prot = 0;
            if ((flNewProtect & 0x02) != 0) prot |= PROT_READ;
            if ((flNewProtect & 0x04) != 0) prot |= PROT_WRITE;
            if ((flNewProtect & 0x20) != 0) prot |= PROT_EXEC;

            return mprotect(lpAddress, (ulong)dwSize.ToInt64(), prot) == 0;
        }

        public IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect)
        {
            int prot = 0;
            if ((flProtect & 0x02) != 0) prot |= PROT_READ;
            if ((flProtect & 0x04) != 0) prot |= PROT_WRITE;
            if ((flProtect & 0x20) != 0) prot |= PROT_EXEC;

            return mmap(lpAddress, (ulong)dwSize.ToInt64(), prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }

        public bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint dwFreeType)
        {
            return munmap(lpAddress, (ulong)dwSize.ToInt64()) == 0;
        }

        public IntPtr FindFreeRegionBelow4GB(IntPtr processHandle, uint size)
        {
            throw new NotImplementedException();
        }

        public bool CloseHandle(IntPtr handle)
        {
            // Nothing to close in Linux implementation since we use PIDs directly
            return true;
        }

	public int GetPID(string procName)
	{
	    Process[] Processes = Process.GetProcessesByName(procName);
	    if (Processes.Length < 1)
	    {
		return 0;
	    }
	    return Processes[0].Id;
	}
        #endregion

        #region Module Information
        public MODULEINFO GetModuleInfo(IntPtr processHandle, string moduleName)
        {
            MODULEINFO moduleInfo = new MODULEINFO();
            int pid = processHandle.ToInt32();

            string mapsPath = $"/proc/{pid}/maps";
            try
            {
                var lines = File.ReadAllLines(mapsPath);
                foreach (var line in lines)
                {
                    if (line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var addresses = parts[0].Split('-');

                        ulong start = Convert.ToUInt64(addresses[0], 16);
                        ulong end = Convert.ToUInt64(addresses[1], 16);

                        moduleInfo.lpBaseOfDll = new IntPtr((long)start);
                        moduleInfo.SizeOfImage = (uint)(end - start);
                        moduleInfo.EntryPoint = IntPtr.Zero;  // Not easily available on Linux

                        break;
                    }
                }
            }
            catch { }

            return moduleInfo;
        }

        public IntPtr GetModuleHandle(string moduleName)
        {
            try
            {
                var lines = File.ReadAllLines("/proc/self/maps");
                foreach (var line in lines)
                {
                    if (line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        var address = line.Split('-')[0];
                        return new IntPtr((long)Convert.ToUInt64(address, 16));
                    }
                }
            }
            catch { }

            return IntPtr.Zero;
        }
        #endregion

        #region Remote Execution
        public uint Execute(IntPtr processHandle, IntPtr address, uint timeoutSeconds = 0xFFFFFFFF)
        {
            // Note: Remote thread execution on Linux requires different approaches
            // depending on the specific use case. This is a basic implementation.
            int pid = processHandle.ToInt32();

            try
            {
                if (ptrace(PTRACE_ATTACH, pid, IntPtr.Zero, IntPtr.Zero) == -1)
                {
                    Console.WriteLine($"Failed to attach to process: {GetLastErrorMessage()}");
                    return 0;
                }

                // Execute code...
                // This would need to be implemented based on specific requirements
                // Could involve ptrace calls to manipulate registers and execute code

                ptrace(PTRACE_DETACH, pid, IntPtr.Zero, IntPtr.Zero);
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing remote code: {ex.Message}");
                return 0;
            }
        }

        public uint ExecuteCommand(IntPtr processHandle, byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
        {
            // Allocate memory in the target process
            IntPtr address = VirtualAllocEx(processHandle, IntPtr.Zero, (IntPtr)bytes.Length, 0x1000, 0x40);
            if (address == IntPtr.Zero)
            {
                Console.WriteLine($"Failed to allocate memory: {GetLastErrorMessage()}");
                return 0;
            }

            try
            {
                // Write the code to the allocated memory
                IntPtr bytesWritten;
                if (!WriteProcessMemory(processHandle, (ulong)address, bytes, bytes.Length, out bytesWritten))
                {
                    Console.WriteLine($"Failed to write bytes to memory: {GetLastErrorMessage()}");
                    VirtualFreeEx(processHandle, address, IntPtr.Zero, 0x8000);
                    return 0;
                }

                // Execute the code
                uint result = Execute(processHandle, address, timeoutSeconds);

                // Clean up
                VirtualFreeEx(processHandle, address, IntPtr.Zero, 0x8000);
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing command: {ex.Message}");
                VirtualFreeEx(processHandle, address, IntPtr.Zero, 0x8000);
                return 0;
            }
        }

        #endregion

    }
}

