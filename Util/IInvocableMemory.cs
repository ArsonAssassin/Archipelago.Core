using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Archipelago.Core.Util.Enums;
using Archipelago.Core.Util.PlatformMemory;
using Serilog;

namespace Archipelago.Core.Util
{
    public interface IInvocableMemory : IMemory
    {
        bool ReadProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        bool WriteProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);
        IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        bool VirtualProtectEx(IntPtr processH, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
        bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);
        uint GetLastError();
        bool CloseHandle(IntPtr handle);
        int GetPID(string procName);
        List<int> GetPIDs(string procName);
        IntPtr GetModuleHandle(string moduleName);
        string GetLastErrorMessage();
        uint Execute(nint v, nint address, uint timeoutSeconds);
        uint ExecuteCommand(nint v, byte[] bytes, uint timeoutSeconds);
        MODULEINFO GetModuleInfo(IntPtr processHandle, string moduleName);
        IntPtr FindFreeRegionBelow4GB(IntPtr processHandle, uint size);

        nint GetModuleBaseAddress(int pid, string moduleName);
        nint GetExportAddress(int pid, nint moduleBase, string exportName);

        byte IMemory.ReadByte(ulong address)
        {
            byte[] buffer = new byte[1];
            bool success = ReadProcessMemory(PlatformMemory.PlatformMemory.CurrentHandle(), address, buffer, buffer.Length, out _);
            if (!success)
                Log.Logger.Warning("ReadByte failed at address 0x{Address:X}", address);
            return buffer[0];
        }

        byte[] IMemory.ReadByteArray(ulong address, int length)
        {
            byte[] buffer = new byte[length];
            bool success = ReadProcessMemory(PlatformMemory.PlatformMemory.CurrentHandle(), address, buffer, buffer.Length, out _);
            if (!success)
                Log.Logger.Warning("ReadByteArray failed at address 0x{Address:X} (length {Length})", address, length);
            return buffer;
        }

        bool IMemory.WriteByte(ulong address, byte value)
            => WriteProcessMemory(PlatformMemory.PlatformMemory.CurrentHandle(), address, new[] { value }, 1, out _);

        void IMemory.WriteByteArray(ulong address, byte[] data, Endianness endianness = Endianness.Little)
        {
            if (endianness == Endianness.Big && BitConverter.IsLittleEndian ||
                endianness == Endianness.Little && !BitConverter.IsLittleEndian)
            {
                data = (byte[])data.Clone();
                Array.Reverse(data);
            }
            bool success = WriteProcessMemory(PlatformMemory.PlatformMemory.CurrentHandle(), address, data, data.Length, out _);
            if (!success)
                Log.Logger.Warning("WriteByteArray failed at address 0x{Address:X} (length {Length})", address, data.Length);
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
    }
}
