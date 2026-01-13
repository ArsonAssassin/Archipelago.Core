using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Archipelago.Core.Util.PlatformMemory;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util
{

    public class Memory
    {
        #region Platform Implementation
        internal static readonly IMemory PlatformImpl;
        private static nint _currentHandle;
        private static int _currentProcessId = 0;

        static Memory()
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
        #endregion

        #region Constants
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_OPERATION = 0x0008;
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
            return PlatformImpl.OpenProcess(PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME | PROCESS_VM_READ | PROCESS_VM_WRITE, false, proc);
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
        public static int GetProcFromIdFromPartial(string procPartialName)
        {
            Console.WriteLine($"Find Process ID {procPartialName}");
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

        #region Read Operations
        public static byte ReadByte(ulong address)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            byte[] buffer = new byte[1];
            PlatformImpl.ReadProcessMemory(CurrentHandle(), address + GlobalOffset, buffer, buffer.Length, out _);
            return buffer[0];
        }

        public static byte[] ReadByteArray(ulong address, int length)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            byte[] buffer = new byte[length];
            PlatformImpl.ReadProcessMemory(CurrentHandle(), address + GlobalOffset, buffer, buffer.Length, out _);
            return buffer;
        }
        public static T ReadStruct<T>(ulong address)
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size]; // Allocate the buffer
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                if (handle.Target == null)
                {
                    throw new NullReferenceException();
                }
                PlatformImpl.ReadProcessMemory(CurrentHandle(), address + GlobalOffset, buffer, size, out _);
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }
        public static List<T> ReadStructs<T>(ulong address, int numStructs)
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size * numStructs]; // Allocate the buffer
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned); // Pin the buffer
            List<T> structures = new List<T>();
            try
            {
                if (handle.Target == null)
                {
                    throw new NullReferenceException();
                }
                PlatformImpl.ReadProcessMemory(CurrentHandle(), address + GlobalOffset, buffer, numStructs * size, out _);
                IntPtr basePtr = handle.AddrOfPinnedObject();
                for (int i = 0; i < numStructs; i++)
                {
                    // Calculate the pointer for the current struct instance
                    IntPtr currentStructPtr = new IntPtr(basePtr.ToInt64() + (long)i * size);
                    // Unmarshal the struct from the calculated pointer
                    T structure = (T)Marshal.PtrToStructure(currentStructPtr, typeof(T));
                    structures.Add(structure);
                }
            }
            finally
            {
                handle.Free();
            }
            return structures;
        }
        public static bool ReadBit(ulong address, int bitNumber, Endianness endianness = Endianness.Little)
        {
            if (bitNumber < 0 || bitNumber > 7)
                throw new ArgumentOutOfRangeException(nameof(bitNumber), "Bit number must be between 0-7");

            byte b = ReadByte(address);

            if (endianness == Endianness.Big)
            {
                bitNumber = 7 - bitNumber;
            }

            return (b & (1 << bitNumber)) != 0;
        }

        public static ushort ReadUShort(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(ushort));
            return BitConverter.ToUInt16(HandleEndianness(buffer, endianness), 0);
        }

        public static short ReadShort(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(short));
            return BitConverter.ToInt16(HandleEndianness(buffer, endianness), 0);
        }

        public static uint ReadUInt(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(uint));
            return BitConverter.ToUInt32(HandleEndianness(buffer, endianness), 0);
        }

        public static int ReadInt(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(int));
            return BitConverter.ToInt32(HandleEndianness(buffer, endianness), 0);
        }

        public static long ReadLong(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(long));
            return BitConverter.ToInt64(HandleEndianness(buffer, endianness), 0);
        }

        public static ulong ReadULong(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(ulong));
            return BitConverter.ToUInt64(HandleEndianness(buffer, endianness), 0);
        }

        public static float ReadFloat(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(float));
            return BitConverter.ToSingle(HandleEndianness(buffer, endianness), 0);
        }

        public static double ReadDouble(ulong address, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = ReadByteArray(address, sizeof(double));
            return BitConverter.ToDouble(HandleEndianness(buffer, endianness), 0);
        }

        public static string ReadString(ulong address, int length, Endianness endianness = Endianness.Little, Encoding encoding = null)
        {
            byte[] dataBuffer = ReadByteArray(address, length);
            encoding ??= Encoding.UTF8;
            return encoding.GetString(dataBuffer);
        }

        public static T ReadObject<T>(ulong baseAddress, Endianness endianness = Endianness.Little) where T : class, new()
        {
            var type = typeof(T);
            var classOffset = type.GetCustomAttribute<MemoryOffsetAttribute>()?.Offset ?? 0;
            return (T)ReadObjectInternal(type, baseAddress + classOffset, endianness);
        }

        internal static object ReadObjectInternal(Type type, ulong baseAddress, Endianness endianness)
        {
            var result = Activator.CreateInstance(type);
            var properties = type.GetProperties()
                .Where(p => p.GetCustomAttribute<MemoryOffsetAttribute>() != null)
                .ToList();

            if (properties.Count == 0)
            {
                throw new ArgumentException($"Type {type.Name} must have at least one property decorated with {nameof(MemoryOffsetAttribute)}");
            }

            foreach (var property in properties)
            {
                var attribute = property.GetCustomAttribute<MemoryOffsetAttribute>();
                var offset = attribute.Offset;
                var address = baseAddress + offset;

                if (property.PropertyType == typeof(byte[]))
                {
                    if (attribute.ByteArrayLength <= 0)
                    {
                        throw new ArgumentException($"Byte array property {property.Name} must specify a positive ByteArrayLength");
                    }
                    var byteArray = ReadByteArray(address, attribute.ByteArrayLength);
                    property.SetValue(result, byteArray);
                }
                else if (property.PropertyType.IsGenericType &&
                    (property.PropertyType.GetGenericTypeDefinition() == typeof(List<>) ||
                     property.PropertyType.GetGenericTypeDefinition() == typeof(IList<>) ||
                     property.PropertyType.GetGenericTypeDefinition() == typeof(ICollection<>)))
                {
                    if (attribute.CollectionLength <= 0)
                    {
                        throw new ArgumentException($"Collection property {property.Name} must specify a positive CollectionLength");
                    }

                    var elementType = property.PropertyType.GetGenericArguments()[0];
                    var listType = typeof(List<>).MakeGenericType(elementType);
                    var list = (System.Collections.IList)Activator.CreateInstance(listType);

                    var elementSize = GetElementSize(elementType);

                    for (int i = 0; i < attribute.CollectionLength; i++)
                    {
                        var elementAddress = address + (ulong)(i * elementSize);
                        if (!IsBuiltInType(elementType))
                        {
                            var element = ReadObjectInternal(elementType, elementAddress, endianness);
                            list.Add(element);
                        }
                        else
                        {
                            var element = ReadPropertyValue(elementAddress, property, endianness);
                            list.Add(element);
                        }
                    }

                    property.SetValue(result, list);
                }
                else if (property.PropertyType.IsEnum)
                {
                    var underlyingType = Enum.GetUnderlyingType(property.PropertyType);
                    object rawValue = ReadPropertyValue(address, property, endianness, underlyingType);
                    var enumValue = Enum.ToObject(property.PropertyType, rawValue);
                    property.SetValue(result, enumValue);
                }
                else if (!IsBuiltInType(property.PropertyType))
                {
                    var nestedObject = ReadObjectInternal(property.PropertyType, address, endianness);
                    property.SetValue(result, nestedObject);
                }
                else
                {
                    var value = ReadPropertyValue(address, property, endianness);
                    property.SetValue(result, value);
                }
            }

            return result;
        }
        public static T Read<T>(ulong address, Endianness endianness) where T : struct
        {
            object result = typeof(T) switch
            {
                Type t when t == typeof(byte) => ReadByte(address),
                Type t when t == typeof(short) => ReadShort(address, endianness),
                Type t when t == typeof(ushort) => ReadUShort(address, endianness),
                Type t when t == typeof(int) => ReadInt(address, endianness),
                Type t when t == typeof(uint) => ReadUInt(address, endianness),
                Type t when t == typeof(long) => ReadLong(address, endianness),
                Type t when t == typeof(ulong) => ReadULong(address, endianness),
                Type t when t == typeof(float) => ReadFloat(address, endianness),
                Type t when t == typeof(double) => ReadDouble(address, endianness),
                Type t when t == typeof(bool) => ReadBit(address, 0, endianness),
                Type t when t == typeof(string) => throw new NotSupportedException("Cannot Read type string with Read<T>, use ReadString instead"),
                _ => throw new NotSupportedException($"Type {typeof(T).Name} is not supported for memory reading")
            };

            return (T)result;
        }
        private static object ReadPropertyValue(ulong address, PropertyInfo property, Endianness endianness, Type enumType = null)
        {
            var propertyType = enumType != null ? enumType : property.PropertyType;
            var attribute = property.GetCustomAttribute<MemoryOffsetAttribute>();

            if (propertyType == typeof(string))
            {
                return ReadString(address, attribute.StringLength, endianness);
            }
            else if (propertyType == typeof(byte))
            {
                return ReadByte(address);
            }
            else if (propertyType == typeof(short))
            {
                return ReadShort(address, endianness);
            }
            else if (propertyType == typeof(ushort))
            {
                return ReadUShort(address, endianness);
            }
            else if (propertyType == typeof(int))
            {
                return ReadInt(address, endianness);
            }
            else if (propertyType == typeof(uint))
            {
                return ReadUInt(address, endianness);
            }
            else if (propertyType == typeof(long))
            {
                return ReadLong(address, endianness);
            }
            else if (propertyType == typeof(ulong))
            {
                return ReadULong(address, endianness);
            }
            else if (propertyType == typeof(float))
            {
                return ReadFloat(address, endianness);
            }
            else if (propertyType == typeof(double))
            {
                return ReadDouble(address, endianness);
            }
            else if (propertyType == typeof(bool))
            {
                return ReadBit(address, 0, endianness);
            }

            throw new NotSupportedException($"Type {propertyType.Name} is not supported for memory reading");
        }
        #endregion

        #region Write Operations
        public static bool Write(ulong address, byte[] value)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            return PlatformImpl.WriteProcessMemory(CurrentHandle(), address + GlobalOffset, value, value.Length, out _);
        }

        public static bool WriteString(ulong address, string value, Endianness endianness = Endianness.Little, Encoding encoding = null)
        {
            encoding ??= Encoding.UTF8;
            byte[] bytes = encoding.GetBytes(value);
            WriteByteArray(address, bytes, endianness);
            return true;
        }

        public static bool WriteByte(ulong address, byte value)
        {
            return Write(address, new[] { value });
        }

        public static void WriteByteArray(ulong address, byte[] data, Endianness endianness = Endianness.Little)
        {
            if (endianness == Endianness.Big && BitConverter.IsLittleEndian ||
                endianness == Endianness.Little && !BitConverter.IsLittleEndian)
            {
                data = data.ToArray(); // Create a copy before reversing
                Array.Reverse(data);
            }
            Write(address, data);
        }

        public static bool Write(ulong address, ushort value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, short value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, uint value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, int value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, float value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, double value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, long value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool Write(ulong address, ulong value, Endianness endianness = Endianness.Little)
        {
            byte[] buffer = HandleEndianness(BitConverter.GetBytes(value), endianness);
            return Write(address, buffer);
        }

        public static bool WriteBit(ulong address, int bitNumber, bool value, Endianness endianness = Endianness.Little)
        {
            if (bitNumber < 0 || bitNumber > 7)
                throw new ArgumentOutOfRangeException(nameof(bitNumber), "Bit number must be between 0-7");

            if (endianness == Endianness.Big)
            {
                bitNumber = 7 - bitNumber;
            }

            byte currentByte = ReadByte(address);

            if (value)
                currentByte = (byte)(currentByte | (1 << bitNumber));
            else
                currentByte = (byte)(currentByte & ~(1 << bitNumber));

            return WriteByte(address, currentByte);
        }

        public static bool WriteObject<T>(ulong baseAddress, T obj, Endianness endianness = Endianness.Little) where T : class
        {
            var type = typeof(T);
            var classOffset = type.GetCustomAttribute<MemoryOffsetAttribute>()?.Offset ?? 0;
            return WriteObjectInternal(type, baseAddress + classOffset, obj, endianness);
        }

        private static bool WriteObjectInternal(Type type, ulong baseAddress, object obj, Endianness endianness)
        {
            var properties = type.GetProperties()
                .Where(p => p.GetCustomAttribute<MemoryOffsetAttribute>() != null)
                .ToList();

            if (properties.Count == 0)
            {
                throw new ArgumentException($"Type {type.Name} must have at least one property decorated with {nameof(MemoryOffsetAttribute)}");
            }

            bool success = true;
            foreach (var property in properties)
            {
                var offset = property.GetCustomAttribute<MemoryOffsetAttribute>().Offset;
                var address = baseAddress + offset;

                var value = property.GetValue(obj);
                if (value == null) continue;

                if (property.PropertyType.IsGenericType &&
                    (property.PropertyType.GetGenericTypeDefinition() == typeof(List<>) ||
                     property.PropertyType.GetGenericTypeDefinition() == typeof(IList<>) ||
                     property.PropertyType.GetGenericTypeDefinition() == typeof(ICollection<>)))
                {
                    var list = (System.Collections.IList)value;
                    var elementType = property.PropertyType.GetGenericArguments()[0];
                    var elementSize = GetElementSize(elementType);

                    for (int i = 0; i < list.Count; i++)
                    {
                        var elementAddress = address + (ulong)(i * elementSize);
                        if (!IsBuiltInType(elementType))
                        {
                            success &= WriteObjectInternal(elementType, elementAddress, list[i], endianness);
                        }
                        else
                        {
                            success &= WritePropertyValue(elementAddress, property, list[i], endianness);
                        }
                    }
                }
                else if (!IsBuiltInType(property.PropertyType))
                {
                    success &= WriteObjectInternal(property.PropertyType, address, value, endianness);
                }
                else
                {
                    success &= WritePropertyValue(address, property, value, endianness);
                }
            }

            return success;
        }
        private static bool WritePropertyValue(ulong address, PropertyInfo property, object value, Endianness endianness)
        {
            if (value == null) return true;

            var propertyType = property.PropertyType;
            var attribute = property.GetCustomAttribute<MemoryOffsetAttribute>();

            if (propertyType == typeof(string))
            {
                return WriteString(address, (string)value, endianness);
            }
            else if (propertyType == typeof(byte))
            {
                return WriteByte(address, (byte)value);
            }
            else if (propertyType == typeof(short))
            {
                return Write(address, (short)value, endianness);
            }
            else if (propertyType == typeof(ushort))
            {
                return Write(address, (ushort)value, endianness);
            }
            else if (propertyType == typeof(int))
            {
                return Write(address, (int)value, endianness);
            }
            else if (propertyType == typeof(uint))
            {
                return Write(address, (uint)value, endianness);
            }
            else if (propertyType == typeof(long))
            {
                return Write(address, (long)value, endianness);
            }
            else if (propertyType == typeof(ulong))
            {
                return Write(address, (ulong)value, endianness);
            }
            else if (propertyType == typeof(float))
            {
                return Write(address, (float)value, endianness);
            }
            else if (propertyType == typeof(double))
            {
                return Write(address, (double)value, endianness);
            }
            else if (propertyType == typeof(bool))
            {
                return WriteBit(address, 0, (bool)value, endianness);
            }

            throw new NotSupportedException($"Type {propertyType.Name} is not supported for memory writing");
        }
        public static void WriteStruct<T>(ulong address, T str)
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(str, ptr, true);
                Marshal.Copy(ptr, buffer, 0, size);
                PlatformImpl.WriteProcessMemory(CurrentHandle(), address + GlobalOffset, buffer, size, out _);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
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

        #region Pattern Scanning
        public static IntPtr FindSignature(IntPtr start, int size, byte[] pattern, string mask)
        {
            if (CurrentProcId == 0) throw new ArgumentException("CurrentProcId has not been set");
            byte[] buffer = new byte[size];

            PlatformImpl.ReadProcessMemory(CurrentHandle(), (ulong)start, buffer, size, out var bytesRead);

            for (int i = 0; i < size - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (mask[j] != '?' && buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return start + i;
            }

            return IntPtr.Zero;
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
        #endregion

        #region Utilities
        public static byte[] ReadFromPointer(ulong ptrAddress, int length, int depth)
        {
            var next = ReadByteArray(ptrAddress, length);
            if (--depth == 0)
                return next;
            return ReadFromPointer(BitConverter.ToUInt32(next), length, depth);
        }
        public static Task MonitorAddressForAction<T>(ulong address, Action action, Func<T, bool> criteria)
        {
            int size = GetElementSize(typeof(T));
            var initialValue = ConvertByteArrayToT<T>(Memory.ReadByteArray(address, size));
            return Task.Run(async () =>
            {
                var value = initialValue;
                while (!criteria(value))
                {
                    value = ConvertByteArrayToT<T>(Memory.ReadByteArray(address, size));
                    await Task.Delay(10);
                }
                action();
            });
        }
        public static Task MonitorAddressBitForAction(ulong address, int bitNum, Action action)
        {
            var initialValue = ReadBit(address, bitNum);
            return Task.Run(async () =>
            {
                var value = initialValue;
                while (!value)
                {
                    value = ReadBit(address, bitNum);
                    await Task.Delay(10);
                }
                action();
            });
        }
        public static Task MonitorAddressByteChangeForAction(ulong address, int readyTriggerVal, int triggerActionVal, Action action)
        {
            return Task.Run(async () =>
            {
                int lastVal = ReadByte(address);
                while (true)
                {
                    int value = ReadByte(address);
                    if (lastVal == readyTriggerVal && value == triggerActionVal)
                    {
                        action();
                    }
                    lastVal = value;
                    await Task.Delay(10);
                }
            });
        }
        private static bool IsBuiltInType(Type type)
        {
            return type.IsPrimitive || type == typeof(string) || type == typeof(decimal);
        }
        private static byte[] HandleEndianness(byte[] data, Endianness endianness)
        {
            if (endianness == Endianness.Big && BitConverter.IsLittleEndian ||
                endianness == Endianness.Little && !BitConverter.IsLittleEndian)
            {
                Array.Reverse(data);
            }
            return data;
        }
        private static T ConvertByteArrayToT<T>(byte[] bytes)
        {
            if (typeof(T) == typeof(byte)) return (T)(object)bytes[0];
            if (typeof(T) == typeof(short)) return (T)(object)BitConverter.ToInt16(bytes, 0);
            if (typeof(T) == typeof(ushort)) return (T)(object)BitConverter.ToUInt16(bytes, 0);
            if (typeof(T) == typeof(int)) return (T)(object)BitConverter.ToInt32(bytes, 0);
            if (typeof(T) == typeof(uint)) return (T)(object)BitConverter.ToUInt32(bytes, 0);
            if (typeof(T) == typeof(long)) return (T)(object)BitConverter.ToInt64(bytes, 0);
            if (typeof(T) == typeof(ulong)) return (T)(object)BitConverter.ToUInt64(bytes, 0);
            if (typeof(T) == typeof(float)) return (T)(object)BitConverter.ToSingle(bytes, 0);
            if (typeof(T) == typeof(double)) return (T)(object)BitConverter.ToDouble(bytes, 0);

            // For other types, you might need to use a more complex deserialization method
            throw new NotSupportedException($"Type {typeof(T)} is not supported for conversion from byte array.");
        }
        private static int GetElementSize(Type type)
        {
            if (type == typeof(byte)) return 1;
            if (type == typeof(short) || type == typeof(ushort)) return 2;
            if (type == typeof(int) || type == typeof(uint) || type == typeof(float)) return 4;
            if (type == typeof(long) || type == typeof(ulong) || type == typeof(double)) return 8;

            // For complex types, get size by checking their properties' offsets and sizes
            var properties = type.GetProperties()
                .Where(p => p.GetCustomAttribute<MemoryOffsetAttribute>() != null)
                .ToList();

            if (properties.Count == 0) return 0;

            var lastProperty = properties.OrderByDescending(p =>
            {
                var attr = p.GetCustomAttribute<MemoryOffsetAttribute>();
                return attr.Offset + GetElementSize(p.PropertyType) * Math.Max(1, attr.CollectionLength);
            }).First();

            var lastAttr = lastProperty.GetCustomAttribute<MemoryOffsetAttribute>();
            return (int)(lastAttr.Offset + GetElementSize(lastProperty.PropertyType) * Math.Max(1, lastAttr.CollectionLength));
        }
        #endregion
    }
}
