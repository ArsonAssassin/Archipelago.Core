using Archipelago.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util
{
    public static class Helpers
    {

        public static ILocation DeepClone(this ILocation location)
        {
            return location switch
            {
                Location loc => new Location
                {
                    Id = loc.Id,
                    Name = loc.Name,
                    Category = loc.Category,
                    Address = loc.Address,
                    AddressBit = loc.AddressBit,
                    NibblePosition = loc.NibblePosition,
                    CheckType = loc.CheckType,
                    CheckValue = loc.CheckValue,
                    CompareType = loc.CompareType,
                    RangeStartValue = loc.RangeStartValue,
                    RangeEndValue = loc.RangeEndValue
                },
                CompositeLocation comp => new CompositeLocation
                {
                    Id = comp.Id,
                    Name = comp.Name,
                    Category = comp.Category,
                    CheckType = comp.CheckType,
                    Conditions = comp.Conditions?.Select(c => c.DeepClone()).ToList() ?? new List<ILocation>()
                },
                _ => throw new NotSupportedException($"Unknown location type: {location.GetType()}")
            };
        }

        public static T Random<T>(this IEnumerable<T> list) where T : struct
        {
            return list.ToList()[new Random().Next(0, list.Count())];
        }
        public static string OpenEmbeddedResource(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using Stream stream = assembly.GetManifestResourceStream(resourceName);
            using StreamReader reader = new StreamReader(stream);
            string jsonFile = reader.ReadToEnd();
            return jsonFile;
        }

        public static bool CheckLocation(Location location)
        {
            switch (location.CheckType)
            {
                case (LocationCheckType.Bit):
                    var currentAddressValue = Memory.ReadByte(location.Address);
                    bool currentBitValue = GetBitValue(currentAddressValue, location.AddressBit);
                    if (string.IsNullOrWhiteSpace(location.CheckValue))
                    {
                        return currentBitValue;
                    }
                    else { return !currentBitValue; }
                case (LocationCheckType.Int):
                    var currentIntValue = Memory.ReadInt(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentIntValue == Convert.ToInt32(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentIntValue > Convert.ToInt32(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentIntValue < Convert.ToInt32(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentIntValue <= Convert.ToInt32(location.RangeEndValue) && currentIntValue >= Convert.ToInt32(location.RangeStartValue));
                    }
                    break;
                case (LocationCheckType.UInt):
                    var currentUIntValue = Memory.ReadUInt(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentUIntValue == Convert.ToUInt32(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentUIntValue > Convert.ToUInt32(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentUIntValue < Convert.ToUInt32(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentUIntValue <= Convert.ToUInt32(location.RangeEndValue) && currentUIntValue >= Convert.ToUInt32(location.RangeStartValue));
                    }
                    break;
                case (LocationCheckType.Byte):
                    var currentByteValue = Memory.ReadByte(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentByteValue == Convert.ToByte(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentByteValue > Convert.ToByte(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentByteValue < Convert.ToByte(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentByteValue <= Convert.ToByte(location.RangeEndValue) && currentByteValue >= Convert.ToByte(location.RangeStartValue));
                    }
                    break;
                case (LocationCheckType.FalseBit):
                    var currentAddressValue2 = Memory.ReadByte(location.Address);
                    bool currentBitValue2 = !GetBitValue(currentAddressValue2, location.AddressBit);
                    if (string.IsNullOrWhiteSpace(location.CheckValue))
                    {
                        return currentBitValue2;
                    }
                    else { return !currentBitValue2; }
                case (LocationCheckType.Short):
                    var currentShortValue = Memory.ReadShort(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentShortValue == Convert.ToInt16(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentShortValue > Convert.ToInt16(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentShortValue < Convert.ToInt16(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentShortValue <= Convert.ToInt16(location.RangeEndValue) && currentShortValue >= Convert.ToInt16(location.RangeStartValue));
                    }
                    break;
                case (LocationCheckType.UShort):
                    var currentUShortValue = Memory.ReadUShort(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentUShortValue == Convert.ToUInt16(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentUShortValue > Convert.ToUInt16(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentUShortValue < Convert.ToUInt16(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentUShortValue <= Convert.ToUInt16(location.RangeEndValue) && currentUShortValue >= Convert.ToUInt16(location.RangeStartValue));
                    }
                    break;
                case (LocationCheckType.Long):
                    var currentLongValue = Memory.ReadLong(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentLongValue == Convert.ToInt64(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentLongValue > Convert.ToInt64(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentLongValue < Convert.ToInt64(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentLongValue <= Convert.ToInt64(location.RangeEndValue) && currentLongValue >= Convert.ToInt64(location.RangeStartValue));
                    }
                    break;

                case (LocationCheckType.ULong):
                    var currentULongValue = Memory.ReadULong(location.Address);
                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return currentULongValue == Convert.ToUInt64(location.CheckValue);

                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return currentULongValue > Convert.ToUInt64(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return currentULongValue < Convert.ToUInt64(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (currentULongValue <= Convert.ToUInt64(location.RangeEndValue) && currentULongValue >= Convert.ToUInt64(location.RangeStartValue));
                    }
                    break;
                case (LocationCheckType.Nibble):
                    var currentNibbleValue = Memory.ReadByte(location.Address);
                    byte nibbleValue;

                    if (location.NibblePosition == NibblePosition.Upper)
                    {
                        nibbleValue = (byte)((currentNibbleValue >> 4) & 0x0F);
                    }
                    else
                    {
                        nibbleValue = (byte)(currentNibbleValue & 0x0F);
                    }

                    if (location.CompareType == LocationCheckCompareType.Match)
                    {
                        return nibbleValue == Convert.ToByte(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.GreaterThan)
                    {
                        return nibbleValue > Convert.ToByte(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.LessThan)
                    {
                        return nibbleValue < Convert.ToByte(location.CheckValue);
                    }
                    else if (location.CompareType == LocationCheckCompareType.Range)
                    {
                        if (string.IsNullOrWhiteSpace(location.RangeEndValue)) throw new ArgumentException("RangeEndValue must be provided for location check type Range");
                        if (string.IsNullOrWhiteSpace(location.RangeStartValue)) throw new ArgumentException("RangeStartValue must be provided for location check type Range");
                        return (nibbleValue <= Convert.ToByte(location.RangeEndValue) && nibbleValue >= Convert.ToByte(location.RangeStartValue));
                    }
                    break;
                default:
                    return false;
            }
            return false;

        }
        public static ulong ResolvePointer(ulong address, params ulong[] offsets)
        {
            var currentAddress = address;
            for (int i = 0; i < offsets.Length - 1; i++)
            {
                currentAddress = currentAddress + offsets[i];
                currentAddress = Memory.ReadULong(currentAddress);
            }
            if (offsets.Length > 0)
            {
                currentAddress = currentAddress + offsets[offsets.Length - 1];
            }
            return currentAddress;
        }
        public static T ResolvePointer<T>(ulong address, Endianness endianness = Endianness.Little, params ulong[] offsets) where T : struct
        {
            var lastAddress = ResolvePointer(address, offsets);
            return Memory.Read<T>(lastAddress, endianness);
        }
        private static bool GetBitValue(byte value, int bitIndex)
        {
            return (value & (1 << bitIndex)) != 0;
        }
        public static byte[] IntToLittleEndianBytes(int value, int numBytes = 4)
        {
            if (numBytes < 1 || numBytes > 4)
            {
                throw new ArgumentOutOfRangeException(nameof(numBytes), "Number of bytes must be between 1 and 4.");
            }

            byte[] bytes = new byte[numBytes];
            for (int i = 0; i < numBytes; i++)
            {
                bytes[i] = (byte)(value >> (i * 8));
            }

            return bytes;
        }
        public static byte IntToLittleEndianByte(int value)
        {

            return (byte)(value >> (0 * 8));
        }
    }
}
