using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util
{
    public interface IMemory
    {
        abstract byte ReadByte(ulong address);
        abstract byte[] ReadByteArray(ulong address, int length);
        abstract bool WriteByte(ulong address, byte value);
        abstract void WriteByteArray(ulong address, byte[] data, Endianness endianness = Endianness.Little);

    }
}
