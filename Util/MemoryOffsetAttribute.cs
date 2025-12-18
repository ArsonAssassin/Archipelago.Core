using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util
{
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Class)]
    public class MemoryOffsetAttribute : Attribute
    {
        public uint Offset { get; }
        public int StringLength { get; }
        public int CollectionLength { get; }
        public int BitPosition { get; }
        public int ByteArrayLength { get; }

        public MemoryOffsetAttribute(uint offset, int stringLength = 100, int collectionLength = 0, int bitPosition = -1, int byteArrayLength = 0)
        {
            Offset = offset;
            StringLength = stringLength;
            CollectionLength = collectionLength;
            BitPosition = bitPosition;
            ByteArrayLength = byteArrayLength;
        }
    }
}
