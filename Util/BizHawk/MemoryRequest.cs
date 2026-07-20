using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.BizHawk
{
    internal class MemoryRequest
    {
        public MemoryOpType Op { get; set; }
        public string? DomainName { get; set; }  // null = default/main domain
        public long Address { get; set; }
        public int Length { get; set; }          // for ReadBytes
        public byte[]? Data { get; set; }        // for writes
    }
}
