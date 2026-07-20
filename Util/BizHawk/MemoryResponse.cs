using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.BizHawk
{
    internal class MemoryResponse
    {
        public bool Success { get; set; }
        public byte[]? Data { get; set; }
        public string[]? Domains { get; set; }
        public string? Error { get; set; }
    }
}
