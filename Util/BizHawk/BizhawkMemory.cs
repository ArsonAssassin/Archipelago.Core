using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.BizHawk
{
    public class BizhawkMemory : IMemory
    {
        private static readonly BizhawkPipeClient _pipeClient = new();

        public bool IsConnected => _pipeClient.IsConnected;

        /// <summary>Connect to the pipe without selecting a domain. Call ListDomains() then SetDomain() afterwards.</summary>
        public void Connect(int timeoutMs = 5000) => _pipeClient.Connect(timeoutMs);

        /// <summary>Connect to the pipe and immediately select the given memory domain.</summary>
        public bool Connect(string domainName, int timeoutMs = 5000) => _pipeClient.Connect(domainName, timeoutMs);

        /// <summary>Returns all memory domains available for the currently loaded ROM.</summary>
        public string[] ListDomains() => _pipeClient.ListDomains();

        /// <summary>Switch to a different memory domain after connecting.</summary>
        public bool SetDomain(string domainName) => _pipeClient.SetDomain(domainName);

        public void Disconnect() => _pipeClient.Disconnect();
        public byte ReadByte(ulong address)
        {
           return _pipeClient.ReadBytes(address, 1)[0];
        }

        public byte[] ReadByteArray(ulong address, int length)
        {
            return _pipeClient.ReadBytes(address, length);
        }

        public bool WriteByte(ulong address, byte value)
        {
            return _pipeClient.WriteBytes(address, new byte[] { value });
        }

        public void WriteByteArray(ulong address, byte[] data, Enums.Endianness endianness = Enums.Endianness.Little)
        {
            var bytesToWrite = endianness == Enums.Endianness.Big
             ? data.Reverse().ToArray()
             : data;

            _pipeClient.WriteBytes(address, bytesToWrite);
        }
    }
}
