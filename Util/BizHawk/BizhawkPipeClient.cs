using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.BizHawk
{
    internal class BizhawkPipeClient : IDisposable
    {
        private const string PipeName = "archipelago-bizhawk-comms";

        private NamedPipeClientStream? _pipe;
        private readonly object _lock = new();

        public bool IsConnected => _pipe?.IsConnected ?? false;

        public void Connect(int timeoutMs = 5000)
        {
            _pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.None);
            _pipe.Connect(timeoutMs); // throws TimeoutException if the tool isn't listening — fail fast by design
        }

        public bool Connect(string domainName, int timeoutMs = 5000)
        {
            Connect(timeoutMs);
            return SetDomain(domainName);
        }

        public bool SetDomain(string domainName)
        {
            var response = SendRequest(new MemoryRequest { Op = MemoryOpType.SetDomain, DomainName = domainName });
            if (!response.Success)
                throw new InvalidOperationException($"Failed to select domain '{domainName}': {response.Error}");
            return true;
        }
        public void Disconnect()
        {
            _pipe?.Dispose();
            _pipe = null;
        }
        public string[] ListDomains()
        {
            var response = SendRequest(new MemoryRequest { Op = MemoryOpType.ListDomains });
            if (!response.Success)
                throw new IOException(response.Error ?? "ListDomains failed");
            return response.Domains ?? Array.Empty<string>();
        }

        public byte[] ReadBytes(ulong address, int length)
        {
            var response = SendRequest(new MemoryRequest
            {
                Op = MemoryOpType.ReadBytes,
                Address = checked((long)address),
                Length = length
            });

            if (!response.Success)
                throw new IOException(response.Error ?? "ReadBytes failed");

            return response.Data ?? Array.Empty<byte>();
        }

        public bool WriteBytes(ulong address, byte[] data)
        {
            var response = SendRequest(new MemoryRequest
            {
                Op = MemoryOpType.WriteBytes,
                Address = checked((long)address),
                Data = data
            });

            return response.Success;
        }
        private MemoryResponse SendRequest(MemoryRequest request)
        {
            if (_pipe is null || !_pipe.IsConnected)
                throw new InvalidOperationException("Not connected — call Connect() first.");

            lock (_lock)
            {
                using var payloadStream = new MemoryStream();
                using (var writer = new BinaryWriter(payloadStream, Encoding.UTF8, leaveOpen: true))
                {
                    WriteRequest(writer, request);
                }
                var payload = payloadStream.ToArray();

                _pipe.Write(BitConverter.GetBytes(payload.Length), 0, 4);
                _pipe.Write(payload, 0, payload.Length);
                _pipe.Flush();

                var lengthBuf = new byte[4];
                ReadExact(_pipe, lengthBuf);
                int responseLength = BitConverter.ToInt32(lengthBuf, 0);

                var responseBuf = new byte[responseLength];
                ReadExact(_pipe, responseBuf);

                using var reader = new BinaryReader(new MemoryStream(responseBuf));
                return ReadResponse(reader);
            }
        }

        private static void ReadExact(Stream stream, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = stream.Read(buffer, offset, buffer.Length - offset);
                if (read == 0) throw new IOException("Pipe closed mid-message.");
                offset += read;
            }
        }

        // Mirrors the tool's ReadRequest field-for-field — order matters, there's no framing to enforce it.
        private static void WriteRequest(BinaryWriter w, MemoryRequest r)
        {
            w.Write((byte)r.Op);
            w.Write(r.Address);
            w.Write(r.Length);
            var domainBytes = Encoding.UTF8.GetBytes(r.DomainName ?? "");
            w.Write(domainBytes.Length);
            w.Write(domainBytes);
            var data = r.Data ?? Array.Empty<byte>();
            w.Write(data.Length);
            w.Write(data);
        }

        // Mirrors the tool's WriteResponse field-for-field.
        private static MemoryResponse ReadResponse(BinaryReader r)
        {
            bool success = r.ReadBoolean();

            int errorLen = r.ReadInt32();
            string? error = errorLen > 0 ? Encoding.UTF8.GetString(r.ReadBytes(errorLen)) : null;

            int dataLen = r.ReadInt32();
            byte[]? data = dataLen > 0 ? r.ReadBytes(dataLen) : null;

            int domainCount = r.ReadInt32();
            string[]? domains = null;
            if (domainCount > 0)
            {
                domains = new string[domainCount];
                for (int i = 0; i < domainCount; i++)
                {
                    int len = r.ReadInt32();
                    domains[i] = Encoding.UTF8.GetString(r.ReadBytes(len));
                }
            }

            return new MemoryResponse { Success = success, Error = error, Data = data, Domains = domains };
        }

        public void Dispose() => Disconnect();
    }
}

