using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public interface IGameClient
    {
        public bool IsConnected { get; set; }
        public bool Connect();
        public Task<bool> ConnectAsync();
        public int ProcId { get; set; }
        public string ProcessName { get; set; }
    }
}
