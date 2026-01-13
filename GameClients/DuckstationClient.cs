using Archipelago.Core;
using Archipelago.Core.Util;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.GameClients
{
    public class DuckstationClient : IGameClient
    {
        public DuckstationClient()
        {
            ProcessName = "duckstation";
            ProcId = Memory.GetProcessID(ProcessName);
        }
        public bool IsConnected { get; set; }
        public int ProcId { get; set; }
        public string ProcessName { get; set; }

        public bool Connect()
        {
            Log.Verbose($"Connecting to {ProcessName}");
            if (ProcId == 0)
            {
                Log.Error($"{ProcessName} not found.");
                return false;
            }
            return true;
        }
    }
}
