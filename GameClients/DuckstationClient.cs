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
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ProcessName = "duckstation";
                ProcId = Memory.GetProcFromIdFromPartial(ProcessName);
            }
            else
            {
                ProcessName = "duckstation-qt-x64-ReleaseLTCG";
                ProcId = Memory.GetProcIdFromExe(ProcessName);
            }
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
