using Archipelago.Core.Util;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class GameClient : IGameClient
    {
        public GameClient(string exeName)
        {
            ProcessName = exeName;
        }
        public bool IsConnected { get; set; }
        public int ProcId { get { return Memory.GetProcIdFromExe(ProcessName); } set { } }
        public string ProcessName { get; set; }

        public bool Connect()
        {
            Log.Verbose($"Connecting to {ProcessName}");
            var pid = ProcId;
            if (pid == 0)
            {
                Log.Error($"{ProcessName} not found.");
                IsConnected = false;
            }
            else IsConnected = true;
            return IsConnected;
        }
    }
}
