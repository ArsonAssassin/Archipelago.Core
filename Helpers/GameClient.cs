using Archipelago.Core.Util;
using Archipelago.Core.Util.PlatformMemory;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class GameClient : IGameClient
    {
        private int _pinnedProcId;

        public GameClient(string exeName)
        {
            ProcessName = exeName;
        }

        public GameClient(string exeName, int procId)
        {
            ProcessName = exeName;
            _pinnedProcId = procId;
        }

        public bool IsConnected { get; set; }

        public int ProcId
        {
            get
            {
                if (_pinnedProcId != 0)
                    return _pinnedProcId;
                return PlatformMemory.GetProcIdFromExe(ProcessName);
            }
            set
            {
                _pinnedProcId = value;
            }
        }

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
            else
            {
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    IsConnected = !proc.HasExited;
                    if (!IsConnected)
                    {
                        Log.Error($"{ProcessName} (PID {pid}) has exited.");
                    }
                }
                catch (ArgumentException)
                {
                    Log.Error($"{ProcessName} (PID {pid}) no longer exists.");
                    IsConnected = false;
                }
            }
            return IsConnected;
        }
    }
}
