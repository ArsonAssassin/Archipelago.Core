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

        public static IProcessPicker? ProcessPicker { get; set; }

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

        public async Task<bool> ConnectAsync()
        {
            // If already pinned to a specific PID, skip resolution
            if (_pinnedProcId != 0)
                return Connect();

            var processes = PlatformMemory.DiscoverProcesses(ProcessName);

            if (processes.Count == 1)
            {
                _pinnedProcId = processes[0].PID;
                return Connect();
            }

            // No picker registered → fall back to existing behavior
            if (ProcessPicker == null)
                return Connect();

            // 0 results → empty search field; multiple → prepopulate with exe name
            string searchText = processes.Count > 1 ? ProcessName : "";
            var selected = await ProcessPicker.PickProcessAsync(searchText);

            if (selected != null)
            {
                ProcessName = selected.ProcessName;
                _pinnedProcId = selected.PID;
            }

            return Connect();
        }
    }
}
