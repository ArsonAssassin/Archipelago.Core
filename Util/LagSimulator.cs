using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util
{
    internal class LagSimulator
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [Flags]
        public enum ThreadAccess : int
        {
            SUSPEND_RESUME = (0x0002)
        }

        private CancellationTokenSource cts;
        private Random random = new Random();

        public LagSimulator()
        {
        }

        public void Start(int minLagMs = 50, int maxLagMs = 200, int frequency = 5)
        {
            cts = new CancellationTokenSource();
            Task.Run(() => SimulateLag(minLagMs, maxLagMs, frequency, cts.Token));
        }

        public void Stop()
        {
            try
            {
                cts?.Cancel();
                ResumeProcess();
            }
            finally
            {
            }
        }

        private async Task SimulateLag(int minLagMs, int maxLagMs, int frequency, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                if (random.Next(100) < frequency)
                {
                    int lagDuration = random.Next(minLagMs, maxLagMs + 1);
                    SuspendProcess();
                    await Task.Delay(lagDuration, token);
                    ResumeProcess();
                }
                await Task.Delay(100, token); // Check every 100ms
            }
        }

        private void SuspendProcess()
        {
            foreach (ProcessThread thread in Memory.GetCurrentProcess().Threads)
            {
                IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (threadHandle != IntPtr.Zero)
                {
                    try
                    {
                        SuspendThread(threadHandle);
                    }
                    finally
                    {
                        CloseHandle(threadHandle);
                    }
                }
            }
        }

        private void ResumeProcess()
        {
            foreach (ProcessThread thread in Memory.GetCurrentProcess().Threads)
            {
                IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (threadHandle != IntPtr.Zero)
                {
                    try
                    {
                        ResumeThread(threadHandle);
                    }
                    finally
                    {
                        CloseHandle(threadHandle);
                    }
                }
            }
        }
    }
}
