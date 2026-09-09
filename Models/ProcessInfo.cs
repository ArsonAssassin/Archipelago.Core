namespace Archipelago.Core.Models
{
    public class ProcessInfo
    {
        public int PID { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string WindowTitle { get; set; } = string.Empty;

        public ProcessInfo() { }

        public ProcessInfo(int pid, string processName, string windowTitle)
        {
            PID = pid;
            ProcessName = processName;
            WindowTitle = windowTitle;
        }

        public override string ToString()
        {
            return string.IsNullOrEmpty(WindowTitle)
                ? $"{ProcessName} (PID: {PID})"
                : $"{ProcessName} - {WindowTitle} (PID: {PID})";
        }
    }
}
