using System;

namespace Archipelago.Core.Util.PlatformMemory
{
    public class ElevationRequiredException : UnauthorizedAccessException
    {
        public int TargetProcessId { get; }

        public ElevationRequiredException(int processId)
            : base($"Access denied opening process {processId}. Run as administrator to access this process.")
        {
            TargetProcessId = processId;
        }
    }
}
