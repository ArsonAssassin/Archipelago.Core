using Serilog.Events;

namespace Archipelago.Core.Util.Config
{
    public class LoggingConfig
    {
        public LogEventLevel LogLevel { get; set; } = LogEventLevel.Information;
    }
}
