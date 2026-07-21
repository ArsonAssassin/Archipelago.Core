using Archipelago.Core.Models;
using Archipelago.MultiClient.Net;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public interface ILocationManager
    {
        event EventHandler<LocationCompletedEventArgs>? LocationCompleted;
        Func<bool>? EnableLocationsCondition { get; set; }

        void AddLocation(ILocation location);
        void RemoveLocation(ILocation location);
        Task MonitorLocationsAsync(ArchipelagoSession currentSession, List<ILocation> locations, CancellationToken cancellationToken = default);
        void CancelMonitors();
    }
}
