using Archipelago.Core.Models;
using Archipelago.MultiClient.Net;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class LocationManager
    {
        private GameStateManager _gameStateManager;
        public event EventHandler<LocationCompletedEventArgs>? LocationCompleted;
        public Func<bool>? EnableLocationsCondition;
        private CancellationTokenSource _monitorToken { get; set; } = new CancellationTokenSource();
        private List<ILocation> _monitoredLocations { get; set; } = new List<ILocation>();

        private Channel<ILocation> _locationsChannel;
        private List<Task> _workerTasks = new List<Task>();
        private const int WORKER_COUNT = 8;
        private const int BATCH_SIZE = 25;
        public LocationManager(ref GameStateManager gameStateManager)
        {
            _gameStateManager = gameStateManager;
        }
        public void AddLocation(ILocation location)
        {

            if (!_monitoredLocations.Any(x => x.Id == location.Id))
            {
                _monitoredLocations.Add(location);

                if (_locationsChannel != null)
                {
                    _locationsChannel.Writer.TryWrite(location);
                }
            }

        }
        public void RemoveLocation(ILocation location)
        {
            var confirmedLocation = _monitoredLocations.SingleOrDefault(x => x.Id == location.Id);
            if (confirmedLocation != null)
            {
                Log.Verbose($"Location {location.Id} - {location.Name} removed from tracking");
                _monitoredLocations.Remove(confirmedLocation);
            }
            else
            {
                Log.Warning($"Could not remove location {location.Id} - {location.Name} because it was not found in the list, or was found multiple times.");
            }

        }
        public async Task MonitorLocationsAsync(ArchipelagoSession currentSession, List<ILocation> locations, CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.CombineTokens(cancellationToken);
            _locationsChannel = Channel.CreateUnbounded<ILocation>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });

            _monitoredLocations = locations;    

            foreach (var location in locations)
            {
                await _locationsChannel.Writer.WriteAsync(location, _monitorToken.Token);
            }

            await StartMonitoringAsync(currentSession);
        }
        private async Task StartMonitoringAsync(ArchipelagoSession currentSession)
        {
            _workerTasks.Clear();

            for (int i = 0; i < WORKER_COUNT; i++)
            {
                var workerId = i;
                var task = Task.Run(async () => await ProcessLocationWorkerAsync(currentSession, workerId), _monitorToken.Token);
                _workerTasks.Add(task);
            }

            try
            {
                await Task.WhenAll(_workerTasks);
            }
            catch (OperationCanceledException)
            {
                Log.Debug("Location monitoring cancelled");
            }
        }
        private async Task ProcessLocationWorkerAsync(ArchipelagoSession currentSession, int workerId)
        {
            var reader = _locationsChannel.Reader;
            var recheckQueue = new Queue<ILocation>();

            Log.Verbose($"Worker {workerId} started");

            while (!_monitorToken.IsCancellationRequested)
            {
                try
                {
                    var batchChecked = 0;

                    while (batchChecked < BATCH_SIZE && reader.TryRead(out var location))
                    {
                        if (_monitorToken.IsCancellationRequested) break;

                        if (EnableLocationsCondition?.Invoke() ?? true)
                        {
                            try
                            {
                                if (location.Check())
                                {
                                    await SendLocationAsync(currentSession, location, _monitorToken.Token);
                                    Log.Verbose($"[Worker {workerId}] {location.Name} ({location.Id}) Completed");
                                }
                                else
                                {
                                    recheckQueue.Enqueue(location);
                                }
                            }
                            catch (Exception ex)
                            {
                                Log.Error($"[Worker {workerId}] Error checking location {location.Id}: {ex.Message}");
                                recheckQueue.Enqueue(location);
                            }
                        }
                        else
                        {
                            recheckQueue.Enqueue(location);
                        }

                        batchChecked++;
                    }

                    while (recheckQueue.Count > 0)
                    {
                        var location = recheckQueue.Dequeue();
                        await _locationsChannel.Writer.WriteAsync(location, _monitorToken.Token);
                    }

                    await Task.Delay(50, _monitorToken.Token);
                }
                catch (OperationCanceledException)
                {
                    Log.Verbose($"Worker {workerId} cancelled");
                    break;
                }
                catch (Exception ex)
                {
                    Log.Error($"[Worker {workerId}] Unexpected error: {ex.Message}");
                    await Task.Delay(1000, _monitorToken.Token); // Back off on error
                }
            }

            Log.Debug($"Worker {workerId} stopped");
        }
        internal async Task SendLocationAsync(ArchipelagoSession currentSession, ILocation location, CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.CombineTokens(cancellationToken);
            if (currentSession == null)
            {
                Log.Error("Must be connected and logged in to send locations.");
                return;
            }
            if (!(EnableLocationsCondition?.Invoke() ?? true))
            {
                Log.Debug("Location precondition not met, location not sent");
                return;
            }
            Log.Debug($"Marking location {location.Id} as complete");
            if (currentSession.Locations.AllLocationsChecked.Contains(location.Id))
            {
                Log.Debug($"Skipping location {location.Name} - already completed.");
                return;
            }
            await currentSession.Locations.CompleteLocationChecksAsync([(long)location.Id]);

            LocationCompleted?.Invoke(this, new LocationCompletedEventArgs(location));
        }
        public void CancelMonitors()
        {
            try
            {
                _monitorToken?.Cancel();
                _locationsChannel?.Writer.Complete();
                if (_workerTasks.Any())
                {
                    Task.WaitAll(_workerTasks.ToArray(), TimeSpan.FromSeconds(5));
                }
                _monitorToken?.Dispose();
            }
            catch (Exception ex)
            {
                Log.Error($"Error cancelling monitors: {ex.Message}");
            }
        }
    }
}
