using Archipelago.Core.Helpers;
using Archipelago.Core.Json;
using Archipelago.Core.Models;
using Archipelago.Core.Util;
using Archipelago.Core.Util.GPS;
using Archipelago.Core.Util.Overlay;
using Archipelago.Core.Util.PlatformLibrary;
using Archipelago.MultiClient.Net;
using Archipelago.MultiClient.Net.BounceFeatures.DeathLink;
using Archipelago.MultiClient.Net.Enums;
using Archipelago.MultiClient.Net.Helpers;
using Archipelago.MultiClient.Net.MessageLog.Messages;
using Archipelago.MultiClient.Net.Models;
using Archipelago.MultiClient.Net.Packets;
using Serilog;
using System.Collections.Concurrent;
using System.Drawing.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Color = Archipelago.Core.Util.Overlay.Color;

namespace Archipelago.Core
{
    public class ArchipelagoClient : IDisposable
    {
        private readonly Timer _gameClientPollTimer;
        private GameStateManager? _gameStateManager;
        private GPSStateManager? _gpsStateManager;
        public bool IsConnected { get; set; }
        public bool IsLoggedIn { get; set; }
        public event EventHandler<ItemReceivedEventArgs>? ItemReceived;
        public event EventHandler<ConnectionChangedEventArgs>? Disconnected;
        public event EventHandler<ConnectionChangedEventArgs>? Connected;
        public event EventHandler<MessageReceivedEventArgs>? MessageReceived;
        public event EventHandler<LocationCompletedEventArgs>? LocationCompleted;
        public event EventHandler? GameDisconnected;
        public Func<bool>? EnableLocationsCondition;
        public ItemsHandlingFlags? itemsFlags { get; set; }
        public int itemsReceivedCurrentSession { get; set; }
        public bool isReadyToReceiveItems { get; set; }
        public ArchipelagoSession CurrentSession { get; set; }
        private CancellationTokenSource _monitorToken { get; set; } = new CancellationTokenSource();
        private List<ILocation> _monitoredLocations { get; set; } = new List<ILocation>();

        private Channel<ILocation> _locationsChannel;
        private List<Task> _workerTasks = new List<Task>();
        private const int WORKER_COUNT = 8;
        public GPSHandler GPSHandler
        {
            get => _gpsStateManager?.Handler;
            set
            {
                if (_gpsStateManager != null)
                {
                    _gpsStateManager.Handler = value;
                }
            }
        }
        public GPSStateManager GpsStateManager { get { return _gpsStateManager; } }
        private string GameName { get; set; } = "";
        private string Seed { get; set; } = "";
        private Dictionary<string, object> _options = [];
        public Dictionary<string, object> Options { get { return _options; } }
        public ItemState ItemState => _gameStateManager?.CurrentItemState;
        public LocationState LocationState => _gameStateManager?.CurrentLocationState;
        public Dictionary<string, object> CustomValues => _gameStateManager?.CustomValues ?? new Dictionary<string, object>();

        private IOverlayService? OverlayService { get; set; }

        private readonly SemaphoreSlim _receiveItemSemaphore = new SemaphoreSlim(1, 1);
        private bool isOverlayEnabled = false;
        private const int BATCH_SIZE = 25;
        private IGameClient _gameClient;

        private CancellationTokenSource _cancellationTokenSource { get; set; } = new CancellationTokenSource();
        private readonly List<CancellationTokenSource> _linkedTokenSources = new();
        public ArchipelagoClient(IGameClient gameClient)
        {
            Memory.CurrentProcId = gameClient.ProcId;
            AppDomain.CurrentDomain.ProcessExit += async (sender, e) => await SaveGameStateAsync();
            _gameClient = gameClient;
            _gameClientPollTimer = new Timer(PeriodicGameClientConnectionCheck, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
            NativeLibraryLoader.Initialize();
            this.isReadyToReceiveItems = false;
        }
        public async Task SaveGameStateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);

            if (_gameStateManager == null)
            {
                Log.Warning("GameStateManager not initialized");
                return;
            }

            await _gameStateManager.SaveItemsAsync(cancellationToken);
            await _gameStateManager.SaveLocationsAsync(cancellationToken);
        }
        public async Task LoadGameStateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);

            if (_gameStateManager == null)
            {
                Log.Warning("GameStateManager not initialized");
                return;
            }

            await _gameStateManager.LoadItemsAsync(cancellationToken);
            await _gameStateManager.LoadLocationsAsync(cancellationToken);
            if (_gameStateManager.CurrentItemState.ReceivedItems.Count == 0
             && _gameStateManager.CurrentLocationState.CompletedLocations.Count == 0)
            {
                Log.Logger.Information("No locations or items received.");
                /* attempt to migrate from "gamestate" (previous method of storing item and loc state) */
                await _gameStateManager.MigrateGameStateAsync(cancellationToken);
            }
        }
        private void PeriodicGameClientConnectionCheck(object? state)
        {
            var isConnected = _gameClient.Connect();
            if (!isConnected)
            {
                Log.Warning("Connection to game lost, disconnecting from Archipelago");
                GameDisconnected?.Invoke(this, EventArgs.Empty);
                Disconnect();
            }
        }

        public void IntializeOverlayService(IOverlayService overlayService)
        {
            OverlayService = overlayService;
            OverlayService.AttachToWindow(Memory.GetCurrentProcess().MainWindowHandle);
            isOverlayEnabled = true;
        }
        public async Task Connect(string host, string gameName, CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            Disconnect();
            try
            {
                CurrentSession = ArchipelagoSessionFactory.CreateSession(host);
                var roomInfo = await CurrentSession.ConnectAsync();
                Seed = roomInfo.SeedName;
                GameName = gameName;

                CurrentSession.Socket.SocketClosed += Socket_SocketClosed;
                CurrentSession.MessageLog.OnMessageReceived += HandleMessageReceived;
                CurrentSession.Items.ItemReceived += ItemReceivedHandler;
                /* Does this do anything? We haven't added a listener on PacketReceived */
                CurrentSession.Socket.SendPacket(new SetNotifyPacket() { Keys = new[] { "ItemState" } });
                CurrentSession.Socket.SendPacket(new SetNotifyPacket() { Keys = new[] { "LocationState" } });
                CurrentSession.Socket.SendPacket(new SetNotifyPacket() { Keys = new[] { "CustomValues" } });
                CurrentSession.Socket.SendPacket(new SetNotifyPacket() { Keys = new[] { "GPS" } });
                IsConnected = true;
            }
            catch (Exception ex)
            {
                Log.Error("Couldn't connect to Archipelago");
                Log.Error(ex.Message);
            }
        }
        private async void ItemReceivedHandler(ReceivedItemsHelper helper)
        {
            await ReceiveItems(_cancellationTokenSource.Token);
        }

        private void Socket_SocketClosed(string reason)
        {
            Log.Warning($"Connection Closed: {reason}");
            Disconnect();
        }

        public void Disconnect()
        {
            if (CurrentSession != null)
            {
                Log.Information($"Disconnecting...");
                CurrentSession.Socket.DisconnectAsync();
                CurrentSession.Socket.SocketClosed -= Socket_SocketClosed;
                CurrentSession.MessageLog.OnMessageReceived -= HandleMessageReceived;
                CurrentSession.Items.ItemReceived -= ItemReceivedHandler;
                CancelMonitors();
                _gpsStateManager?.Dispose();
                _gpsStateManager = null;
                _gameStateManager = null;
                CurrentSession = null;
            }
            IsConnected = false;
            IsLoggedIn = false;
            Disconnected?.Invoke(this, new ConnectionChangedEventArgs(false));
            Log.Information($"Disconnected");
        }

        public async Task Login(string playerName, string password = null, ItemsHandlingFlags? itemsHandlingFlags = null, CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            if (!IsConnected)
            {
                Log.Error("Must be connected to the server to log in.  Please ensure your host is correct.");
                return;
            }
            if (itemsHandlingFlags != null)
            {
                itemsFlags = itemsHandlingFlags;
            }
            var loginResult = await CurrentSession.LoginAsync(GameName, playerName, itemsHandlingFlags ?? ItemsHandlingFlags.AllItems, Version.Parse("0.6.2"), password: password, requestSlotData: true);
            Log.Verbose($"Login Result: {(loginResult.Successful ? "Success" : "Failed")}");
            if (loginResult.Successful)
            {
                Log.Information($"Connected as Player: {playerName} playing {GameName}");
            }
            else
            {
                Log.Error($"Login failed.");
                return;
            }
            var currentSlot = CurrentSession.ConnectionInfo.Slot;
            var slotData = await CurrentSession.DataStorage.GetSlotDataAsync(currentSlot);
            Log.Information("Loading Options.");
            if (slotData.TryGetValue("options", out object? optionData))
            {
                if (optionData != null)
                {
                    _options = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(optionData.ToString());
                }
                Log.Verbose($"Options: \n\t{System.Text.Json.JsonSerializer.Serialize(optionData)}");
            }
            else
            {
                Log.Warning("No options found.");
            }
            _gameStateManager = new GameStateManager(CurrentSession, GameName, Seed, currentSlot);
            _gpsStateManager = new GPSStateManager(CurrentSession, GameName, Seed, currentSlot);

            await LoadGameStateAsync(cancellationToken);

            itemsReceivedCurrentSession = 0;

            IsLoggedIn = true;
            await Task.Run(() => Connected?.Invoke(this, new ConnectionChangedEventArgs(true)));
            isReadyToReceiveItems = true;
            await ReceiveItems(cancellationToken);

            return;
        }
        public async void SendMessage(string message, CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            await CurrentSession.Socket.SendPacketAsync(new SayPacket() { Text = message });

        }
        private void HandleMessageReceived(LogMessage message)
        {
            Log.Debug($"Message received");
            MessageReceived?.Invoke(this, new MessageReceivedEventArgs(message));
        }
        public void SendGoalCompletion()
        {
            Log.Debug($"Sending Goal");

            try
            {
                var update = new StatusUpdatePacket
                {
                    Status = ArchipelagoClientState.ClientGoal
                };
                CurrentSession.Socket.SendPacket(update);
            }
            catch (Exception ex)
            {
                Log.Error($"Could not send goal: {ex.Message}");
            }
        }
        public void CancelMonitors()
        {
            try
            {
                _monitorToken?.Cancel();
                _locationsChannel?.Writer.Complete();
            }
            catch (Exception ex)
            {
                Log.Error($"Error cancelling monitors: {ex.Message}");
            }
        }
        private async Task ReceiveItems(CancellationToken cancellationToken = default)
        {
            if (!isReadyToReceiveItems)
            {
                return;
            }
            cancellationToken = CombineTokens(cancellationToken);
            await _receiveItemSemaphore.WaitAsync(cancellationToken);
            try
            {
                if (!isReadyToReceiveItems) /* in case it was set false while waiting */
                {
                    return;
                }
                await _gameStateManager.LoadItemsAsync(cancellationToken);

                bool receivedNewItems = false;

                ItemInfo newItemInfo = CurrentSession.Items.PeekItem();
                while (newItemInfo != null)
                {
                    itemsReceivedCurrentSession++;
                    bool receiveSuccess = true;
                    if (itemsReceivedCurrentSession > ItemState.LastCheckedIndex)
                    {
                        var item = new Item
                        {
                            Id = newItemInfo.ItemId,
                            Name = newItemInfo.ItemName,
                        };
                        Log.Debug($"Adding new item {item.Name}");

                        var args = new ItemReceivedEventArgs()
                        {
                            Item = item,
                            LocationId = newItemInfo.LocationId,
                            Player = newItemInfo.Player,
                            Success = true  /* default to true - so game client can set it to false if it fails */
                        };
                        ItemReceived?.Invoke(this, args);
                        receiveSuccess = args.Success;

                        if (receiveSuccess)
                        {
                            ItemState.ReceivedItems.Enqueue(item);
                            ItemState.LastCheckedIndex = itemsReceivedCurrentSession;
                            receivedNewItems = true;
                        }
                        else
                        {
                            itemsReceivedCurrentSession--; /* undo the earlier increment */
                            isReadyToReceiveItems = false;
                            Log.Verbose($"Unable to receive item: {item.Name}.");
                            /* Game client knows the item failed to receive, so they can reinitiate it when they want to. */
                            break; /* leave the dequeueing loop */
                        }
                    }
                    else
                    {
                        Log.Verbose($"Fast forwarding past previously received item {newItemInfo.ItemName}");
                    }

                    CurrentSession.Items.DequeueItem();
                    newItemInfo = CurrentSession.Items.PeekItem();
                }

                if (receivedNewItems)
                {
                    await _gameStateManager.SaveItemsAsync(cancellationToken);
                }
            }
            finally
            {
                _receiveItemSemaphore.Release();
            }
        }

        public async void ReceiveReady()
        {
            isReadyToReceiveItems = true;
            await ReceiveItems();
        }
        public async Task AddLocationAsync(ILocation location)
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

        public async Task RemoveLocationAsync(ILocation location)
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
        public async Task MonitorLocations(List<ILocation> locations)
        {
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

            await StartMonitoring();
        }
        private async Task StartMonitoring()
        {
            _workerTasks.Clear();

            for (int i = 0; i < WORKER_COUNT; i++)
            {
                var workerId = i;
                var task = Task.Run(async () => await ProcessLocationWorkerAsync(workerId), _monitorToken.Token);
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
        private async Task ProcessLocationWorkerAsync(int workerId)
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
                                    SendLocation(location, _monitorToken.Token);
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

        [Obsolete]
        public async Task MonitorLocationsOld(List<ILocation> locations, CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            var locationBatches = locations
                .Select((location, index) => new { Location = location, Index = index })
                .GroupBy(x => x.Index / BATCH_SIZE)
                .Select(g => g.Select(x => x.Location).ToList())
                .ToList();
            Log.Debug($"Created {locationBatches.Count} batches");

            var tasks = locationBatches.Select(x => MonitorBatch(x, _cancellationTokenSource.Token));
            await Task.WhenAll(tasks);

        }
        public void AddOverlayMessage(string message, CancellationToken cancellationToken = default)
        {
            if (isOverlayEnabled)
            {
                cancellationToken = CombineTokens(cancellationToken);
                OverlayService.AddTextPopup(message);
            }
        }
        public void AddRichOverlayMessage(LogMessage message, CancellationToken cancellationToken = default)
        {
            if (isOverlayEnabled)
            {
                cancellationToken = CombineTokens(cancellationToken);
                var spans = new List<ColoredTextSpan>();
                foreach (var part in message.Parts)
                {
                    spans.Add(new ColoredTextSpan()
                    {
                        Text = part.Text,
                        Color = new Util.Overlay.Color(part.Color.R, part.Color.G, part.Color.B)
                    });
                }
                OverlayService.AddRichTextPopup(spans);
            }
        }
        [Obsolete]
        private async Task MonitorBatch(List<ILocation> batch, CancellationToken token)
        {
            List<ILocation> completed = [];
            while (!batch.All(x => completed.Any(y => y.Id == x.Id)))
            {
                if (token.IsCancellationRequested) return;
                if (EnableLocationsCondition?.Invoke() ?? true)
                {
                    foreach (var location in batch)
                    {
                        var isCompleted = location.Check();// Helpers.CheckLocation(location);
                        if (isCompleted)
                        {
                            completed.Add(location);
                            //  Log.Logger.Information(JsonConvert.SerializeObject(location));
                        }
                    }
                    if (completed.Count > 0)
                    {
                        foreach (var location in completed)
                        {
                            SendLocation(location, token);
                            Log.Debug($"{location.Name} ({location.Id}) Completed");
                            batch.Remove(location);
                        }
                    }
                    completed.Clear();
                }
                await Task.Delay(500, token);
            }
        }
        public async void SendLocation(ILocation location, CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            if (CurrentSession == null)
            {
                Log.Error("Must be connected and logged in to send locations.");
                return;
            }
            if (LocationState?.CompletedLocations == null)
            {
                Log.Error("Could not send location, LocationState is null.");
                return;
            }
            if (!(EnableLocationsCondition?.Invoke() ?? true))
            {
                Log.Debug("Location precondition not met, location not sent");
                return;
            }
            Log.Debug($"Marking location {location.Id} as complete");
            if (LocationState.CompletedLocations.Any((x) => x.Id == location.Id))
            {
                Log.Debug($"Skipping location {location.Name} - already completed.");
                return;
            }

            await CurrentSession.Locations.CompleteLocationChecksAsync([(long)location.Id]);
            LocationState.CompletedLocations.Enqueue(location);
            await _gameStateManager.SaveLocationsAsync(cancellationToken);
            LocationCompleted?.Invoke(this, new LocationCompletedEventArgs(location));
        }

        public async Task SaveGPSAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);

            if (_gpsStateManager == null)
            {
                Log.Warning("GPSStateManager not initialized");
                return;
            }

            await _gpsStateManager.SaveAsync(cancellationToken);
        }

        private CancellationToken CombineTokens(CancellationToken externalToken)
        {
            if (externalToken == default || externalToken == CancellationToken.None)
            {
                return _cancellationTokenSource.Token;
            }

            var linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
                _cancellationTokenSource.Token,
                externalToken
            );

            lock (_linkedTokenSources)
            {
                _linkedTokenSources.Add(linkedSource);
            }

            return linkedSource.Token;
        }
        public async Task ForceReloadAllItems(CancellationToken cancellationToken = default)
        {
            if (_gameStateManager?.CurrentItemState == null)
            {
                Log.Warning("Cannot reload items - ItemState is null");
                return;
            }

            _gameStateManager.CurrentItemState.ReceivedItems = new ConcurrentQueue<Item>();
            _gameStateManager.CurrentItemState.LastCheckedIndex = 0;
            await _gameStateManager.ForceSaveItemsAsync(cancellationToken);
        }
        public async Task SendBounceMessage(BouncePacket bouncePacket)
        {
            await CurrentSession.Socket.SendPacketAsync(bouncePacket);
        }
        public DeathLinkService EnableDeathLink()
        {
            var service = CurrentSession.CreateDeathLinkService();
            service.EnableDeathLink();
            return service;
        }
        public void Dispose()
        {

            try
            {
                CancelMonitors();

                if (_workerTasks.Any())
                {
                    Task.WaitAll(_workerTasks.ToArray(), TimeSpan.FromSeconds(5));
                }

                SaveGameStateAsync().Wait(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex)
            {
                Log.Error($"Could not finalise tasks: {ex.Message}");
            }

            if (IsConnected)
            {
                Disconnect();
            }
            _gameClientPollTimer?.Dispose();
            _receiveItemSemaphore?.Dispose();
            _gpsStateManager?.Dispose();
            OverlayService?.Dispose();
            _monitorToken?.Dispose();
            _cancellationTokenSource?.Dispose();

            // Dispose all linked token sources
            lock (_linkedTokenSources)
            {
                foreach (var source in _linkedTokenSources)
                {
                    source?.Dispose();
                }
                _linkedTokenSources.Clear();
            }

        }

    }
}
