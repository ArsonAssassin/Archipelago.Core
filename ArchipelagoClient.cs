using Archipelago.Core.Json;
using Archipelago.Core.Models;
using Archipelago.Core.Util;
using Archipelago.Core.Util.GPS;
using Archipelago.Core.Util.Overlay;
using Archipelago.MultiClient.Net;
using Archipelago.MultiClient.Net.BounceFeatures.DeathLink;
using Archipelago.MultiClient.Net.Enums;
using Archipelago.MultiClient.Net.Helpers;
using Archipelago.MultiClient.Net.MessageLog.Messages;
using Archipelago.MultiClient.Net.Models;
using Archipelago.MultiClient.Net.Packets;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Serilog;
using System.Drawing.Text;
using System.Text.Json;
using System.Threading;

namespace Archipelago.Core
{
    public class ArchipelagoClient : IDisposable
    {
        private readonly Timer _gameStateTimer;
        private readonly Timer _gameClientPollTimer;
        private DateTime _lastGameStateUpdate = DateTime.MinValue;
        public bool IsConnected { get; set; }
        public bool IsLoggedIn { get; set; }
        public event EventHandler<ItemReceivedEventArgs>? ItemReceived;
        public event EventHandler<ConnectionChangedEventArgs>? Disconnected;
        public event EventHandler<ConnectionChangedEventArgs>? Connected;
        public event EventHandler<MessageReceivedEventArgs>? MessageReceived;
        public event EventHandler<LocationCompletedEventArgs>? LocationCompleted;
        public event EventHandler? GameDisconnected;
        public Func<bool>? EnableLocationsCondition;
        public int itemsReceivedCurrentSession { get; set; }
        public bool isReadyToReceiveItems { get; set; }
        public ArchipelagoSession CurrentSession { get; set; }
        private CancellationTokenSource _monitorToken { get; set; }
        private List<ILocation> _monitoredLocations { get; set; } = new List<ILocation>();
        public GPSHandler GPSHandler
        {
            get
            {
                return _gpsHandler;
            }
            set
            {
                if (_gpsHandler != value)
                {
                    _gpsHandler = value;
                    if (_gpsHandler != null)
                    {
                        _gpsHandler.PositionChanged += _gpsHandler_PositionChanged;
                        _gpsHandler.MapChanged += _gpsHandler_MapChanged;
                    }
                }
            }
        }

        private string GameName { get; set; } = "";
        private string Seed { get; set; } = "";
        private Dictionary<string, object> _options = [];
        public Dictionary<string, object> Options { get { return _options; } }
        public GameState GameState { get; set; }
        public Dictionary<string, object> CustomValues { get; set; }
        public bool ShouldSaveStateOnItemReceived { get; set; }
        private IOverlayService? OverlayService { get; set; }

        private readonly SemaphoreSlim _receiveItemSemaphore = new SemaphoreSlim(1, 1);
        private bool isOverlayEnabled = false;
        private GPSHandler _gpsHandler;
        private const int BATCH_SIZE = 25;
        private const int THREAD_COUNT = 20;
        private IGameClient _gameClient;
        private object _locationListLock = new object();

        private CancellationTokenSource _cancellationTokenSource { get; set; } = new CancellationTokenSource();
        public ArchipelagoClient(IGameClient gameClient)
        {
            Memory.CurrentProcId = gameClient.ProcId;
            AppDomain.CurrentDomain.ProcessExit += async (sender, e) => await SaveGameStateAsync();
            _gameClient = gameClient;
            _gameStateTimer = new Timer(PeriodicGameStateUpdate, null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
            _gameClientPollTimer = new Timer(PeriodicGameClientConnectionCheck, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
            this.isReadyToReceiveItems = false;
            this.ShouldSaveStateOnItemReceived = true;
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
            OverlayService.Show();
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
                CurrentSession.Socket.SendPacket(new SetNotifyPacket() { Keys = new[] { "GameState" } });
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
                GameState = null;
                CurrentSession = null;
            }
            IsConnected = false;
            IsLoggedIn = false;
            Disconnected?.Invoke(this, new ConnectionChangedEventArgs(false));
            Log.Information($"Disconnected");
        }

        public async Task Login(string playerName, string password = null, CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            if (!IsConnected)
            {
                Log.Error("Must be connected to the server to log in.  Please ensure your host is correct.");
                return;
            }
            var loginResult = await CurrentSession.LoginAsync(GameName, playerName, ItemsHandlingFlags.AllItems, Version.Parse("0.6.1"), password: password, requestSlotData: true);
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

            await LoadGameStateAsync(cancellationToken);
            if (CustomValues == null)
            {
                CustomValues = new Dictionary<string, object>();
            }
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
            _monitorToken.Cancel();
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
                if (this.ShouldSaveStateOnItemReceived)
                {
                    await LoadGameStateAsync(cancellationToken);
                }

                var newItemInfo = CurrentSession.Items.DequeueItem();
                while (newItemInfo != null)
                {
                    itemsReceivedCurrentSession++;
                    if (itemsReceivedCurrentSession > GameState.LastCheckedIndex)
                    {
                        var item = new Item
                        {
                            Id = newItemInfo.ItemId,
                            Name = newItemInfo.ItemName,
                        };
                        Log.Debug($"Adding new item {item.Name}");
                        GameState.ReceivedItems.Add(item);
                        ItemReceived?.Invoke(this, new ItemReceivedEventArgs() { Item = item });
                        GameState.LastCheckedIndex = itemsReceivedCurrentSession;
                        if (this.ShouldSaveStateOnItemReceived)
                        {
                            await SaveGameStateAsync();
                        }
                    }
                    else
                    {
                        Log.Debug($"Fast forwarding past previously received item {newItemInfo.ItemName}");
                    }

                    newItemInfo = CurrentSession.Items.DequeueItem();
                }

                if (!cancellationToken.IsCancellationRequested)
                {
                    await CheckAndTriggerEarlySave(cancellationToken);
                }
            }
            finally
            {
                _receiveItemSemaphore.Release();
            }
        }
        private async Task ProcessLocationsAsync()
        {

            
            while (true)
            {
                List<ILocation> snapshot;
                lock (_locationListLock)
                {
                    snapshot = _monitoredLocations.Select(loc => loc.DeepClone()).ToList();
                }
                var startTime = DateTime.UtcNow;
                if (_monitorToken.IsCancellationRequested) return;
                if (!EnableLocationsCondition?.Invoke() ?? true) return;
				foreach (var location in snapshot)
				{

					var isCompleted = location.Check();// Helpers.CheckLocation(location);
					if (isCompleted)
					{
						SendLocation(location, _monitorToken.Token);
						Log.Debug($"{location.Name} ({location.Id}) Completed");
						RemoveLocationAsync(location);
						//  Log.Logger.Information(JsonConvert.SerializeObject(location));
					}
				}                   
                
                await Task.Delay(500);
            }
        }

        public async Task RemoveLocationAsync(ILocation location)
        {
            lock (_locationListLock)
            {
                var confirmedLocation = _monitoredLocations.SingleOrDefault(x => x.Id == location.Id);
                if (confirmedLocation != null)
                {
                    Log.Verbose($"Location {location.Id} - {location.Name} removed from tracking");
                    _monitoredLocations?.Remove(confirmedLocation);
                }
                else
                {
                    Log.Warning($"Could not remove location {location.Id} - {location.Name} because it was not found in the list, or was found multiple times.");
                }
            }
        }
        public async Task AddLocationAsync(ILocation location)
        {
            lock (_locationListLock)
            {
                if(!_monitoredLocations.Any(x => x.Id == location.Id))
                    _monitoredLocations?.Add(location);
            }
        }
        public async Task MonitorLocations(List<ILocation> locations)
        {

            _monitoredLocations = locations;
            StartMonitoring();

        }
        private async Task StartMonitoring()
        {
            var tasks = new Task[THREAD_COUNT];
    
            for (int i = 0; i < THREAD_COUNT; i++)
            {
                tasks[i] = Task.Run(() => ProcessLocationsAsync(), _monitorToken.Token);
            }
            await Task.WhenAll(tasks);
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
            if (GameState?.CompletedLocations == null)
            {
                Log.Error("Could not send location, GameState is null.");
                return;
            }
            if (EnableLocationsCondition?.Invoke() ?? true)
            {
                Log.Debug($"Marking location {location.Id} as complete");

                await CurrentSession.Locations.CompleteLocationChecksAsync([(long)location.Id]);
                GameState.CompletedLocations.Add(location);
                if (this.ShouldSaveStateOnItemReceived)
                {
                    await SaveGameStateAsync(cancellationToken);
                }
                LocationCompleted?.Invoke(this, new LocationCompletedEventArgs(location));
            }
            else
            {
                Log.Debug("Location precondition not met, location not sent");
            }
        }
        private async void PeriodicGameStateUpdate(object state)
        {
            await PerformGameStateUpdate(_cancellationTokenSource.Token);
        }
        private async Task PerformGameStateUpdate(CancellationToken cancellationToken)
        {
            try
            {
                await SaveGameStateAsync(cancellationToken);

                await LoadGameStateAsync(cancellationToken);
                _lastGameStateUpdate = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                Log.Error($"Error in game state update: {ex.Message}");
            }
        }
        private async Task CheckAndTriggerEarlySave(CancellationToken cancellationToken)
        {
            var timeSinceLastUpdate = DateTime.UtcNow - _lastGameStateUpdate;

            // If we're in the buffer zone (less than 50 seconds until next save)
            if (timeSinceLastUpdate >= TimeSpan.FromSeconds(10))
            {
                Log.Verbose($"Performing immediate save");
                await PerformGameStateUpdate(cancellationToken);
            }
            else
            {
                Log.Verbose($"Skipping duplicate save");
            }
        }
        private async Task ForceSaveAsync()
        {
            await PerformGameStateUpdate(_cancellationTokenSource.Token);
            Log.Debug("Force save completed");
        }
        public async Task SaveGameStateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            if (CurrentSession == null || GameState == null) return;
            Log.Debug($"Saving game state");

            try
            {
                var dataStorage = await CurrentSession.DataStorage.GetSlotDataAsync(CurrentSession.ConnectionInfo.Slot);
                await CurrentSession.Socket.SendPacketAsync(CreateSetPacket("GameState", GameState));
                await CurrentSession.Socket.SendPacketAsync(CreateSetPacket("CustomValues", CustomValues));

            }
            catch (Exception ex)
            {
                Log.Logger.Error("Failed to save to datastorage");
            }
        }
        private void _gpsHandler_MapChanged(object? sender, MapChangedEventArgs e)
        {
            SaveGPSAsync();
        }

        private void _gpsHandler_PositionChanged(object? sender, PositionChangedEventArgs e)
        {
            SaveGPSAsync();
        }
        public async Task SaveGPSAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            if (CurrentSession == null || GameState == null) return;
            Log.Debug($"Saving gps state");

            try
            {
                var dataStorage = await CurrentSession.DataStorage.GetSlotDataAsync(CurrentSession.ConnectionInfo.Slot);
                await CurrentSession.Socket.SendPacketAsync(CreateSetPacket("GPS", _gpsHandler.GetCurrentPosition()));

            }
            catch (Exception ex)
            {
                Log.Logger.Error("Failed to save to datastorage");
            }
        }
        private SetPacket CreateSetPacket<T>(string key, T value)
        {
            return new SetPacket()
            {
                Key = $"{GameName}_{CurrentSession.ConnectionInfo.Slot}_{Seed}_{key}",
                WantReply = true,
                DefaultValue = JObject.FromObject(new Dictionary<string, object>()),
                Operations = new[] {
                        new OperationSpecification()
                        {
                            OperationType = OperationType.Replace,
                            Value = JToken.FromObject(new Dictionary<string, object>{ { key, value } })
                        }
                    }
            };
        }

        public async Task LoadGameStateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = CombineTokens(cancellationToken);
            Log.Debug($"Loading game state");
            try
            {
                (bool success, GameState data) = await DeserializeFromDataStorageAsync<GameState>("GameState");
                if (success) { GameState = data; }
                else
                {
                    Log.Warning("No existing GameState, Creating new GameState");
                    GameState = new GameState() { LastCheckedIndex = 0 };
                    await SaveGameStateAsync(cancellationToken);
                }

                (bool success2, Dictionary<string, object> data2) = await GetFromDataStorageAsync<Dictionary<string, object>>("CustomValues");
                if (success2) CustomValues = data2;
            }
            catch
            {
                Log.Warning("An unhandled exception occurred when loading GameState. Creating new GameState.");
                GameState = new GameState();
            }
        }
        public async Task<(bool Success, T? Result)> DeserializeFromDataStorageAsync<T>(string key)
        {
            try
            {
                var dataStorage = CurrentSession.DataStorage[$"{GameName}_{CurrentSession.ConnectionInfo.Slot}_{Seed}_{key}"];
                var foo = await dataStorage.GetAsync<Dictionary<string, object>>();
                object bar = foo[key];
                var type = JsonConvert.DeserializeObject<T>(bar.ToString(), new JsonSerializerSettings()
                {
                    Converters = { new LocationConverter() },
                    Formatting = Formatting.Indented
                });

                Log.Logger.Verbose($"Loaded {key} from datastorage");
                return (true, type);
            }
            catch (Exception ex)
            {
                Log.Logger.Debug($"Failed to load {key} from datastorage: {ex.Message}");
                return (false, default(T?));
            }
        }
        public async Task<(bool Success, T? Result)> GetFromDataStorageAsync<T>(string key)
        {
            try
            {
                var dataStorage = CurrentSession.DataStorage[$"{GameName}_{CurrentSession.ConnectionInfo.Slot}_{Seed}_{key}"];
                var foo = await dataStorage.GetAsync<Dictionary<string, T>>();
                var bar = foo[key];

                if (bar is T correctType)
                {
                    Log.Logger.Verbose($"Loaded {key} from datastorage");
                    return (true, correctType);
                }

                return (false, default(T?));
            }
            catch (Exception ex)
            {
                Log.Logger.Debug($"Failed to load {key} from datastorage: {ex.Message}");
                return (false, default(T?));
            }
        }
        private CancellationToken CombineTokens(CancellationToken externalToken)
        {
            if (externalToken == default || externalToken == CancellationToken.None)
            {
                return _cancellationTokenSource.Token;
            }

            return CancellationTokenSource.CreateLinkedTokenSource(
                _cancellationTokenSource.Token,
                externalToken
            ).Token;
        }
        public async void ForceReloadAllItems()
        {
            GameState.ReceivedItems = new List<Item>();
            GameState.LastCheckedIndex = 0;
            await ForceSaveAsync();
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
                ForceSaveAsync().Wait(TimeSpan.FromSeconds(2));
            }
            catch (Exception ex)
            {
                Log.Error($"Could not perform final save: {ex.Message}");
            }

            if (IsConnected)
            {
                Disconnect();
            }
            _gameClientPollTimer?.Dispose();
            _receiveItemSemaphore?.Dispose();
            _gameStateTimer?.Dispose();
            OverlayService?.Hide();
            OverlayService?.Dispose();
            _monitorToken?.Dispose();
            _cancellationTokenSource?.Dispose();

        }

    }
}
