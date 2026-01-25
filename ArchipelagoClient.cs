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

        public ItemManager ItemManager 
        {
            get 
            {
                return _itemManager; 
            }
            set 
            {
                if (_itemManager != value) 
                {
                    _itemManager = value; 
                }
            }
        }
        public LocationManager LocationManager
        {
            get
            {
                return _locationManager;
            }
            set
            {
                if (_locationManager != value)
                {
                    _locationManager = value;
                }
            }
        }
        public bool IsConnected { get; set; }
        public bool IsLoggedIn { get; set; }
        public event EventHandler<ConnectionChangedEventArgs>? Disconnected;
        public event EventHandler<ConnectionChangedEventArgs>? Connected;
        public event EventHandler<MessageReceivedEventArgs>? MessageReceived;
        public event EventHandler? GameDisconnected;
        public ItemsHandlingFlags? itemsFlags { get; set; }
        public ArchipelagoSession CurrentSession { get; set; }
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
        public Dictionary<string, string> CustomValues => _gameStateManager?.CustomValues ?? new Dictionary<string, string>();

        private IOverlayService? OverlayService { get; set; }

        private bool isOverlayEnabled = false;
        private IGameClient _gameClient;
        private ItemManager _itemManager;
        private LocationManager _locationManager;

        public ArchipelagoClient(IGameClient gameClient)
        {
            Memory.CurrentProcId = gameClient.ProcId;
            AppDomain.CurrentDomain.ProcessExit += async (sender, e) => await SaveGameStateAsync();
            _gameClient = gameClient;
            _gameClientPollTimer = new Timer(PeriodicGameClientConnectionCheck, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
            NativeLibraryLoader.Initialize();
        }
        public async Task SaveGameStateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);

            if (_gameStateManager == null)
            {
                Log.Warning("GameStateManager not initialized");
                return;
            }

            await _gameStateManager.SaveItemIndexAsync(cancellationToken);
            if (CustomValues.Count > 0)
            {
                await _gameStateManager.SaveCustomValuesAsync(cancellationToken);
            }
        }
        public async Task LoadGameStateAsync(CancellationToken cancellationToken = default, bool loadItemIndex = true)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);

            if (_gameStateManager == null)
            {
                Log.Warning("GameStateManager not initialized");
                return;
            }

            if (loadItemIndex)
            {
                await _gameStateManager.LoadItemIndexAsync(cancellationToken);
            }
            await _gameStateManager.LoadCustomValuesAsync(cancellationToken);
        }
        public async Task SaveCustomValuesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);

            if (_gameStateManager == null)
            {
                Log.Warning("GameStateManager not initialized");
                return;
            }

            await _gameStateManager.SaveCustomValuesAsync(cancellationToken);
        }
        public async Task LoadCustomValuesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);

            if (_gameStateManager == null)
            {
                Log.Warning("GameStateManager not initialized");
                return;
            }

            await _gameStateManager.LoadCustomValuesAsync(cancellationToken);
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
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);
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
                CurrentSession.Socket.SendPacket(new SetNotifyPacket() { Keys = new[] { "ItemIndex" } });
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
            await ReceiveItems();
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
                LocationManager?.CancelMonitors();
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

        public async Task Login(string playerName, string password = null, ItemsHandlingFlags? itemsHandlingFlags = null, CancellationToken cancellationToken = default, bool startReadyToReceiveItems = true)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);
            if (!IsConnected)
            {
                Log.Error("Must be connected to the server to log in.  Please ensure your host is correct.");
                return;
            }
            if (itemsHandlingFlags != null)
            {
                itemsFlags = itemsHandlingFlags;
            }
            var loginResult = await CurrentSession.LoginAsync(GameName, playerName, itemsHandlingFlags ?? ItemsHandlingFlags.AllItems, Version.Parse("0.6.5"), password: password, requestSlotData: true);
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
            ItemManager = new ItemManager(ref _gameStateManager);
            LocationManager = new LocationManager(ref _gameStateManager);
            await LoadGameStateAsync(cancellationToken, startReadyToReceiveItems);


            IsLoggedIn = true;
            await Task.Run(() => Connected?.Invoke(this, new ConnectionChangedEventArgs(true)));
            
            ItemManager.Initialize(startReadyToReceiveItems);
            await ReceiveItems(cancellationToken);

            return;
        }
        public async void SendMessage(string message, CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);
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
        public async Task MonitorLocationsAsync(List<ILocation> locations, CancellationToken cancellationToken = default)
        {
            await LocationManager.MonitorLocationsAsync(CurrentSession, locations, cancellationToken);
        }
        public async Task SendLocationAsync(ILocation location, CancellationToken cancellationToken = default)
        {
            await LocationManager.SendLocationAsync(CurrentSession, location, cancellationToken);
        }
        private async Task ReceiveItems(CancellationToken cancellationToken = default)
        {
            await ItemManager.ReceiveItems(CurrentSession, cancellationToken);           
        }

        public async Task ReceiveReady()
        {
            await ItemManager.ReceiveReady(CurrentSession);
        }

        public void AddOverlayMessage(string message, CancellationToken cancellationToken = default)
        {
            if (isOverlayEnabled)
            {
                cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);
                OverlayService.AddTextPopup(message);
            }
        }
        public void AddRichOverlayMessage(LogMessage message, CancellationToken cancellationToken = default)
        {
            if (isOverlayEnabled)
            {
                cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);
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
        
        public async Task SaveGPSAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken = Helpers.Helpers.CombineTokens(cancellationToken);

            if (_gpsStateManager == null)
            {
                Log.Warning("GPSStateManager not initialized");
                return;
            }

            await _gpsStateManager.SaveAsync(cancellationToken);
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
                LocationManager?.CancelMonitors();

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
            _gpsStateManager?.Dispose();
            OverlayService?.Dispose();
        }
        // Request a new saveid. 
        public async Task<byte> RequestNewSaveId()
        {
            byte newSaveId;
            await _gameStateManager.LoadSaveIdsAsync();
            if (_gameStateManager.SaveIds.Count > 0)
            {
                byte highestid = _gameStateManager.SaveIds.Max(x => ((byte)x));
                if (highestid >= 255)
                {
                    Log.Logger.Error("Cannot have more than 255 saves");
                    return 0; // return 0, an invalid saveid
                }
                newSaveId = (byte)(highestid + 1);
            }
            else
            {
                newSaveId = 1; // start at 1
            }
            _gameStateManager.SaveIds.Add(newSaveId);
            Log.Logger.Debug($"Added saveid {newSaveId}");
            await _gameStateManager.SaveSaveIdsAsync();
            return newSaveId;
        }

        // Update our "saveid" value stored in the gamestate.
        // Disables item receives, and resets the items in the receivable items list.
        // Returns true if this was allowed, and false if it failed. 
        public async Task<bool> UpdateSaveId(byte newsaveid)
        {
            await _gameStateManager.LoadSaveIdsAsync();
            if (!_gameStateManager.SaveIds.Contains(newsaveid))
            {
                Log.Logger.Error("Error: save id not in list");
                return false;
            }

            string newsaveidString = newsaveid.ToString("X");
            if (_gameStateManager.saveId == newsaveidString) // no update needed
            {
                Log.Logger.Debug("saveid is unchanged");
                return true;
            }
            else
            {
                await ItemManager.StopReceiving();
                _gameStateManager.saveId = newsaveidString;
                await ItemManager.ResetItems();
                Log.Logger.Debug($"Updated saveid to {newsaveid}");
            }
            return true;
        }
    }
}
