using Archipelago.Core.Json;
using Archipelago.Core.Models;
using Archipelago.MultiClient.Net;
using Archipelago.MultiClient.Net.Enums;
using Archipelago.MultiClient.Net.Models;
using Archipelago.MultiClient.Net.Packets;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class GameStateManager
    {
        private readonly ArchipelagoSession _session;
        private readonly string _gameName;
        private readonly string _seed;
        private readonly int _slot;

        private DateTime _lastSaveTime = DateTime.MinValue;
        private readonly SemaphoreSlim _saveSemaphore = new SemaphoreSlim(1, 1);
        private const int SAVE_THROTTLE_SECONDS = 10;

        public GameState CurrentState { get; private set; }
        public Dictionary<string, object> CustomValues { get; private set; }

        public GameStateManager(ArchipelagoSession session, string gameName, string seed, int slot)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _gameName = gameName ?? throw new ArgumentNullException(nameof(gameName));
            _seed = seed ?? throw new ArgumentNullException(nameof(seed));
            _slot = slot;

            CustomValues = new Dictionary<string, object>();
        }

        public async Task SaveAsync(CancellationToken cancellationToken = default)
        {
            if (CurrentState == null)
            {
                Log.Warning("Cannot save - GameState is null");
                return;
            }

            var timeSinceLastSave = DateTime.UtcNow - _lastSaveTime;
            if (timeSinceLastSave < TimeSpan.FromSeconds(SAVE_THROTTLE_SECONDS))
            {
                Log.Verbose($"Save throttled - last save was {timeSinceLastSave.TotalSeconds:F1}s ago (minimum {SAVE_THROTTLE_SECONDS}s)");
                return;
            }

            if (!await _saveSemaphore.WaitAsync(0, cancellationToken))
            {
                Log.Verbose("Save already in progress, skipping");
                return;
            }

            try
            {
                Log.Debug("Saving game state");

                await _session.Socket.SendPacketAsync(CreateSetPacket("GameState", CurrentState));
                await _session.Socket.SendPacketAsync(CreateSetPacket("CustomValues", CustomValues));

                _lastSaveTime = DateTime.UtcNow;
                Log.Debug("Save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save game state: {ex.Message}");
                throw;
            }
            finally
            {
                _saveSemaphore.Release();
            }
        }

        public async Task ForceSaveAsync(CancellationToken cancellationToken = default)
        {
            _lastSaveTime = DateTime.MinValue;
            await SaveAsync(cancellationToken);
        }

        public async Task LoadAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading game state");

            try
            {
                var (success, data) = await DeserializeFromStorageAsync<GameState>("GameState");
                if (success && data != null)
                {
                    CurrentState = data;
                    Log.Verbose($"Loaded GameState with {CurrentState.ReceivedItems.Count} items, LastCheckedIndex: {CurrentState.LastCheckedIndex}");
                }
                else
                {
                    Log.Warning("No existing GameState found - creating new");
                    CurrentState = new GameState() { LastCheckedIndex = 0 };
                }

                var (success2, data2) = await GetFromStorageAsync<Dictionary<string, object>>("CustomValues");
                if (success2 && data2 != null)
                {
                    CustomValues = data2;
                }
                else
                {
                    CustomValues = new Dictionary<string, object>();
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading GameState: {ex.Message}");
                CurrentState = new GameState() { LastCheckedIndex = 0 };
                CustomValues = new Dictionary<string, object>();
            }
        }

        public async Task UpdateAndSaveAsync(Action<GameState> updateAction, CancellationToken cancellationToken = default)
        {
            if (CurrentState == null)
            {
                Log.Warning("Cannot update - GameState is null");
                return;
            }

            updateAction(CurrentState);
            await SaveAsync(cancellationToken);
        }

        public void ResetThrottle()
        {
            _lastSaveTime = DateTime.MinValue;
            Log.Debug("Save throttle reset");
        }

        private SetPacket CreateSetPacket<T>(string key, T value)
        {
            return new SetPacket()
            {
                Key = BuildStorageKey(key),
                WantReply = true,
                DefaultValue = JObject.FromObject(new Dictionary<string, object>()),
                Operations = new[]
                {
                    new OperationSpecification()
                    {
                        OperationType = OperationType.Replace,
                        Value = JToken.FromObject(new Dictionary<string, object> { { key, value } })
                    }
                }
            };
        }

        private async Task<(bool Success, T? Result)> DeserializeFromStorageAsync<T>(string key)
        {
            try
            {
                var dataStorage = _session.DataStorage[BuildStorageKey(key)];
                var data = await dataStorage.GetAsync<Dictionary<string, object>>();
                var value = data[key];

                var result = JsonConvert.DeserializeObject<T>(value.ToString(), new JsonSerializerSettings()
                {
                    Converters = { new LocationConverter() },
                    Formatting = Formatting.Indented
                });

                Log.Verbose($"Loaded {key} from data storage");
                return (true, result);
            }
            catch (Exception ex)
            {
                Log.Debug($"Failed to load {key} from data storage: {ex.Message}");
                return (false, default);
            }
        }

        private async Task<(bool Success, T? Result)> GetFromStorageAsync<T>(string key)
        {
            try
            {
                var dataStorage = _session.DataStorage[BuildStorageKey(key)];
                var data = await dataStorage.GetAsync<Dictionary<string, T>>();
                var value = data[key];

                if (value is T correctType)
                {
                    Log.Verbose($"Loaded {key} from data storage");
                    return (true, correctType);
                }

                return (false, default);
            }
            catch (Exception ex)
            {
                Log.Debug($"Failed to load {key} from data storage: {ex.Message}");
                return (false, default);
            }
        }

        private string BuildStorageKey(string key)
        {
            return $"{_gameName}_{_slot}_{_seed}_{key}";
        }
    }
}
