using Archipelago.Core.Json;
using Archipelago.Core.Models;
using Archipelago.MultiClient.Net;
using Archipelago.MultiClient.Net.Enums;
using Archipelago.MultiClient.Net.Models;
using Archipelago.MultiClient.Net.Packets;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class GameStateManager
    {
        private readonly ArchipelagoSession _session;
        private readonly string _gameName;
        private readonly string _seed;
        private readonly int _slot;
        private readonly string _saveId;

        private DateTime _lastItemSaveTime = DateTime.MinValue;
        private DateTime _lastLocationSaveTime = DateTime.MinValue;
        private readonly SemaphoreSlim _saveItemSemaphore = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _saveLocationSemaphore = new SemaphoreSlim(1, 1);
        private const int SAVE_THROTTLE_SECONDS = 10;

        public ItemState CurrentItemState { get; private set; }
        public LocationState CurrentLocationState { get; private set; }
        public Dictionary<string, object> CustomValues { get; private set; }

        public GameStateManager(ArchipelagoSession session, string gameName, string seed, int slot)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _gameName = gameName ?? throw new ArgumentNullException(nameof(gameName));
            _seed = seed ?? throw new ArgumentNullException(nameof(seed));
            _slot = slot;

            CustomValues = new Dictionary<string, object>();
        }

        public async Task SaveItemsAsync(CancellationToken cancellationToken = default)
        {
            if (CurrentItemState == null)
            {
                Log.Warning("Cannot save - ItemState is null");
                return;
            }

            var timeSinceLastItemSave = DateTime.UtcNow - _lastItemSaveTime;
            if (timeSinceLastItemSave < TimeSpan.FromSeconds(SAVE_THROTTLE_SECONDS))
            {
                Log.Verbose($"Save throttled - last save was {timeSinceLastItemSave.TotalSeconds:F1}s ago (minimum {SAVE_THROTTLE_SECONDS}s)");
                return;
            }

            if (!await _saveItemSemaphore.WaitAsync(0, cancellationToken))
            {
                Log.Verbose("Save already in progress, skipping");
                return;
            }

            try
            {
                Log.Debug("Saving Itemstate");

                await _session.Socket.SendPacketAsync(CreateSetPacket("ItemState", CurrentItemState));

                _lastItemSaveTime = DateTime.UtcNow;
                Log.Debug("Save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save Item state: {ex.Message}");
                throw;
            }
            finally
            {
                _saveItemSemaphore.Release();
            }
        }

        public async Task ForceSaveItemsAsync(CancellationToken cancellationToken = default)
        {
            _lastItemSaveTime = DateTime.MinValue;
            await SaveItemsAsync(cancellationToken);
        }

        public async Task LoadItemsAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading item state");

            try
            {
                var (success, data) = await DeserializeFromStorageAsync<ItemState>("ItemState");
                if (success && data != null)
                {
                    CurrentItemState = data;
                    Log.Verbose($"Loaded ItemState with {CurrentItemState.ReceivedItems.Count} items, LastCheckedIndex: {CurrentItemState.LastCheckedIndex}");
                }
                else
                {
                    Log.Warning("No existing ItemState found - creating new");
                    CurrentItemState = new ItemState() { LastCheckedIndex = 0 };
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading ItemState: {ex.Message}");
                CurrentItemState = new ItemState() { LastCheckedIndex = 0 };
            }
        }

        public async Task UpdateAndSaveItemsAsync(Action<ItemState> updateAction, CancellationToken cancellationToken = default)
        {
            if (CurrentItemState == null)
            {
                Log.Warning("Cannot update - ItemState  is null");
                return;
            }

            updateAction(CurrentItemState);
            await SaveItemsAsync(cancellationToken);
        }

        public void ResetItemThrottle()
        {
            _lastItemSaveTime = DateTime.MinValue;
            Log.Debug("Save throttle reset");
        }

        public async Task SaveLocationsAsync(CancellationToken cancellationToken = default)
        {
            if (CurrentLocationState == null)
            {
                Log.Warning("Cannot save - LocationState is null");
                return;
            }

            var timeSinceLastLocationSave = DateTime.UtcNow - _lastLocationSaveTime;
            if (timeSinceLastLocationSave < TimeSpan.FromSeconds(SAVE_THROTTLE_SECONDS))
            {
                Log.Verbose($"Save throttled - last save was {timeSinceLastLocationSave.TotalSeconds:F1}s ago (minimum {SAVE_THROTTLE_SECONDS}s)");
                return;
            }

            if (!await _saveLocationSemaphore.WaitAsync(0, cancellationToken))
            {
                Log.Verbose("Save already in progress, skipping");
                return;
            }

            try
            {
                Log.Debug("Saving Location state");

                await _session.Socket.SendPacketAsync(CreateSetPacket("LocationState", CurrentLocationState));

                _lastLocationSaveTime = DateTime.UtcNow;
                Log.Debug("Save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save Location state: {ex.Message}");
                throw;
            }
            finally
            {
                _saveLocationSemaphore.Release();
            }
        }

        public async Task ForceSaveLocationsAsync(CancellationToken cancellationToken = default)
        {
            _lastLocationSaveTime = DateTime.MinValue;
            await SaveLocationsAsync(cancellationToken);
        }

        public async Task LoadLocationsAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading Location state");

            try
            {
                var (success, data) = await DeserializeFromStorageAsync<LocationState>("LocationState");
                if (success && data != null)
                {
                    CurrentLocationState = data;
                    Log.Verbose($"Loaded LocationState with {CurrentLocationState.CompletedLocations.Count} Locations");
                }
                else
                {
                    Log.Warning("No existing LocationState found - creating new");
                    CurrentLocationState = new LocationState() { };
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading LocationState: {ex.Message}");
            }
        }

        public async Task UpdateAndSaveLocationsAsync(Action<LocationState> updateAction, CancellationToken cancellationToken = default)
        {
            if (CurrentLocationState == null)
            {
                Log.Warning("Cannot update - LocationState  is null");
                return;
            }

            updateAction(CurrentLocationState);
            await SaveLocationsAsync(cancellationToken);
        }

        public void ResetLocationThrottle()
        {
            _lastLocationSaveTime = DateTime.MinValue;
            Log.Debug("Save throttle reset");
        }

        public async Task MigrateGameStateAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading Game state");
            GameState result = null;
            try
            {
                var (success, data) = await DeserializeFromStorageAsync<GameState>("GameState");
                if (success && data != null)
                {
                    result = data;
                    Log.Information($"Migrating GameState with {result.CompletedLocations.Count} Locations and {result.ReceivedItems.Count} items received.");
                    CurrentItemState = new ItemState();
                    CurrentItemState.ReceivedItems = result.ReceivedItems;
                    CurrentItemState.LastCheckedIndex = result.LastCheckedIndex;

                    CurrentLocationState = new LocationState();
                    CurrentLocationState.CompletedLocations = result.CompletedLocations;

                    await SaveItemsAsync();
                    await SaveLocationsAsync();
                    Log.Information($"Migration from GameState to ItemState and LocationState complete.");
                }
                else
                {
                    Log.Debug("Migration attempt failed - No existing GameState found.");
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading GameState: {ex.Message}");
            }
        }

        private SetPacket CreateSetPacket<T>(string key, T value)
        {
            return new SetPacket()
            {
                Key = BuildStorageKey(key),
                WantReply = true,
                DefaultValue = Newtonsoft.Json.Linq.JObject.FromObject(new Dictionary<string, object>()),
                Operations = new[]
                {
                    new OperationSpecification()
                    {
                        OperationType = OperationType.Replace,
                        Value = Newtonsoft.Json.Linq.JToken.FromObject(new Dictionary<string, object> { { key, value } })
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
                if (data is null)
                {
                    Log.Debug($"Failed to load {key} from data storage");
                    return (false, default);
                }
                var value = data[key];

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Converters = { new LocationConverter() }
                };

                var json = value.ToString();
                var result = JsonSerializer.Deserialize<T>(json!, options);

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
                if (data is null)
                {
                    Log.Debug($"Failed to load {key} from data storage");
                    return (false, default);
                }
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
