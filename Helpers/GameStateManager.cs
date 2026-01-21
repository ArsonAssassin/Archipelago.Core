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

        private readonly SemaphoreSlim _saveItemSemaphore = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _saveCustomValuesSemaphore = new SemaphoreSlim(1, 1);

        public int SavedItemIndex { get; set; }
        public Dictionary<string, string> CustomValues { get; private set; }
        public List<byte> SaveIds { get; private set; } = [];
        public string saveId;

        public GameStateManager(ArchipelagoSession session, string gameName, string seed, int slot)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _gameName = gameName ?? throw new ArgumentNullException(nameof(gameName));
            _seed = seed ?? throw new ArgumentNullException(nameof(seed));
            _slot = slot;
            saveId = "";

            CustomValues = new Dictionary<string, string>();
        }

        public async Task SaveItemIndexAsync(CancellationToken cancellationToken = default)
        {
            if (!await _saveItemSemaphore.WaitAsync(0, cancellationToken))
            {
                Log.Verbose("Save already in progress, skipping");
                return;
            }
            try
            {
                Log.Debug("Saving Item index");

                string suffix = "";
                if (saveId != "")
                {
                    suffix = $"_{saveId}";
                }

                await _session.Socket.SendPacketAsync(CreateSetPacket($"ItemIndex{suffix}", SavedItemIndex));

                Log.Debug("Item index save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save Item index: {ex.Message}");
                throw;
            }
            finally
            {
                _saveItemSemaphore.Release();
            }
        }
        public async Task ForceSaveItemIndexAsync(CancellationToken cancellationToken = default)
        {
            await SaveItemIndexAsync(cancellationToken);
        }

        public async Task LoadItemIndexAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading item index");

            try
            {
                string suffix = "";
                if (saveId != "")
                {
                    suffix = $"_{saveId}";
                }

                var (success, data) = await DeserializeFromStorageAsync<int>($"ItemIndex{suffix}");
                if (success && data != null)
                {
                    SavedItemIndex = data;

                    Log.Verbose($"Loaded ItemIndex with {SavedItemIndex} items");
                }
                else
                {
                    Log.Warning("No existing ItemIndex found - creating new");
                    SavedItemIndex = 0;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading ItemIndex: {ex.Message}");
                SavedItemIndex = 0;
            }
        }

        public async Task UpdateAndSaveItemIndexAsync(Action<int> updateAction, CancellationToken cancellationToken = default)
        {
            updateAction(SavedItemIndex);
            await SaveItemIndexAsync(cancellationToken);
        }
        public async Task SaveCustomValuesAsync(CancellationToken cancellationToken = default)
        {
            if (!await _saveCustomValuesSemaphore.WaitAsync(0, cancellationToken))
            {
                Log.Verbose("Save already in progress, skipping");
                return;
            }

            try
            {
                Log.Debug("Saving Custom values");

                await _session.Socket.SendPacketAsync(CreateSetPacket("CustomValues", CustomValues));

                Log.Debug("Custom values save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save Custom values: {ex.Message}");
                throw;
            }
            finally
            {
                _saveCustomValuesSemaphore.Release();
            }
        }
        public async Task ForceSaveCustomValuesAsync(CancellationToken cancellationToken = default)
        {
            await SaveCustomValuesAsync(cancellationToken);
        }

        public async Task LoadCustomValuesAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading Custom Values");

            try
            {
                var (success, data) = await DeserializeFromStorageAsync<Dictionary<string, string>>("CustomValues");
                if (success && data != null)
                {
                    CustomValues = data;
                    Log.Verbose($"Loaded Custom Values with {CustomValues.Count} elements");
                }
                else
                {
                    CustomValues = new Dictionary<string, string>();
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading Custom Values: {ex.Message}");
                CustomValues = new Dictionary<string, string>();
            }
        }

        public async Task UpdateAndSaveCustomValuesAsync(Action<Dictionary<string, string>> updateAction, CancellationToken cancellationToken = default)
        {
            updateAction(CustomValues);
            await SaveCustomValuesAsync(cancellationToken);
        }
        public async Task SaveSaveIdsAsync(CancellationToken cancellationToken = default)
        {
            if (!await _saveItemSemaphore.WaitAsync(0, cancellationToken))
            {
                Log.Verbose("Save already in progress, skipping");
                return;
            }

            try
            {
                Log.Debug("Saving Save Ids");

                await _session.Socket.SendPacketAsync(CreateSetPacket("SaveIds", SaveIds));

                Log.Debug("Save Ids save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save Save Ids: {ex.Message}");
                throw;
            }
            finally
            {
                _saveItemSemaphore.Release();
            }
        }

        public async Task LoadSaveIdsAsync(CancellationToken cancellationToken = default)
        {
            Log.Verbose("Loading Save Ids");

            try
            {
                var (success, data) = await DeserializeFromStorageAsync<List<byte>>("SaveIds");
                if (success && data != null)
                {
                    SaveIds = data;

                    Log.Verbose($"Loaded SaveIds with {SaveIds} items");
                }
                else
                {
                    Log.Warning("No existing SaveIds found - creating new");
                    SaveIds = [];
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading SaveIds: {ex.Message}");
                SaveIds = [];
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
