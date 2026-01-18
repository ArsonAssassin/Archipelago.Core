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

        private readonly SemaphoreSlim _saveItemSemaphore = new SemaphoreSlim(1, 1);

        public int SavedItemIndex { get; set; }
        public Dictionary<string, object> CustomValues { get; private set; }

        public GameStateManager(ArchipelagoSession session, string gameName, string seed, int slot)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _gameName = gameName ?? throw new ArgumentNullException(nameof(gameName));
            _seed = seed ?? throw new ArgumentNullException(nameof(seed));
            _slot = slot;

            CustomValues = new Dictionary<string, object>();
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

                await _session.Socket.SendPacketAsync(CreateSetPacket("ItemIndex", SavedItemIndex));

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
                var (success, data) = await DeserializeFromStorageAsync<int>("ItemIndex");
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
