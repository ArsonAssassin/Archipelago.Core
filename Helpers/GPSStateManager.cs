using Archipelago.Core.Util.GPS;
using Archipelago.MultiClient.Net;
using Archipelago.MultiClient.Net.Enums;
using Archipelago.MultiClient.Net.Models;
using Archipelago.MultiClient.Net.Packets;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class GPSStateManager
    {
        private readonly ArchipelagoSession _session;
        private readonly string _gameName;
        private readonly string _seed;
        private readonly int _slot;
        private GPSHandler? _gpsHandler;

        public GPSStateManager(ArchipelagoSession session, string gameName, string seed, int slot)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _gameName = gameName ?? throw new ArgumentNullException(nameof(gameName));
            _seed = seed ?? throw new ArgumentNullException(nameof(seed));
            _slot = slot;
        }

        public GPSHandler? Handler
        {
            get => _gpsHandler;
            set
            {
                if (_gpsHandler != null)
                {
                    _gpsHandler.PositionChanged -= OnPositionChanged;
                    _gpsHandler.MapChanged -= OnMapChanged;
                }

                _gpsHandler = value;

                if (_gpsHandler != null)
                {
                    _gpsHandler.PositionChanged += OnPositionChanged;
                    _gpsHandler.MapChanged += OnMapChanged;
                }
            }
        }

        private void OnPositionChanged(object? sender, PositionChangedEventArgs e)
        {
            _ = SaveAsync(); 
        }

        private void OnMapChanged(object? sender, MapChangedEventArgs e)
        {
            _ = SaveAsync(); 
        }

        public async Task SaveAsync(CancellationToken cancellationToken = default)
        {
            if (_gpsHandler == null)
            {
                Log.Debug("Cannot save GPS - handler is null");
                return;
            }

            try
            {
                Log.Debug("Saving GPS state");
                var packet = CreateSetPacket("GPS", _gpsHandler.GetCurrentPosition());
                await _session.Socket.SendPacketAsync(packet);
                Log.Debug("GPS save completed");
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to save GPS state: {ex.Message}");
            }
        }

        private SetPacket CreateSetPacket<T>(string key, T value)
        {
            return new SetPacket()
            {
                Key = $"{_gameName}_{_slot}_{_seed}_{key}",
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

        public void Dispose()
        {
            if (_gpsHandler != null)
            {
                _gpsHandler.PositionChanged -= OnPositionChanged;
                _gpsHandler.MapChanged -= OnMapChanged;
            }
        }
    }
}
