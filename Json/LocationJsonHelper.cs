using Archipelago.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Archipelago.Core.Json
{
    public class LocationJsonHelper
    {
        private static LocationJsonHelper _instance;
        public static LocationJsonHelper Instance => _instance ??= new LocationJsonHelper();

        private readonly JsonSerializerOptions _options;

        public LocationJsonHelper()
        {
            _options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new LocationConverter() }
            };
        }

        public string SerializeLocation(ILocation location)
        {
            return JsonSerializer.Serialize(location, _options);
        }

        public string SerializeLocations(List<ILocation> locations)
        {
            return JsonSerializer.Serialize(locations, _options);
        }

        public ILocation DeserializeLocation(string json)
        {
            return JsonSerializer.Deserialize<ILocation>(json, _options);
        }

        public T DeserializeLocation<T>(string json) where T : ILocation
        {
            return JsonSerializer.Deserialize<T>(json, _options);
        }

        public List<ILocation> DeserializeLocations(string json)
        {
            return JsonSerializer.Deserialize<List<ILocation>>(json, _options);
        }
    }
}
