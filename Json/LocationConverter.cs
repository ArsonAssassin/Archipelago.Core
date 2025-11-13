using Archipelago.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Archipelago.Core.Json
{
    internal class LocationConverter : JsonConverter<ILocation>
    {
        public override ILocation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var root = jsonDoc.RootElement;

            if (root.ValueKind == JsonValueKind.Null)
                return null;

            // Detect the CheckType property
            if (root.TryGetProperty("CheckType", out var checkTypeElement))
            {
                LocationCheckType checkType;

                // Handle both string and number representations
                if (checkTypeElement.ValueKind == JsonValueKind.Number)
                {
                    checkType = (LocationCheckType)checkTypeElement.GetInt32();
                }
                else if (checkTypeElement.ValueKind == JsonValueKind.String)
                {
                    if (!Enum.TryParse<LocationCheckType>(checkTypeElement.GetString(), out checkType))
                    {
                        // Fallback if parse fails
                        return JsonSerializer.Deserialize<Location>(root.GetRawText(), options);
                    }
                }
                else
                {
                    // Fallback for unexpected types
                    return JsonSerializer.Deserialize<Location>(root.GetRawText(), options);
                }

                // Determine which type to deserialize based on CheckType
                if (checkType == LocationCheckType.AND || checkType == LocationCheckType.OR)
                {
                    return JsonSerializer.Deserialize<CompositeLocation>(root.GetRawText(), options);
                }
                else
                {
                    return JsonSerializer.Deserialize<Location>(root.GetRawText(), options);
                }
            }

            // Fallback: default to Location
            return JsonSerializer.Deserialize<Location>(root.GetRawText(), options);
        }

        public override void Write(Utf8JsonWriter writer, ILocation value, JsonSerializerOptions options)
        {
            switch (value)
            {
                case CompositeLocation composite:
                    JsonSerializer.Serialize(writer, composite, options);
                    break;
                case Location location:
                    JsonSerializer.Serialize(writer, location, options);
                    break;
                default:
                    throw new JsonException($"Unexpected ILocation type: {value.GetType()}");
            }
        }
    }


}
