# Configuration

[← Back to README](../README.md)

`AppConfig` provides INI-based configuration loaded from a `config.ini` file next to the executable. If the file does not exist on first access, it is created automatically with default values.

## Default config.ini

```ini
[Logging]
LogLevel=Information

[Connection]
Host=archipelago.gg
Slot=
Password=

[Overlay]
XOffset=100
YOffset=100
FontSize=14
FadeDuration=10
DefaultTextColorR=255
DefaultTextColorG=255
DefaultTextColorB=255
DefaultTextColorA=255
```

## Loading config

```csharp
using Archipelago.Core.Util.Config;

var config = AppConfig.Current; // lazy-loads from config.ini next to the .exe
```

`AppConfig.Current` is a thread-safe singleton. The first access parses the file (or creates it with defaults if missing). Subsequent accesses return the cached instance.

### Custom file path

To load from a different location, call `SetFilePath` before any access to `Current`:

```csharp
AppConfig.SetFilePath(@"C:\MyApp\settings.ini");
var config = AppConfig.Current; // loads from the custom path
```

### Explicit load / reload

```csharp
// Load from a specific path (replaces the singleton)
var config = AppConfig.Load(@"C:\MyApp\settings.ini");

// Re-read the file into the existing instance
AppConfig.Current.Reload();
```

## Reading settings

### Logging

```csharp
LogEventLevel level = AppConfig.Current.Logging.LogLevel;
```

### Connection

```csharp
string host     = AppConfig.Current.Connection.Host;
string slot     = AppConfig.Current.Connection.Slot;
string password = AppConfig.Current.Connection.Password;
```

### Overlay

```csharp
float xOffset      = AppConfig.Current.Overlay.XOffset;
float yOffset      = AppConfig.Current.Overlay.YOffset;
float fontSize     = AppConfig.Current.Overlay.FontSize;
float fadeDuration = AppConfig.Current.Overlay.FadeDuration;

// Create an OverlayOptions instance directly from config
var overlay = new WindowsOverlayService(AppConfig.Current.Overlay.ToOverlayOptions());
```

## Modifying and saving

Section properties have public setters. Call `Save()` to write the current state back to the INI file:

```csharp
AppConfig.Current.Connection.Host = "localhost:38281";
AppConfig.Current.Connection.Slot = "Player1";
AppConfig.Current.Logging.LogLevel = LogEventLevel.Debug;
AppConfig.Current.Save();
```

## Custom sections

Consumer developers can register their own config sections so game-specific settings live in the same `config.ini`.

### Registering a section

Provide a loader (parses raw key-value pairs into your type) and a serializer (converts back for saving):

```csharp
AppConfig.Current.RegisterSection<MyGameConfig>(
    "MyGame",
    raw =>
    {
        var cfg = new MyGameConfig();
        if (raw.TryGetValue("Difficulty", out var d))
            cfg.Difficulty = d;
        if (raw.TryGetValue("MaxLives", out var ml) && int.TryParse(ml, out var v))
            cfg.MaxLives = v;
        return cfg;
    },
    cfg => new Dictionary<string, string>
    {
        ["Difficulty"] = cfg.Difficulty,
        ["MaxLives"] = cfg.MaxLives.ToString()
    }
);
```

This reads the `[MyGame]` section from the INI file immediately. If the section does not exist, the loader receives an empty dictionary and your defaults apply.

### Retrieving a section

```csharp
var myConfig = AppConfig.Current.GetSection<MyGameConfig>("MyGame");
```

Returns `null` if the section has not been registered.

### Raw access

For quick lookups without a typed class:

```csharp
var raw = AppConfig.Current.GetRawSection("MyGame");
// raw is Dictionary<string, string>? — null if the section doesn't exist in the file
```

### Saving custom sections

Registered sections are included automatically when you call `Save()`. Unregistered sections in the file are not preserved — only built-in and registered sections are written.

## See also

- [Overlay](overlay.md) — `OverlayConfig.ToOverlayOptions()`
- [PlatformMemory](platform-memory.md) — elevation detection
