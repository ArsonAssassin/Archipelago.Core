# Overlay

[← Back to README](../README.md)

The overlay service renders floating text popups over the game window using ImGui. Popups fade out after a configurable duration.

## Setup

```csharp
using Archipelago.Core.Util.Overlay;

var options = new OverlayOptions
{
    FontSize     = 18f,
    XOffset      = 100f,   // pixels from left of game window (default 100)
    YOffset      = 100f,   // pixels from top  of game window (default 100)
    FadeDuration = 10.0f,  // seconds before a popup fades out (default 10)
    DefaultTextColor = new Color(255, 255, 255)
};

var overlay = new WindowsOverlayService(options);
client.IntializeOverlayService(overlay);
```

`IntializeOverlayService` attaches the overlay window to the game's main window handle. The overlay follows the game window automatically.

## Adding messages

```csharp
// Plain text
client.AddOverlayMessage("Item received!");

// Rich text — coloured segments from an Archipelago LogMessage
client.AddRichOverlayMessage(logMessage);
```

`AddOverlayMessage` does nothing if the overlay has not been initialised, so it is safe to call unconditionally.

## Direct service access

If you need finer control, call the `IOverlayService` methods directly:

```csharp
// Plain text popup
overlay.AddTextPopup("Hello");

// Rich text popup
overlay.AddRichTextPopup(new List<ColoredTextSpan>
{
    new ColoredTextSpan { Text = "Player",  Color = new Color(255, 100, 100) },
    new ColoredTextSpan { Text = " found ", Color = new Color(255, 255, 255) },
    new ColoredTextSpan { Text = "Sword",   Color = new Color(100, 200, 255) }
});

// Reposition the overlay window
overlay.SetPosition(50f, 50f);
overlay.SetSize(400f, 300f);
overlay.SetSizeAndPosition(50f, 50f, 400f, 300f);
```

## Configuration file

Overlay defaults can be loaded from `config.ini` instead of being hardcoded:

```csharp
using Archipelago.Core.Util.Config;

var overlay = new WindowsOverlayService(AppConfig.Current.Overlay.ToOverlayOptions());
client.IntializeOverlayService(overlay);
```

See [Configuration](configuration.md) for the full list of overlay settings.

## Disposal

The overlay is disposed automatically when `ArchipelagoClient` is disposed. Call `overlay.Dispose()` directly if you manage its lifetime independently.

## See also

- [ArchipelagoClient](archipelago-client.md)
