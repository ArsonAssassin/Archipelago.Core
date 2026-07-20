# Death Link

[← Back to README](../README.md)

Death Link synchronises player deaths across the multiworld. When one participating player dies, all other Death Link participants die too.

## Setup

Call `EnableDeathLink` after `Login`:

```csharp
var deathLink = client.EnableDeathLink();
```

This creates and enables the underlying `DeathLinkService` from `Archipelago.MultiClient.Net`.

## Receiving deaths

```csharp
deathLink.OnDeathLinkReceived += (sender, deathLinkObject) =>
{
    Console.WriteLine($"Death received from {deathLinkObject.Source}: {deathLinkObject.Cause}");
    KillPlayer();
};
```

## Sending deaths

```csharp
deathLink.SendDeathLink(new DeathLink("PlayerName", "Walked off a cliff"));
```

The `Cause` string is optional and appears in chat.

## Disabling

```csharp
deathLink.DisableDeathLink();
```

## See also

- [ArchipelagoClient](archipelago-client.md)
