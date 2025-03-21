# Guide to Using Archipelago NuGet Packages for Game Emulator Integration
# Table of Contents

Introduction
Available Packages
Installation
Basic Usage
Connecting to an AP Server
Location Tracking
Advanced Features

## Introduction
This guide covers the usage of Archipelago NuGet packages for integrating game emulators with the Archipelago Multiworld Randomizer. These packages allow developers to create new "APWorlds," enabling the implementation of new games for Archipelago.
## Available Packages

 - Archipelago.Core: Contains most of the core functionality
 - Archipelago.MauiGUI: Contains a GUI interface written in MAUI.

## Installation

Install the Archipelago.Core NuGet package OR Install the MauiGui package directly (Which contains the Core package)

## Basic Usage
### Creating a Game Client
```
var gameClient = new ePSXeClient();
gameClient.Connect();
```  
### Creating an Archipelago Client
```
var archipelagoClient = new ArchipelagoClient(gameClient);
```  
### Using Memory Functions
```var money = Memory.ReadInt(0x00000000);
Memory.WriteString(0x00000000, "Hello World");
```  

### Connecting to an AP Server
```
archipelagoClient.Connect("archipelago.gg:12345", "GameName");
archipelagoClient.Login("Player1", "Password");
```  
### Location Tracking
To set up location tracking:

Create a collection of Location objects
Call MonitorLocations after connecting:

``` 
archipelagoClient.MonitorLocations(myLocations);
 ```  

## Location Object Properties

 - ulong address: The address that changes when the location is completed
 - int addressbit: Which bit of this address is related to this specific location (only used when LocationCheckType == Bit)
 - string name: The name of the location
 - int id: The id of the location in the apworld
 - LocationCheckType CheckType: The data type of the location check (supports Bit, Int, Uint, Byte)
 - string CheckValue: The value to compare to determine if the location check is met
 - LocationCheckCompareType CompareType: The comparison type for the location check (supports Match, GreaterThan, LessThan, Range)

## Other Features

The client will trigger the ItemReceived event when an item is received.
Ensure location tracking setup is done after connecting the Archipelago client but before logging in the user.

To handle all messages, suscribe to ArchipelagoClient.MessageReceived  
To complete a game, call ArchipelagoClient.SendGoalCompletion();  

# Custom Game Client
If you are working with a game that does not use one of the included emulators, you can access memory of a custom exe by creating an instance of IGameClient.
```
public class MyGameClient : IGameClient
{
   public bool IsConnected{get;set;}
   public int ProcId{get;set;} = Memory.GetProcIdFromExe("myExeName");
   public MyGameClient(){}
   public bool Connect()
   {
      Console.WriteLine("Connecting");
      if(ProcId == 0)
      {
         Console.WriteLine("Process not running");
         return false;
      }
      else
      {
         IsConnected = true;
         return true;
      }
   }
}
```
