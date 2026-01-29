using Archipelago.Core.Models;
using Archipelago.MultiClient.Net;
using Archipelago.MultiClient.Net.Models;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public class ItemManager : IDisposable
    {
        private GameStateManager _gameStateManager;
        private bool isReadyToReceiveItems = false;
        private readonly SemaphoreSlim _receiveItemSemaphore = new SemaphoreSlim(1, 1);
        private Queue<ItemInfo> InProcessItems { get; set; }
        private Queue<ItemInfo> ItemsReceived { get; set; }
        public int itemsReceivedCurrentSession { get; set; }
        public event EventHandler<ItemReceivedEventArgs>? ItemReceived;

        public ItemManager(ref GameStateManager gameStateManager)
        {
            _gameStateManager = gameStateManager;
        }
        public void Initialize()
        {
            itemsReceivedCurrentSession = 0;
            ItemsReceived = [];
            InProcessItems = [];
        }
        internal async Task ReceiveItems(ArchipelagoSession currentSession, CancellationToken cancellationToken = default)
        {
            if (!isReadyToReceiveItems)
            {
                return;
            }
            if (_gameStateManager == null)
            {
                Log.Error("GameStateManager is null. Cannot receive items.");
            }
            cancellationToken = Helpers.CombineTokens(cancellationToken);
            await _receiveItemSemaphore.WaitAsync(cancellationToken);
            try
            {
                if (!isReadyToReceiveItems) /* in case it was set false while waiting */
                {
                    return;
                }
                Log.Logger.Debug("Attempting receive");
                await _gameStateManager.LoadItemIndexAsync(cancellationToken);

                bool receivedNewItems = false;

                ItemInfo newItemInfo = currentSession.Items.PeekItem();
                // move all items into the InProcessItems queue
                while (newItemInfo != null)
                {
                    InProcessItems.Enqueue(newItemInfo);
                    currentSession.Items.DequeueItem();
                    newItemInfo = currentSession.Items.PeekItem();
                }
                // for each item in the InProcessItems queue, try to process it.
                bool abletopeek = InProcessItems.TryPeek(out newItemInfo);
                Log.Logger.Debug($"able to peek? {abletopeek}");
                Log.Logger.Debug($"ircs={itemsReceivedCurrentSession}, sii={_gameStateManager.SavedItemIndex}");
                while (abletopeek && newItemInfo != null)
                {
                    if (!isReadyToReceiveItems) // In case switch is flipped while mid-receiving
                    {
                        return;
                    }
                    itemsReceivedCurrentSession++;
                    bool receiveSuccess = true;
                    if (itemsReceivedCurrentSession > _gameStateManager.SavedItemIndex)
                    {
                        var item = new Item
                        {
                            Id = newItemInfo.ItemId,
                            Name = newItemInfo.ItemName,
                        };
                        Log.Debug($"Adding new item {item.Name}");

                        var args = new ItemReceivedEventArgs()
                        {
                            Item = item,
                            LocationId = newItemInfo.LocationId,
                            Player = newItemInfo.Player,
                            Success = true  /* default to true - so game client can set it to false if it fails */
                        };
                        ItemReceived?.Invoke(this, args);
                        receiveSuccess = args.Success;

                        if (receiveSuccess)
                        {
                            _gameStateManager.SavedItemIndex++;
                            receivedNewItems = true;
                        }
                        else
                        {
                            itemsReceivedCurrentSession--; /* undo the earlier increment */
                            isReadyToReceiveItems = false;
                            Log.Verbose($"Unable to receive item: {item.Name}.");
                            /* Game client knows the item failed to receive, so they can reinitiate it when they want to. */
                            break; /* leave the dequeueing loop */
                        }
                    }
                    else
                    {
                        Log.Verbose($"Fast forwarding past previously received item {newItemInfo.ItemName}");
                    }

                    ItemsReceived.Enqueue(newItemInfo); // add it to the persistent list
                    InProcessItems.Dequeue(); // remove it from in process list
                    abletopeek = InProcessItems.TryPeek(out newItemInfo); // get next item
                }

                if (receivedNewItems)
                {
                    await _gameStateManager.SaveItemIndexAsync(cancellationToken);
                }
            }
            finally
            {
                _receiveItemSemaphore.Release();
            }
        }
        public async Task ForceReloadAllItems(CancellationToken cancellationToken = default)
        {
            if (_gameStateManager == null)
            {
                Log.Warning("Cannot reload items - gameStateManager is null");
                return;
            }

            _gameStateManager.SavedItemIndex = 0;
            await _gameStateManager.ForceSaveItemIndexAsync(cancellationToken);
        }
        public async Task ReceiveReady(ArchipelagoSession currentSession)
        {
            isReadyToReceiveItems = true;
            await ReceiveItems(currentSession);
        }
        public async Task StopReceiving()
        {
            isReadyToReceiveItems = false; // in case we were recieving items, stop.
            await _receiveItemSemaphore.WaitAsync(); // wait for receives to finish
            _receiveItemSemaphore.Release(); // release the semaphore immediately. The isReadyToReceive flag being false will prevent receives until we are done.
        }
        public async Task ResetItems()
        {
            // First, save in process queue to a backup
            Queue<ItemInfo> backup = InProcessItems;
            // Then, reset the in process queue to those already received.
            InProcessItems = ItemsReceived;

            // To the already received items, append the backed up "in process" ones. This maintains the queue order.
            while (backup.TryDequeue(out var item))
            {
                InProcessItems.Enqueue(item);
            }
            // Empty the ItemsReceived list, so it can start getting items again.
            ItemsReceived = new Queue<ItemInfo>();
            Log.Logger.Debug($"IPI queue has {InProcessItems.Count} items");
            Log.Logger.Debug($"IR queue has {ItemsReceived.Count} items");

            // start from receiving "item 0" again
            itemsReceivedCurrentSession = 0;
        }

        public void Dispose()
        {
            _receiveItemSemaphore?.Dispose();
        }
    }
}
