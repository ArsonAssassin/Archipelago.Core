using Archipelago.Core.Models;
using Archipelago.MultiClient.Net;
using System;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public interface IItemManager : IDisposable
    {
        int ItemsReceivedCurrentSession { get; set; }
        event EventHandler<ItemReceivedEventArgs>? ItemReceived;

        void Initialize();
        Task ForceReloadAllItems(CancellationToken cancellationToken = default);
        Task ReceiveReady(ArchipelagoSession currentSession);
        Task StopReceiving();
        Task ResetItems();
    }
}
