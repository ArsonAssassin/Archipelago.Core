using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Archipelago.MultiClient.Net.Helpers;

namespace Archipelago.Core.Models
{
    public class ItemReceivedEventArgs : EventArgs
    {
        public Item Item { get; set; }
        public long LocationId { get; set; }
        public PlayerInfo Player { get; set; }
        public bool Success { get; set; }
    }
}
