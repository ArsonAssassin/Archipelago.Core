using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Models
{
    public class ItemState
    {
        public ItemState()
        {
            ReceivedItems = new ConcurrentQueue<Item>();
        }
        public ConcurrentQueue<Item> ReceivedItems { get; set; }
        public int LastCheckedIndex { get; set; }
		public string SaveId { get; set; }
    }
}
