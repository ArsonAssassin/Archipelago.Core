using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Models
{
    public class GameState
    {
        public GameState()
        {
            CompletedLocations = new ConcurrentQueue<ILocation>();
            ReceivedItems = new ConcurrentQueue<Item>();
        }
        
        public ConcurrentQueue<ILocation> CompletedLocations { get; set; }
        public ConcurrentQueue<Item> ReceivedItems { get; set; }
        public int LastCheckedIndex { get; set; }
    }
}
