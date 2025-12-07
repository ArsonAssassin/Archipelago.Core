using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Models
{
    public class LocationState
    {
        public LocationState()
        {
            CompletedLocations = new ConcurrentQueue<ILocation>();
        }
        
        public ConcurrentQueue<ILocation> CompletedLocations { get; set; }
    }
}
