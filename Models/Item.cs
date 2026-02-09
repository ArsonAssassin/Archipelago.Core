using Archipelago.MultiClient.Net.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Models
{
    public class Item : INotifyPropertyChanged
    {
        private string name;
        private string category;
        private long id;
        private bool isProgression;
        public ItemFlags flags;
        public string Name
        {
            get => name;
            set
            {
                if (name != value)
                {
                    name = value;
                    OnPropertyChanged();
                }
            }
        }
        public string Category
        {
            get => category;
            set
            {
                if (category != value)
                {
                    category = value;
                    OnPropertyChanged();
                }
            }
        }
        public long Id
        {
            get => id;
            set
            {
                if (id != value)
                {
                    id = value;
                    OnPropertyChanged();
                }
            }
        }
        public bool IsProgression
        {
            get => ((flags & ItemFlags.Advancement) != 0);
        }
        public bool IsUseful
        {
            get => ((flags & ItemFlags.NeverExclude) != 0);
        }
        public bool IsTrap
        {
            get => ((flags & ItemFlags.Trap) != 0);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        public void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
