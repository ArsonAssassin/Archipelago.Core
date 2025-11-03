using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Overlay
{
    public class OverlayOptions
    {
        public IColor DefaultTextColor { get; set; }
        public float FontSize { get; set; }
        public float XOffset { get; set; } = 100;
        public float YOffset { get; set; } = 100;
        public float FadeDuration = 10.0f;
    }
}
