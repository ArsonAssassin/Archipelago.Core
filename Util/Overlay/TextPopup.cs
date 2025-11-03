using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Overlay
{
    public class Popup
    {

        public DateTime ExpireTime { get; set; }
        public float Opacity { get; set; } = 1.0f;
        public float Duration { get; set; } = 10.0f;
    }
    public class TextPopup : Popup
    {
        public string Text { get; set; }
    }
    public class RichTextPopup : Popup
    {
        public List<ColoredTextSpan> Spans { get; set; } = new();
    }
}
