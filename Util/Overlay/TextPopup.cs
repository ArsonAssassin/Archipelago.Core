using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
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
    public class ColoredTextSpan
    {
        public string Text { get; set; }
        public IColor Color { get; set; }

        internal Vector4 ToVector4()
        {
            return new Vector4(
                Color.R / 255f,
                Color.G / 255f,
                Color.B / 255f,
                Color.A / 255f
            );
        }
    }
}
