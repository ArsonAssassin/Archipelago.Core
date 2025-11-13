using Archipelago.MultiClient.Net.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Overlay
{
    public interface IOverlayService : IDisposable
    {
        bool AttachToWindow(IntPtr targetWindowHandle);
        void AddTextPopup(string text);
        void AddRichTextPopup(List<ColoredTextSpan> spans);

    }
}
