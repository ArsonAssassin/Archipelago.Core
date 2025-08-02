﻿using Archipelago.MultiClient.Net.Models;
using GameOverlay.Drawing;
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
        void Show();
        void Hide();
        void AddTextPopup(string text);
        Font CreateFont(string fontName, int size);
    }
}
