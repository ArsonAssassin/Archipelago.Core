using GameOverlay.Drawing;
using GameOverlay.Windows;
using SharpDX.DirectWrite;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Overlay
{
    public class WindowsOverlayService : IOverlayService
    {
        private readonly StickyWindow _window;
        private readonly ConcurrentDictionary<Guid, TextPopup> _popups = new ConcurrentDictionary<Guid, TextPopup>();

        private Graphics _gfx;
        private bool _isInitialized = false;
        private bool _isDisposed = false;
        private IntPtr _targetWindowHandle;
        private float _fontSize = 14;
        private IColor _textColor = Color.White;
        private float _xOffset = 100;
        private float _yOffset = 100;
        private SolidBrush _brush;
        private float _fadeDuration = 10.0f;
        private uint _frameCounter = 0;
        private const uint Z_ORDER_REFRESH_INTERVAL = 30;
        private GameOverlay.Drawing.Font _selectedFont;
        public WindowsOverlayService(OverlayOptions options = null)
        {
            if (options != null)
            {
                if (options.FontSize != 0) _fontSize = options.FontSize;
                if (options.TextColor != null) _textColor = options.TextColor;
                if (options.Font != null) _selectedFont = options.Font;
                _xOffset = options.XOffset;
                _yOffset = options.YOffset;
                _fadeDuration = options.FadeDuration;

            }
            // Create overlay window (initially hidden)
            _window = new StickyWindow(0, 0, 800, 600);

            // Configure window properties
            _window.IsTopmost = true;
            _window.IsVisible = false;
            _window.FPS = 30; // Update frequency

            // Setup rendering callback
            _window.DrawGraphics += OnDrawGraphics;
            _window.SetupGraphics += OnSetupGraphics;
            _window.DestroyGraphics += OnDestroyGraphics;

            // Create the window (but keep it hidden)
            _window.Create();
        }

        public bool AttachToWindow(IntPtr targetWindowHandle)
        {
            if (targetWindowHandle == IntPtr.Zero)
                return false;

            _targetWindowHandle = targetWindowHandle;
            _window.PlaceAbove(targetWindowHandle);
            return true;
        }

        public void Show()
        {
            if (_isDisposed) return;
            _window.Show();
        }

        public void Hide()
        {
            if (_isDisposed) return;
            _window.Hide();
        }

        public void AddTextPopup(string text)
        {
            if (_isDisposed || !_isInitialized) return;
            // Create a unique ID for this popup
            var id = Guid.NewGuid();

            // Create the popup
            var popup = new TextPopup
            {
                Text = text,
                ExpireTime = DateTime.Now.AddSeconds(_fadeDuration),
                Opacity = 1.0f,
                Duration = _fadeDuration
            };

            // Add to active popups
            _popups[id] = popup;

            // Remove after expiration
            Task.Delay(TimeSpan.FromMilliseconds(_fadeDuration * 1000))
                .ContinueWith(_ =>
                {
                    if (_isDisposed) return;
                    _popups.TryRemove(id, out var ignore);
                });
        }

        private void OnSetupGraphics(object sender, SetupGraphicsEventArgs e)
        {
            _gfx = e.Graphics;
            // Initialize resources once we have graphics
            if (!_isInitialized)
            {
                if (_selectedFont == null)
                {
                   _selectedFont = _gfx.CreateFont("Arial", _fontSize);
                }

                var color = new GameOverlay.Drawing.Color(
                    _textColor.R,
                    _textColor.G,
                    _textColor.B,
                    _textColor.A
                );
                _brush = _gfx.CreateSolidBrush(color);

                _isInitialized = true;
            }
        }


        private void OnDrawGraphics(object sender, DrawGraphicsEventArgs e)
        {
            _frameCounter++;

            // Periodically refresh z-order to ensure overlay stays above target window
            if (_targetWindowHandle != IntPtr.Zero &&
                _frameCounter % Z_ORDER_REFRESH_INTERVAL == 0)
            {
                try
                {
                    // Refresh the z-order positioning
                    _window.PlaceAbove(_targetWindowHandle);
                }
                catch
                {
                    // If PlaceAbove fails, the target window might be invalid
                    // Could add logging here if needed
                }
            }

            // Update window position in case target window moved
            if (_targetWindowHandle != IntPtr.Zero)
            {
                try
                {
                    GameOverlay.Windows.WindowHelper.GetWindowBounds(_targetWindowHandle, out var rect);
                    _window.X = rect.Left;
                    _window.Y = rect.Top;
                    _window.Width = rect.Right - rect.Left;
                    _window.Height = rect.Bottom - rect.Top;
                }
                catch { /* Ignore errors if window is closed */ }
            }

            // Clear the scene with transparency
            e.Graphics.ClearScene();

            // Get the current time once for all popups
            var now = DateTime.Now;
            var index = 0;

            var activePopups = _popups.Values
        .Where(p => p.ExpireTime >= now)
        .OrderByDescending(p => p.ExpireTime)
        .Take(10);

            // Draw active popups
            foreach (var popup in activePopups)
            {
                if (popup.ExpireTime < now)
                    continue;
                // Get or create font

                var elapsed = (now - popup.ExpireTime.AddSeconds(-popup.Duration)).TotalSeconds;
                var fadeStartTime = popup.Duration * 0.75;
                if (elapsed >= fadeStartTime)
                {
                    var fadeProgress = (elapsed - fadeStartTime) / (popup.Duration - fadeStartTime);
                    popup.Opacity = Math.Max(0, 1.0f - (float)fadeProgress);
                }
                popup.Font = _selectedFont;
                popup.Brush = _brush;

                // Draw the text with current opacity
                GameOverlay.Drawing.Color originalColor = popup.Brush.Color;
                popup.Brush.Color = new GameOverlay.Drawing.Color(
                    originalColor.R,
                    originalColor.G,
                    originalColor.B,
                    originalColor.A * popup.Opacity
                );
                
                e.Graphics.DrawText(_selectedFont, popup.Brush, _xOffset, _yOffset - (index * (_fontSize + 3)), popup.Text);
                _brush.Color = originalColor;
                index++;
            }
        }

        private void OnDestroyGraphics(object sender, DestroyGraphicsEventArgs e)
        {
            _brush?.Dispose();
            _isInitialized = false;
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            _popups.Clear();
            _window.Dispose();

            GC.SuppressFinalize(this);
        }


    }
}
