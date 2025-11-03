using ImGuiNET;
using Silk.NET.Maths;
using Silk.NET.OpenGL;
using Silk.NET.Windowing;
using Silk.NET.Input;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Overlay
{
    public class SilkOverlayService : IOverlayService
    {
        private IWindow? _window;
        private GL? _gl;
        private ImGuiController? _imguiController;

        private readonly ConcurrentDictionary<Guid, Popup> _popups = new();
        private IntPtr _targetWindowHandle;
        private bool _isDisposed = false;
        private bool _isRunning = false;

        // Options
        private float _fontSize = 14;
        private IColor _textColor = Color.White;
        private float _xOffset = 100;
        private float _yOffset = 100;
        private float _fadeDuration = 10.0f;

        private Vector4 _defaultTextColor;
        private uint _frameCounter = 0;

        public SilkOverlayService(OverlayOptions options = null)
        {
            if (options != null)
            {
                if (options.FontSize != 0) _fontSize = options.FontSize;
                if (options.TextColor != null) _textColor = options.TextColor;
                _xOffset = options.XOffset;
                _yOffset = options.YOffset;
                _fadeDuration = options.FadeDuration;
            }

            _defaultTextColor = new Vector4(
                _textColor.R / 255f,
                _textColor.G / 255f,
                _textColor.B / 255f,
                _textColor.A / 255f
            );
        }

        public bool AttachToWindow(IntPtr targetWindowHandle)
        {
            if (_isRunning) return false;

            _targetWindowHandle = targetWindowHandle;

            // Start overlay on background thread
            Task.Run(() => InitializeAndRun());

            return true;
        }

        private void InitializeAndRun()
        {
            var options = WindowOptions.Default;
            options.Size = new Vector2D<int>(800, 600);
            options.Title = "Overlay";
            options.WindowBorder = WindowBorder.Hidden;
            options.TransparentFramebuffer = true;
            options.IsVisible = true;
            options.TopMost = true;
            options.WindowState = WindowState.Normal;

            // Create the window
            _window = Window.Create(options);

            _window.Load += OnLoad;
            _window.Render += OnRender;
            _window.Closing += OnClosing;
            _window.Resize += OnResize;

            _isRunning = true;
            _window.Run();
        }

        private void OnLoad()
        {
            _gl = _window!.CreateOpenGL();
            var input = _window.CreateInput();
            _imguiController = new ImGuiController(_gl, _window, input);

            // Configure ImGui for overlay
            var io = ImGui.GetIO();
            io.ConfigFlags |= ImGuiConfigFlags.NoMouseCursorChange;

            // Make window click-through on supported platforms
            MakeWindowTransparent();
        }

        private void MakeWindowTransparent()
        {
            // Platform-specific transparency setup
            if (OperatingSystem.IsWindows())
            {
                MakeWindowTransparentWindows();
            }
            else if (OperatingSystem.IsLinux())
            {
                MakeWindowTransparentLinux();
            }
        }

        private void MakeWindowTransparentWindows()
        {
            // Windows-specific: Set WS_EX_LAYERED and WS_EX_TRANSPARENT
            // This requires P/Invoke to user32.dll
            try
            {
                const int GWL_EXSTYLE = -20;
                const uint WS_EX_LAYERED = 0x80000;
                const uint WS_EX_TRANSPARENT = 0x20;

                var handle = _window!.Native!.Win32!.Value.Hwnd;
                var extendedStyle = GetWindowLong(handle, GWL_EXSTYLE);
                SetWindowLong(handle, GWL_EXSTYLE, extendedStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT);
            }
            catch { /* Ignore if P/Invoke fails */ }
        }

        private void MakeWindowTransparentLinux()
        {
            // Linux (X11): Set window type to desktop/notification
            // This is handled by window manager and Silk.NET settings
            // TransparentFramebuffer option should handle most cases
        }

        private void OnRender(double deltaTime)
        {
            if (_isDisposed || _imguiController == null || _gl == null)
                return;

            _gl.Clear(ClearBufferMask.ColorBufferBit);

            _imguiController.Update((float)deltaTime);

            RenderOverlay();

            _imguiController.Render();
        }

        private void RenderOverlay()
        {
            _frameCounter++;

            var now = DateTime.Now;
            var activePopups = _popups.Values
                .Where(p =>
                {
                    if (p is TextPopup tp) return tp.ExpireTime >= now;
                    if (p is RichTextPopup rp) return rp.ExpireTime >= now;
                    return false;
                })
                .OrderByDescending(p =>
                {
                    if (p is TextPopup tp) return tp.ExpireTime;
                    if (p is RichTextPopup rp) return rp.ExpireTime;
                    return DateTime.MinValue;
                })
                .Take(10)
                .ToList();

            if (!activePopups.Any())
                return;

            // Transparent background window
            ImGui.SetNextWindowPos(new Vector2(_xOffset, _yOffset));
            ImGui.SetNextWindowBgAlpha(0.0f);

            ImGui.Begin("Popups",
                ImGuiWindowFlags.NoDecoration |
                ImGuiWindowFlags.NoInputs |
                ImGuiWindowFlags.NoNav |
                ImGuiWindowFlags.NoBackground |
                ImGuiWindowFlags.NoMove);

            var yOffset = 0f;
            foreach (var popup in activePopups)
            {
                ImGui.SetCursorPos(new Vector2(0, yOffset));

                if (popup is TextPopup textPopup)
                {
                    RenderTextPopup(textPopup, now);
                }
                else if (popup is RichTextPopup richPopup)
                {
                    RenderRichTextPopup(richPopup, now);
                }

                yOffset += _fontSize + 3;
            }

            ImGui.End();
        }

        private void RenderTextPopup(TextPopup popup, DateTime now)
        {
            var opacity = CalculateOpacity(popup.ExpireTime, popup.Duration, now);
            var color = new Vector4(
                _defaultTextColor.X,
                _defaultTextColor.Y,
                _defaultTextColor.Z,
                _defaultTextColor.W * opacity
            );

            ImGui.PushStyleColor(ImGuiCol.Text, color);
            ImGui.Text(popup.Text);
            ImGui.PopStyleColor();
        }

        private void RenderRichTextPopup(RichTextPopup popup, DateTime now)
        {
            var opacity = CalculateOpacity(popup.ExpireTime, popup.Duration, now);

            bool first = true;
            foreach (var span in popup.Spans)
            {
                if (!first)
                {
                    ImGui.SameLine(0, 0);
                }

                var color = span.ToVector4();
                color.W *= opacity;

                ImGui.PushStyleColor(ImGuiCol.Text, color);
                ImGui.Text(span.Text);
                ImGui.PopStyleColor();

                first = false;
            }
        }

        private float CalculateOpacity(DateTime expireTime, float duration, DateTime now)
        {
            var elapsed = (now - expireTime.AddSeconds(-duration)).TotalSeconds;
            var fadeStartTime = duration * 0.75;

            if (elapsed >= fadeStartTime)
            {
                var fadeProgress = (elapsed - fadeStartTime) / (duration - fadeStartTime);
                return Math.Max(0, 1.0f - (float)fadeProgress);
            }

            return 1.0f;
        }

        private void OnResize(Vector2D<int> size)
        {
            if (_gl != null)
            {
                _gl.Viewport(size);
            }

            if (_imguiController != null)
            {
                _imguiController.WindowResized(size.X, size.Y);
            }
        }

        private void OnClosing()
        {
            _imguiController?.Dispose();
            _gl?.Dispose();
        }

        public void Show()
        {
        }

        public void Hide()
        {
        }

        public void AddTextPopup(string text)
        {
            if (_isDisposed) return;

            var id = Guid.NewGuid();
            var popup = new TextPopup
            {
                Text = text,
                ExpireTime = DateTime.Now.AddSeconds(_fadeDuration),
                Opacity = 1.0f,
                Duration = _fadeDuration
            };

            _popups[id] = popup;
            ScheduleRemoval(id, _fadeDuration);
        }

        public void AddRichTextPopup(List<ColoredTextSpan> spans)
        {
            if (_isDisposed) return;

            var id = Guid.NewGuid();
            var popup = new RichTextPopup
            {
                Spans = spans,
                ExpireTime = DateTime.Now.AddSeconds(_fadeDuration),
                Opacity = 1.0f,
                Duration = _fadeDuration
            };

            _popups[id] = popup;
            ScheduleRemoval(id, _fadeDuration);
        }

        private void ScheduleRemoval(Guid id, float duration)
        {
            Task.Delay(TimeSpan.FromMilliseconds(duration * 1000))
                .ContinueWith(_ =>
                {
                    if (!_isDisposed)
                    {
                        _popups.TryRemove(id, out var popup);
                    }
                });
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            _popups.Clear();
            _window?.Close();
            _isRunning = false;

            GC.SuppressFinalize(this);
        }

        #region Windows P/Invoke for transparency
        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowLong(IntPtr hWnd, int nIndex);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, uint dwNewLong);
        #endregion
    }

    // Helper classes (same as before)
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
