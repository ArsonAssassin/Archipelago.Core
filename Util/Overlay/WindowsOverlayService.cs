using ImGuiNET;
using Silk.NET.Input;
using Silk.NET.Maths;
using Silk.NET.OpenGL;
using Silk.NET.Windowing;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace Archipelago.Core.Util.Overlay
{
    public class WindowsOverlayService : IOverlayService
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

        private System.Timers.Timer? _windowMonitorTimer;
        public WindowsOverlayService(OverlayOptions options = null)
        {
            if (options != null)
            {
                if (options.FontSize != 0) _fontSize = options.FontSize;
                if (options.DefaultTextColor != null) _textColor = options.DefaultTextColor;
                _xOffset = options.XOffset;
                _yOffset = options.YOffset;
                _fadeDuration = options.FadeDuration;
            }

        }

        public bool AttachToWindow(IntPtr targetWindowHandle)
        {
            if (_isRunning) return false;

            _targetWindowHandle = targetWindowHandle;


            StartWindowMonitoring();


            // Start overlay on background thread
            Task.Run(() => InitializeAndRun());

            return true;
        }
        private void StartWindowMonitoring()
        {
            _windowMonitorTimer = new System.Timers.Timer(100); // Check every 100ms
            _windowMonitorTimer.Elapsed += (o, e)=> UpdateOverlayPositionAndZOrder();
            _windowMonitorTimer.Start();
        }


        private void UpdateOverlayPositionAndZOrder()
        {
            if (_targetWindowHandle == IntPtr.Zero || _window?.Native?.Win32 == null)
                return;

            if (GetWindowRect(_targetWindowHandle, out RECT rect))
            {
                var handle = _window.Native!.Win32!.Value.Hwnd;

                // First ensure transparency is maintained
                const int GWL_EXSTYLE = -20;
                const int GWL_STYLE = -16;
                const uint WS_EX_LAYERED = 0x80000;
                const uint WS_EX_TRANSPARENT = 0x20;
                const uint WS_EX_NOACTIVATE = 0x08000000;
                const uint WS_EX_TOOLWINDOW = 0x00000080;
                const uint WS_POPUP = 0x80000000;
                const uint WS_VISIBLE = 0x10000000;

                const int GWLP_HWNDPARENT = -8;

                SetWindowLongPtr(handle, GWLP_HWNDPARENT, _targetWindowHandle);
                SetWindowLong(handle, GWL_STYLE, WS_POPUP | WS_VISIBLE);

                var extendedStyle = GetWindowLong(handle, GWL_EXSTYLE);
                SetWindowLong(handle, GWL_EXSTYLE,
                    extendedStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT |
                    WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW);

                // Now position overlay directly above target window in z-order
                SetWindowPos(handle, _targetWindowHandle,
                    rect.Left, rect.Top,
                    rect.Right - rect.Left, rect.Bottom - rect.Top,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            }
        }


        private void InitializeAndRun()
        {
            var options = WindowOptions.Default;
            options.Size = new Vector2D<int>(800, 600);
            options.Title = "Overlay";
            options.WindowBorder = WindowBorder.Hidden;
            options.TransparentFramebuffer = true;
            options.IsVisible = false; // Start invisible, show after setup
            options.TopMost = true;
            options.WindowState = WindowState.Normal;
            options.ShouldSwapAutomatically = true;

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

            // Don't create input context - we don't want any input
            _imguiController = new ImGuiController(_gl, _window, null);

            // Configure ImGui for overlay
            var io = ImGui.GetIO();
            io.ConfigFlags |= ImGuiConfigFlags.NoMouseCursorChange | ImGuiConfigFlags.NoMouse | ImGuiConfigFlags.NoKeyboard | ImGuiConfigFlags.None;

            // Make window completely non-interactive BEFORE showing it
            MakeWindowTransparent();

            // Small delay to ensure styles are applied
            Task.Delay(100).ContinueWith(_ =>
            {
                _window.IsVisible = true;
            });
        }

        private void MakeWindowTransparent()
        {
            try
            {
                const int GWL_EXSTYLE = -20;
                const int GWL_STYLE = -16;
                const uint WS_EX_LAYERED = 0x80000;
                const uint WS_EX_TRANSPARENT = 0x20;
                const uint WS_EX_NOACTIVATE = 0x08000000;
                const uint WS_EX_TOOLWINDOW = 0x00000080;
                const uint WS_EX_TOPMOST = 0x00000008;
                const uint WS_POPUP = 0x80000000;
                const uint WS_VISIBLE = 0x10000000;
                const uint WS_DISABLED = 0x08000000;


                var handle = _window!.Native!.Win32!.Value.Hwnd;

                SetWindowLong(handle, GWL_STYLE, WS_POPUP | WS_VISIBLE);

                // Set extended styles
                var extendedStyle = GetWindowLong(handle, GWL_EXSTYLE);
                SetWindowLong(handle, GWL_EXSTYLE,
                    extendedStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT |
                    WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST);

                // Position overlay above target window (not globally topmost)
                SetWindowPos(handle, _targetWindowHandle, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            }
            catch { /* Ignore if P/Invoke fails */ }
        }
        private void OnRender(double deltaTime)
        {
            if (_isDisposed || _imguiController == null || _gl == null)
                return;
            _gl.ClearColor(0f, 0f, 0f, 0f);
            _gl.Clear(ClearBufferMask.ColorBufferBit);

            _imguiController.Update((float)deltaTime);

            RenderOverlay();

            _imguiController.Render();
        }

        private void RenderOverlay()
        {
            var now = DateTime.Now;
            var activePopups = _popups.Values
                .Where(p =>
                {
                    if (p is RichTextPopup rp) return rp.ExpireTime >= now;
                    return false;
                })
                .OrderByDescending(p =>
                {
                    if (p is RichTextPopup rp) return rp.ExpireTime;
                    return DateTime.MinValue;
                })
                .Take(10)
                .ToList();

            // Always begin the window, even if no popups
            ImGui.SetNextWindowPos(new Vector2(_xOffset, _yOffset));
            ImGui.SetNextWindowBgAlpha(0.0f);

            ImGui.Begin("Popups",
                ImGuiWindowFlags.NoBackground |
                ImGuiWindowFlags.AlwaysAutoResize |
                ImGuiWindowFlags.NoTitleBar);

            if (activePopups.Any())
            {
                var yOffset = 0f;
                foreach (var popup in activePopups)
                {
                    ImGui.SetCursorPos(new Vector2(0, yOffset));
                     if (popup is RichTextPopup richPopup)
                    {
                        RenderRichTextPopup(richPopup, now);
                    }

                    yOffset += _fontSize + 5; // Increased spacing slightly
                }
            }
            
            ImGui.End();
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

        public void AddTextPopup(string text)
        {
            AddRichTextPopup(new List<ColoredTextSpan> { new ColoredTextSpan { Color = _textColor, Text = text } });
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

            _windowMonitorTimer?.Stop();
            _windowMonitorTimer?.Dispose();

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

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

        [DllImport("user32.dll")]
        private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);
        [DllImport("user32.dll", EntryPoint = "SetWindowLongPtr")]
        private static extern IntPtr SetWindowLongPtrNative(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        // For 32-bit compatibility (optional, but good practice)
        [DllImport("user32.dll", EntryPoint = "SetWindowLong")]
        private static extern IntPtr SetWindowLong32(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        private static IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong)
        {
            if (IntPtr.Size == 8)
                return SetWindowLongPtrNative(hWnd, nIndex, dwNewLong);
            else
                return SetWindowLong32(hWnd, nIndex, dwNewLong);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINDOWPLACEMENT
        {
            public int length;
            public int flags;
            public int showCmd;
            public System.Drawing.Point ptMinPosition;
            public System.Drawing.Point ptMaxPosition;
            public RECT rcNormalPosition;
        }


        private const uint SWP_NOMOVE = 0x0002;
        private const uint SWP_NOSIZE = 0x0001;
        private const uint SWP_NOACTIVATE = 0x0010;
        private const uint SWP_SHOWWINDOW = 0x0040;
        #endregion
    }

}