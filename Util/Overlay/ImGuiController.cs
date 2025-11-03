using ImGuiNET;
using Silk.NET.GLFW;
using Silk.NET.Input;
using Silk.NET.OpenGL;
using Silk.NET.Windowing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Overlay
{
    public class ImGuiController : IDisposable
    {
        private GL _gl;
        private IView _view;
        private IInputContext _input;
        private bool _frameBegun;

        private uint _vertexArray;
        private uint _vertexBuffer;
        private uint _vertexBufferSize;
        private uint _indexBuffer;
        private uint _indexBufferSize;

        private uint _fontTexture;
        private uint _shader;
        private int _attribLocationTex;
        private int _attribLocationProjMtx;
        private int _attribLocationVtxPos;
        private int _attribLocationVtxUV;
        private int _attribLocationVtxColor;

        private int _windowWidth;
        private int _windowHeight;

        public ImGuiController(GL gl, IView view, IInputContext input)
        {
            _gl = gl;
            _view = view;
            _input = input;
            _windowWidth = view.Size.X;
            _windowHeight = view.Size.Y;

            var context = ImGui.CreateContext();
            ImGui.SetCurrentContext(context);

            var io = ImGui.GetIO();
            io.BackendFlags |= ImGuiBackendFlags.RendererHasVtxOffset;

            CreateDeviceResources();
            SetPerFrameImGuiData(1f / 60f);

            ImGui.NewFrame();
            _frameBegun = true;
        }

        public void Update(float deltaSeconds)
        {
            if (_frameBegun)
            {
                ImGui.Render();
            }

            SetPerFrameImGuiData(deltaSeconds);
            UpdateImGuiInput();

            _frameBegun = true;
            ImGui.NewFrame();
        }

        public void Render()
        {
            if (!_frameBegun)
                return;

            _frameBegun = false;
            ImGui.Render();
            RenderImDrawData(ImGui.GetDrawData());
        }

        private void SetPerFrameImGuiData(float deltaSeconds)
        {
            var io = ImGui.GetIO();
            io.DisplaySize = new Vector2(_windowWidth, _windowHeight);

            if (_windowWidth > 0 && _windowHeight > 0)
            {
                io.DisplayFramebufferScale = new Vector2(1f, 1f);
            }

            io.DeltaTime = deltaSeconds;
        }

        private void UpdateImGuiInput()
        {
            var io = ImGui.GetIO();

            var mouseState = _input.Mice.Count > 0 ? _input.Mice[0] : null;
            var keyboardState = _input.Keyboards.Count > 0 ? _input.Keyboards[0] : null;

            if (mouseState != null)
            {
                io.MousePos = new Vector2(mouseState.Position.X, mouseState.Position.Y);
                io.MouseDown[0] = mouseState.IsButtonPressed(Silk.NET.Input.MouseButton.Left);
                io.MouseDown[1] = mouseState.IsButtonPressed(Silk.NET.Input.MouseButton.Right);
                io.MouseDown[2] = mouseState.IsButtonPressed(Silk.NET.Input.MouseButton.Middle);
            }

            foreach (var key in Enum.GetValues<ImGuiKey>())
            {
                if (key == ImGuiKey.None)
                    continue;
                io.AddKeyEvent(key, false);
            }
        }

        private void CreateDeviceResources()
        {
            // Create vertex array
            _vertexArray = _gl.GenVertexArray();
            _gl.BindVertexArray(_vertexArray);

            _vertexBufferSize = 10000;
            _indexBufferSize = 2000;

            _vertexBuffer = _gl.GenBuffer();
            _gl.BindBuffer(BufferTargetARB.ArrayBuffer, _vertexBuffer);
            _gl.BufferData(BufferTargetARB.ArrayBuffer, _vertexBufferSize, IntPtr.Zero, BufferUsageARB.DynamicDraw);

            _indexBuffer = _gl.GenBuffer();
            _gl.BindBuffer(BufferTargetARB.ElementArrayBuffer, _indexBuffer);
            _gl.BufferData(BufferTargetARB.ElementArrayBuffer, _indexBufferSize, IntPtr.Zero, BufferUsageARB.DynamicDraw);

            RecreateFontDeviceTexture();
            CreateShaders();

            _gl.BindVertexArray(0);
            _gl.BindBuffer(BufferTargetARB.ArrayBuffer, 0);
        }

        private void CreateShaders()
        {
            const string vertexSource = @"
                #version 330 core
                uniform mat4 ProjMtx;
                layout (location = 0) in vec2 Position;
                layout (location = 1) in vec2 UV;
                layout (location = 2) in vec4 Color;
                out vec2 Frag_UV;
                out vec4 Frag_Color;
                void main()
                {
                    Frag_UV = UV;
                    Frag_Color = Color;
                    gl_Position = ProjMtx * vec4(Position.xy, 0, 1);
                }";

            const string fragmentSource = @"
                #version 330 core
                uniform sampler2D Texture;
                in vec2 Frag_UV;
                in vec4 Frag_Color;
                out vec4 Out_Color;
                void main()
                {
                    Out_Color = Frag_Color * texture(Texture, Frag_UV.st);
                }";

            _shader = CreateProgram(vertexSource, fragmentSource);
            _attribLocationTex = _gl.GetUniformLocation(_shader, "Texture");
            _attribLocationProjMtx = _gl.GetUniformLocation(_shader, "ProjMtx");
            _attribLocationVtxPos = _gl.GetAttribLocation(_shader, "Position");
            _attribLocationVtxUV = _gl.GetAttribLocation(_shader, "UV");
            _attribLocationVtxColor = _gl.GetAttribLocation(_shader, "Color");
        }

        private uint CreateProgram(string vertexSource, string fragmentSource)
        {
            var program = _gl.CreateProgram();
            var vertex = CompileShader(ShaderType.VertexShader, vertexSource);
            var fragment = CompileShader(ShaderType.FragmentShader, fragmentSource);

            _gl.AttachShader(program, vertex);
            _gl.AttachShader(program, fragment);
            _gl.LinkProgram(program);

            _gl.DetachShader(program, vertex);
            _gl.DetachShader(program, fragment);
            _gl.DeleteShader(vertex);
            _gl.DeleteShader(fragment);

            return program;
        }

        private uint CompileShader(ShaderType type, string source)
        {
            var shader = _gl.CreateShader(type);
            _gl.ShaderSource(shader, source);
            _gl.CompileShader(shader);

            _gl.GetShader(shader, ShaderParameterName.CompileStatus, out var status);
            if (status == 0)
            {
                var info = _gl.GetShaderInfoLog(shader);
                throw new Exception($"Error compiling shader: {info}");
            }

            return shader;
        }

        private void RecreateFontDeviceTexture()
        {
            var io = ImGui.GetIO();
            io.Fonts.GetTexDataAsRGBA32(out IntPtr pixels, out int width, out int height, out int bytesPerPixel);

            _fontTexture = _gl.GenTexture();
            _gl.BindTexture(TextureTarget.Texture2D, _fontTexture);
            _gl.TexParameter(TextureTarget.Texture2D, TextureParameterName.TextureMinFilter, (int)TextureMinFilter.Linear);
            _gl.TexParameter(TextureTarget.Texture2D, TextureParameterName.TextureMagFilter, (int)TextureMagFilter.Linear);

            unsafe
            {
                _gl.TexImage2D(TextureTarget.Texture2D, 0, InternalFormat.Rgba, (uint)width, (uint)height, 0,
                    PixelFormat.Rgba, PixelType.UnsignedByte, (void*)pixels);
            }

            io.Fonts.SetTexID((IntPtr)_fontTexture);
            io.Fonts.ClearTexData();
        }

        private unsafe void RenderImDrawData(ImDrawDataPtr drawData)
        {
            if (drawData.CmdListsCount == 0)
                return;

            uint vertexOffsetInVertices = 0;
            uint indexOffsetInElements = 0;

            var framebufferWidth = (uint)(drawData.DisplaySize.X * drawData.FramebufferScale.X);
            var framebufferHeight = (uint)(drawData.DisplaySize.Y * drawData.FramebufferScale.Y);
            if (framebufferWidth <= 0 || framebufferHeight <= 0)
                return;

            // Setup render state
            _gl.Enable(EnableCap.Blend);
            _gl.BlendEquation(BlendEquationModeEXT.FuncAdd);
            _gl.BlendFunc(BlendingFactor.SrcAlpha, BlendingFactor.OneMinusSrcAlpha);
            _gl.Disable(EnableCap.CullFace);
            _gl.Disable(EnableCap.DepthTest);
            _gl.Enable(EnableCap.ScissorTest);

            _gl.Viewport(0, 0, framebufferWidth, framebufferHeight);

            float L = drawData.DisplayPos.X;
            float R = drawData.DisplayPos.X + drawData.DisplaySize.X;
            float T = drawData.DisplayPos.Y;
            float B = drawData.DisplayPos.Y + drawData.DisplaySize.Y;

            Span<float> orthoProjection = stackalloc float[]
            {
                2.0f / (R - L), 0.0f, 0.0f, 0.0f,
                0.0f, 2.0f / (T - B), 0.0f, 0.0f,
                0.0f, 0.0f, -1.0f, 0.0f,
                (R + L) / (L - R), (T + B) / (B - T), 0.0f, 1.0f,
            };

            _gl.UseProgram(_shader);
            _gl.Uniform1(_attribLocationTex, 0);
            _gl.UniformMatrix4(_attribLocationProjMtx, 1, false, orthoProjection);

            _gl.BindVertexArray(_vertexArray);
            _gl.BindBuffer(BufferTargetARB.ArrayBuffer, _vertexBuffer);
            _gl.BindBuffer(BufferTargetARB.ElementArrayBuffer, _indexBuffer);

            _gl.EnableVertexAttribArray((uint)_attribLocationVtxPos);
            _gl.EnableVertexAttribArray((uint)_attribLocationVtxUV);
            _gl.EnableVertexAttribArray((uint)_attribLocationVtxColor);

            _gl.VertexAttribPointer((uint)_attribLocationVtxPos, 2, VertexAttribPointerType.Float, false,
                (uint)Unsafe.SizeOf<ImDrawVert>(), (void*)0);
            _gl.VertexAttribPointer((uint)_attribLocationVtxUV, 2, VertexAttribPointerType.Float, false,
                (uint)Unsafe.SizeOf<ImDrawVert>(), (void*)8);
            _gl.VertexAttribPointer((uint)_attribLocationVtxColor, 4, VertexAttribPointerType.UnsignedByte, true,
                (uint)Unsafe.SizeOf<ImDrawVert>(), (void*)16);

            for (int n = 0; n < drawData.CmdListsCount; n++)
            {
                var cmdList = drawData.CmdLists[n];

                _gl.BufferData(BufferTargetARB.ArrayBuffer, (nuint)(cmdList.VtxBuffer.Size * Unsafe.SizeOf<ImDrawVert>()),
                    (void*)cmdList.VtxBuffer.Data, BufferUsageARB.StreamDraw);

                _gl.BufferData(BufferTargetARB.ElementArrayBuffer, (nuint)(cmdList.IdxBuffer.Size * sizeof(ushort)),
                    (void*)cmdList.IdxBuffer.Data, BufferUsageARB.StreamDraw);

                for (int cmd_i = 0; cmd_i < cmdList.CmdBuffer.Size; cmd_i++)
                {
                    var pcmd = cmdList.CmdBuffer[cmd_i];

                    var clipRect = new Vector4(
                        pcmd.ClipRect.X - drawData.DisplayPos.X,
                        pcmd.ClipRect.Y - drawData.DisplayPos.Y,
                        pcmd.ClipRect.Z - drawData.DisplayPos.X,
                        pcmd.ClipRect.W - drawData.DisplayPos.Y
                    );

                    if (clipRect.X < framebufferWidth && clipRect.Y < framebufferHeight &&
                        clipRect.Z >= 0.0f && clipRect.W >= 0.0f)
                    {
                        _gl.Scissor((int)clipRect.X, (int)(framebufferHeight - clipRect.W),
                            (uint)(clipRect.Z - clipRect.X), (uint)(clipRect.W - clipRect.Y));

                        _gl.BindTexture(TextureTarget.Texture2D, (uint)pcmd.TextureId);
                        _gl.DrawElementsBaseVertex(PrimitiveType.Triangles, pcmd.ElemCount,
                            DrawElementsType.UnsignedShort, (void*)(pcmd.IdxOffset * sizeof(ushort)),
                            (int)(pcmd.VtxOffset + vertexOffsetInVertices));
                    }
                }

                vertexOffsetInVertices += (uint)cmdList.VtxBuffer.Size;
                indexOffsetInElements += (uint)cmdList.IdxBuffer.Size;
            }

            _gl.Disable(EnableCap.Blend);
            _gl.Disable(EnableCap.ScissorTest);
        }

        public void WindowResized(int width, int height)
        {
            _windowWidth = width;
            _windowHeight = height;
        }

        public void Dispose()
        {
            _gl.DeleteBuffer(_vertexBuffer);
            _gl.DeleteBuffer(_indexBuffer);
            _gl.DeleteVertexArray(_vertexArray);
            _gl.DeleteProgram(_shader);
            _gl.DeleteTexture(_fontTexture);
        }
    }
}
