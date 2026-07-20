using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Hook
{
    public class FunctionHook : IDisposable
    {
        private readonly IntPtr _targetAddress;
        private readonly IntPtr _hookAddress;
        private readonly IntPtr _processHandle;
        private readonly byte[] _originalBytes;
        private readonly byte[] _jumpBytes;
        private readonly int _hookSize;
        private readonly IntPtr _parameterStorage;
        private readonly IntPtr _callbackAddress;
        private readonly bool _executeOriginalInstructions;
        private bool _isInstalled = false;
        private bool _disposed = false;

        public HookCallback Callback { get; set; }
        public delegate bool HookCallback(HookContext context);
        public Func<HookContext, bool> ShouldCallOriginal { get; set; } = _ => true;
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool NativeHookCallback(IntPtr parameters, int paramCount);
        public FunctionHook(IntPtr targetAddress, HookCallback callback, int hookSize = 5, bool executeOriginalInstructions = true)
        {
            _targetAddress = targetAddress;
            _processHandle = PlatformMemory.PlatformMemory.GetProcessH(PlatformMemory.PlatformMemory.CurrentProcId);
            _hookSize = hookSize;
            _executeOriginalInstructions = executeOriginalInstructions;
            Callback = callback;

            // Read original bytes
            _originalBytes = new byte[_hookSize];
            PlatformMemory.PlatformMemory.PlatformImpl.ReadProcessMemory(_processHandle, (ulong)_targetAddress, _originalBytes, _hookSize, out _);

            // Allocate parameter storage
            _parameterStorage = PlatformMemory.PlatformMemory.Allocate(1024);

            // Create managed callback delegate and get function pointer
            var nativeCallback = new NativeHookCallback(HandleNativeCallback);
            _callbackAddress = Marshal.GetFunctionPointerForDelegate(nativeCallback);

            // Create and write the hook stub
            _hookAddress = CreateHookStub();

            // Create jump instruction
            _jumpBytes = CreateJumpInstruction(_targetAddress, _hookAddress);
        }
        private IntPtr CreateHookStub()
        {
            IntPtr stubMemory = PlatformMemory.PlatformMemory.Allocate(1024, PlatformMemory.PlatformMemory.PAGE_EXECUTE_READWRITE);
            byte[] stubCode = GenerateHookStub();
            Memory.Write((ulong)stubMemory, stubCode);
            return stubMemory;
        }
        private bool HandleNativeCallback(IntPtr parameters, int paramCount)
        {
            try
            {
                // Extract parameters from native memory
                var paramArray = new IntPtr[paramCount];
                for (int i = 0; i < paramCount; i++)
                {
                    paramArray[i] = Marshal.ReadIntPtr(parameters, i * IntPtr.Size);
                }

                var context = new HookContext
                {
                    Parameters = paramArray,
                    ReturnValue = IntPtr.Zero,
                    SuppressOriginal = false
                };

                // Call managed callback
                Callback?.Invoke(context);
                for (int i = 0; i < paramCount && i < context.Parameters.Length; i++)
                {
                    Marshal.WriteIntPtr(parameters, i * IntPtr.Size, context.Parameters[i]);
                }
                // Return whether to call original (only if we're configured to execute original instructions)
                return _executeOriginalInstructions && !context.SuppressOriginal && (ShouldCallOriginal?.Invoke(context) ?? true);
            }
            catch (Exception ex)
            {
                Log.Error($"Error in hook callback: {ex.Message}");
                return _executeOriginalInstructions; // Default behavior based on configuration
            }
        }

        private byte[] GenerateHookStub()
        {
            var code = new List<byte>();
            bool is64Bit = IntPtr.Size == 8;

            if (is64Bit)
            {
                // x64 implementation
                // Save registers
                code.AddRange(new byte[] {
                0x50,                          // push rax
                0x51,                          // push rcx
                0x52,                          // push rdx
                0x41, 0x50,                    // push r8
                0x41, 0x51,                    // push r9
                0x41, 0x52,                    // push r10
                0x41, 0x53,                    // push r11
                0x48, 0x83, 0xEC, 0x20,        // sub rsp, 0x20 (shadow space)
            });

                // Store parameters (RCX, RDX, R8, R9, and stack params)
                code.AddRange(new byte[] {
                0x48, 0xB8                     // mov rax, immediate64
            });
                code.AddRange(BitConverter.GetBytes((long)_parameterStorage));
                code.AddRange(new byte[] {
                0x48, 0x89, 0x08,              // mov [rax], rcx
                0x48, 0x89, 0x50, 0x08,        // mov [rax+8], rdx
                0x4C, 0x89, 0x40, 0x10,        // mov [rax+0x10], r8
                0x4C, 0x89, 0x48, 0x18         // mov [rax+0x18], r9
            });

                // Prepare call to managed callback
                code.AddRange(new byte[] {
                0x48, 0xB9                     // mov rcx, immediate64
            });
                code.AddRange(BitConverter.GetBytes((long)_parameterStorage));

                code.AddRange(new byte[] {
                0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00  // mov rdx, 4
            });

                // Call managed callback
                code.AddRange(new byte[] {
                0x48, 0xB8                     // mov rax, immediate64
            });
                code.AddRange(BitConverter.GetBytes((long)_callbackAddress));
                code.AddRange(new byte[] {
                0xFF, 0xD0                     // call rax
            });

                if (_executeOriginalInstructions)
                {
                    // Check return value (AL = 0 means skip original)
                    code.AddRange(new byte[] {
                    0x84, 0xC0,                    // test al, al
                    0x74, 0x20                     // jz skip_original
                });

                    // Restore registers for original call
                    code.AddRange(new byte[] {
                    0x48, 0x83, 0xC4, 0x20,        // add rsp, 0x20
                    0x41, 0x5B,                    // pop r11
                    0x41, 0x5A,                    // pop r10
                    0x41, 0x59,                    // pop r9
                    0x41, 0x58,                    // pop r8
                    0x5A,                          // pop rdx
                    0x59,                          // pop rcx
                    0x58,                          // pop rax
                });

                    // Execute original bytes
                    code.AddRange(_originalBytes);

                    // Jump to continue original function
                    code.AddRange(new byte[] {
                    0x48, 0xB8                     // mov rax, immediate64
                });
                    code.AddRange(BitConverter.GetBytes((long)_targetAddress + _hookSize));
                    code.AddRange(new byte[] {
                    0xFF, 0xE0                     // jmp rax
                });

                    // skip_original label
                }

                // Always restore registers and return
                code.AddRange(new byte[] {
                0x48, 0x83, 0xC4, 0x20,        // add rsp, 0x20
                0x41, 0x5B,                    // pop r11
                0x41, 0x5A,                    // pop r10
                0x41, 0x59,                    // pop r9
                0x41, 0x58,                    // pop r8
                0x5A,                          // pop rdx
                0x59,                          // pop rcx
                0x58,                          // pop rax
                0xC3                           // ret
            });
            }
            else
            {
                // x86 implementation
                code.AddRange(new byte[] {
                0x60,                          // pushad
                0x9C,                          // pushfd
            });

                // Store stack parameters
                code.AddRange(new byte[] {
                0xB8                           // mov eax, immediate32
            });
                code.AddRange(BitConverter.GetBytes((int)_parameterStorage));

                for (int i = 0; i < 4; i++)
                {
                    code.AddRange(new byte[] {
                    0x8B, 0x4C, 0x24, (byte)(0x24 + i * 4),  // mov ecx, [esp+0x24+i*4]
                    0x89, 0x48, (byte)(i * 4)                // mov [eax+i*4], ecx
                });
                }

                // Call managed callback
                code.AddRange(new byte[] {
                0x6A, 0x04,                    // push 4 (param count)
                0x50                           // push eax (parameter storage)
            });
                code.AddRange(new byte[] {
                0xB8                           // mov eax, immediate32
            });
                code.AddRange(BitConverter.GetBytes((int)_callbackAddress));
                code.AddRange(new byte[] {
                0xFF, 0xD0,                    // call eax
                0x83, 0xC4, 0x08               // add esp, 8 (clean up stack)
            });

                if (_executeOriginalInstructions)
                {
                    // Check return value
                    code.AddRange(new byte[] {
                    0x84, 0xC0,                    // test al, al
                    0x74, 0x0C                     // jz skip_original
                });

                    // Restore and call original
                    code.AddRange(new byte[] {
                    0x9D,                          // popfd
                    0x61,                          // popad
                });
                    code.AddRange(_originalBytes);
                    code.AddRange(new byte[] {
                    0xB8                           // mov eax, immediate32
                });
                    code.AddRange(BitConverter.GetBytes((int)_targetAddress + _hookSize));
                    code.AddRange(new byte[] {
                    0xFF, 0xE0                     // jmp eax
                });

                    // skip_original label
                }

                // Always restore and return
                code.AddRange(new byte[] {
                0x9D,                          // popfd
                0x61,                          // popad
                0xC3                           // ret
            });
            }

            return code.ToArray();
        }

        private byte[] CreateJumpInstruction(IntPtr from, IntPtr to)
        {
            long offset = (long)to - (long)from - 5;
            return new byte[]
            {
            0xE9,                           // JMP relative
            (byte)(offset & 0xFF),
            (byte)((offset >> 8) & 0xFF),
            (byte)((offset >> 16) & 0xFF),
            (byte)((offset >> 24) & 0xFF)
            };
        }
        public bool Install()
        {
            if (_isInstalled) return true;

            if (!PlatformMemory.PlatformMemory.PlatformImpl.VirtualProtectEx(_processHandle, _targetAddress, (IntPtr)_hookSize,
                PlatformMemory.PlatformMemory.PAGE_EXECUTE_READWRITE, out uint oldProtect))
            {
                return false;
            }

            bool success = PlatformMemory.PlatformMemory.PlatformImpl.WriteProcessMemory(_processHandle, (ulong)_targetAddress,
                _jumpBytes, _jumpBytes.Length, out _);

            PlatformMemory.PlatformMemory.PlatformImpl.VirtualProtectEx(_processHandle, _targetAddress, (IntPtr)_hookSize,
                oldProtect, out _);

            _isInstalled = success;
            return success;
        }
        public bool Uninstall()
        {
            if (!_isInstalled) return true;

            if (!PlatformMemory.PlatformMemory.PlatformImpl.VirtualProtectEx(_processHandle, _targetAddress, (IntPtr)_hookSize,
                PlatformMemory.PlatformMemory.PAGE_EXECUTE_READWRITE, out uint oldProtect))
            {
                return false;
            }

            bool success = PlatformMemory.PlatformMemory.PlatformImpl.WriteProcessMemory(_processHandle, (ulong)_targetAddress,
                _originalBytes, _originalBytes.Length, out _);

            PlatformMemory.PlatformMemory.PlatformImpl.VirtualProtectEx(_processHandle, _targetAddress, (IntPtr)_hookSize,
                oldProtect, out _);

            _isInstalled = !success;
            return success;
        }
        public void Dispose()
        {
            if (_disposed) return;

            Uninstall();

            if (_hookAddress != IntPtr.Zero)
                PlatformMemory.PlatformMemory.FreeMemory(_hookAddress);

            if (_parameterStorage != IntPtr.Zero)
                PlatformMemory.PlatformMemory.FreeMemory(_parameterStorage);

            _disposed = true;
        }
    }
}
