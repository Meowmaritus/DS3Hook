﻿using DS3Hook.Injection.Structures;
using Managed.X86;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Addr = Managed.X86.X86Address;
using Reg32 = Managed.X86.X86Register32;

namespace DS3Hook.Injection
{
    public class DSAsmCaller : IDisposable
    {
        public const int FUNCTION_CALL_ASM_BUFFER_SIZE = 1024;
        public const int ReturnValueCheckInterval = 5;
        public const int FUNC_RETURN_ADDR_OFFSET = 0x200;
        public const int MAX_WAIT = 1000;
        public const int BUFFER_STACK_SIZE = 5;
        public const uint PLACEHOLDER_INT32 = 0xE110D00D;

        public const int INT32_SIZE = 4;

        public const uint FUNCCALL_ERR = 0xFFFFFFFF;

        private static readonly Type[] SquashIntoDword_NumericTypes = 
            { typeof(byte), typeof(sbyte), typeof(short), typeof(ushort), typeof(int), typeof(uint), typeof(bool), typeof(float) };

        private MemoryStream AsmBuffer = new MemoryStream(1024);
        private dynamic Buffer_Result;
        private List<SafeRemoteHandle> Buffer_ParamPointerList = new List<SafeRemoteHandle>();
        private List<Int32> Buffer_DefaultEmptyStack = new List<Int32>();
        private Int32[] Buffer_Stack = new Int32[BUFFER_STACK_SIZE];
        private byte[] Buffer_ResultBytes = new byte[INT32_SIZE];
        private MutatableDword Buffer_GetFunctionCallResult = 0;

        private MutatableDword Buffer_SquashIntoDwordResult = 0;
        public SafeRemoteHandle CodeHandle { get; private set; }
        private MoveableAddressOffset[] AsmLocAfterEachStackMov = new MoveableAddressOffset[BUFFER_STACK_SIZE];
        private MoveableAddressOffset AsmLocAfterLuaFunctionCall;
        private byte[] GetNewCopyOfAsmBuffer()
        {
            return AsmBuffer.ToArray();
        }

        private bool WriteAsm(IntPtr address, byte[] bytes, int count)
        {
            return Kernel.WriteProcessMemory_SAFE(Hook.DarkSouls3Handle.GetHandle(), address, bytes, count, IntPtr.Zero) 
                && Kernel.FlushInstructionCache(Hook.DarkSouls3Handle.GetHandle(), (IntPtr)address, (UIntPtr)count);
        }


        private bool InjectEntireCodeBuffer()
        {
            return WriteAsm(CodeHandle.GetHandle(), AsmBuffer.ToArray(), (int)AsmBuffer.Position);
        }

        private void CompletelyReInitializeAndInjectCodeInNewLocation()
        {
            UndoCodeInjection();
            CodeHandle?.Dispose();
            CodeHandle = new SafeRemoteHandle(FUNCTION_CALL_ASM_BUFFER_SIZE);
        }


        private void UndoCodeInjection()
        {
            if (CodeHandle != null && !CodeHandle.IsClosed)
            {
                CodeHandle.Close();
            }
        }

        public bool IsCodeInjected
        {
            get { return (!CodeHandle.IsClosed) && (!CodeHandle.IsInvalid); }
        }

        public DSAsmCaller()
        {
            HookEvents();
            CompletelyReInitializeAndInjectCodeInNewLocation();
        }

        private void HookEvents()
        {
            Hook.DarkSouls3Handle.OnAttach += Proc_OnAttachToCurrentProcess;
            Hook.DarkSouls3Handle.OnDetach += Proc_OnDetachFromCurrentProcess;
        }

        private void UnhookEvents()
        {
            Hook.DarkSouls3Handle.OnAttach -= Proc_OnAttachToCurrentProcess;
            Hook.DarkSouls3Handle.OnDetach -= Proc_OnDetachFromCurrentProcess;
        }

        private void Proc_OnDetachFromCurrentProcess()
        {
            UndoCodeInjection();
        }

        private void Proc_OnAttachToCurrentProcess()
        {
            CompletelyReInitializeAndInjectCodeInNewLocation();
        }

        private void InitAsmBuffer(int funcAddr, IEnumerable<dynamic> parameters, List<SafeRemoteHandle> allocPtrList,
            dynamic eax = null,
            dynamic ecx = null,
            dynamic edx = null,
            dynamic ebx = null,
            dynamic esp = null,
            dynamic esi = null,
            dynamic edi = null)
        {
            var args = parameters.ToArray();

            AsmBuffer.Position = 0;
            X86Writer asm = new X86Writer(AsmBuffer, CodeHandle.GetHandle());
            //ASM START:
            asm.Push32(Reg32.EBP);
            asm.Mov32(Reg32.EBP, Reg32.ESP);
            asm.Push32(Reg32.EAX);

            for (int i = args.Length - 1; i >= 0; i += -1)
            {
                asm.Mov32(Reg32.EAX, SquashIntoDword(ref allocPtrList, args[i]));
                asm.Push32(Reg32.EAX);
            }

            if (eax != null)
                asm.Mov32(Reg32.EAX, SquashIntoDword(ref allocPtrList, eax));

            if (ecx != null)
                asm.Mov32(Reg32.ECX, SquashIntoDword(ref allocPtrList, ecx));

            if (edx != null)
                asm.Mov32(Reg32.EDX, SquashIntoDword(ref allocPtrList, edx));

            if (ebx != null)
                asm.Mov32(Reg32.EBX, SquashIntoDword(ref allocPtrList, ebx));

            if (esp != null)
                asm.Mov32(Reg32.ESP, SquashIntoDword(ref allocPtrList, esp));

            if (esi != null)
                asm.Mov32(Reg32.ESI, SquashIntoDword(ref allocPtrList, esi));

            if (edi != null)
                asm.Mov32(Reg32.EDI, SquashIntoDword(ref allocPtrList, edi));

            //CALL LUA FUNCTION:
            asm.Call(new IntPtr(funcAddr));
            AsmLocAfterLuaFunctionCall = new MoveableAddressOffset(this, asm.Position);
            //SET RETURN POS:
            asm.Mov32(Reg32.EBX, CodeHandle.GetHandle().ToInt32() + FUNC_RETURN_ADDR_OFFSET);
            asm.Mov32(new Addr(Reg32.EBX, 0), Reg32.EAX);
            //mov [ebx], eax
            asm.Pop32(Reg32.EAX);

            for (int i = args.Length - 1; i >= 0; i += -1)
            {
                asm.Pop32(Reg32.EAX);
            }

            asm.Mov32(Reg32.ESP, Reg32.EBP);
            asm.Pop32(Reg32.EBP);
            asm.Retn();
        }

        static Int32 ToInt32(bool t)
        {
            if (t) { return 1; }
            else { return 0; }
        }
        static Int32 ToInt32(Int32 t)
        {
            return t;
        }

        private byte[] InitAsm64Buffer(IntPtr funcAddr, IEnumerable<dynamic> parameters, List<SafeRemoteHandle> allocPtrList,
    dynamic rax = null,
    dynamic rcx = null,
    dynamic rdx = null,
    dynamic rbx = null,
    dynamic rsp = null,
    dynamic rsi = null,
    dynamic rdi = null)
        {
            var args = parameters.ToArray();


            byte[] asm64 = {
                0x9C, //pushfq
                0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00, //add rsp, 00000080
                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov rdx, 00   (0xA = rdx loc)
                0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r8, 00 (20d)
                0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r9, 00 (30d)
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov rcx, 00 (40d)
                0x48, 0x89, 0x4C, 0x24, 0x20, //mov [rsp+28],rcx
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov rcx, 00  (55d)
                0x48, 0x89, 0x4C, 0x24, 0x28, //mov [rsp+28],rcx
                0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //call absolute address (76d)

                0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov val return address to rbx (81d)
                0x48, 0x89, 0x03, //mov [rbx], rax

                0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, //sub rsp, 00000080
                0x9D,  //popfq
                0xC3    //retn
            };

            /*
            if (args.Length > 0) { Array.Copy(BitConverter.GetBytes((Int64)args[0]), 0, asm64, 0xA, 8); }
            if (args.Length > 1) { Array.Copy(BitConverter.GetBytes((Int64)args[1]), 0, asm64, 20, 8); }
            if (args.Length > 2) { Array.Copy(BitConverter.GetBytes((Int64)args[2]), 0, asm64, 30, 8); }
            if (args.Length > 3) { Array.Copy(BitConverter.GetBytes((Int64)args[3]), 0, asm64, 40, 8); }
            if (args.Length > 4) { Array.Copy(BitConverter.GetBytes((Int64)args[4]), 0, asm64, 55, 8); }
            */

            //Fix this damn int conversion crap
            List<Int32> intargs = new List<Int32>();

            for (int i = 0; i < (args.Count()); i++)
            {
               intargs.Add(ToInt32(args[i]));
            }

            if (intargs.Count() > 0) { Array.Copy(BitConverter.GetBytes(intargs[0]), 0, asm64, 0xA, 4); }
            if (intargs.Count() > 1) { Array.Copy(BitConverter.GetBytes(intargs[1]), 0, asm64, 20, 4); }
            if (intargs.Count() > 2) { Array.Copy(BitConverter.GetBytes(intargs[2]), 0, asm64, 30, 4); }
            if (intargs.Count() > 3) { Array.Copy(BitConverter.GetBytes(intargs[3]), 0, asm64, 40, 4); }
            if (intargs.Count() > 4) { Array.Copy(BitConverter.GetBytes(intargs[4]), 0, asm64, 55, 4); }

            

            Array.Copy(BitConverter.GetBytes((Int64)funcAddr), 0, asm64, 76, 8);
            Array.Copy(BitConverter.GetBytes(CodeHandle.GetHandle().ToInt64() + 0x200), 0, asm64, 86, 8);  //Move rax to return address

            return asm64;
            
        }



        private void ____freeClrManagedResources()
        {
            UnhookEvents();

            AsmBuffer.Dispose();
            AsmBuffer = null;

            Buffer_Result = null;
            Buffer_ParamPointerList.Clear();
            Buffer_ParamPointerList = null;

            Buffer_DefaultEmptyStack.Clear();
            Buffer_DefaultEmptyStack = null;
            Buffer_Stack = null;
            Buffer_ResultBytes = null;
            //Buffer_StackCounter = null;

            AsmLocAfterEachStackMov = null;
            AsmLocAfterLuaFunctionCall = null;

        }

        private void ____freeNativeUnmanagedResources()
        {
            UndoCodeInjection();
            CodeHandle.Close();
            CodeHandle.Dispose();
            CodeHandle = null;
        }

        private byte[] ExecuteAsm()
        {
            var threadHandle = new SafeRemoteThreadHandle(CodeHandle);
            if (!threadHandle.IsClosed & !threadHandle.IsInvalid)
            {
                Kernel.WaitForSingleObject(threadHandle.GetHandle(), MAX_WAIT);
            }
            threadHandle.Close();
            threadHandle.Dispose();
            threadHandle = null;

            return CodeHandle.GetFuncReturnValue();
        }

        private int SquashIntoDword(ref List<SafeRemoteHandle> allocPtrList, dynamic arg)
        {
            Type typ = arg.GetType();

            Buffer_SquashIntoDwordResult.Int1 = 0;

            if (arg is int)
                Buffer_SquashIntoDwordResult = (int)arg;
            else if (arg is bool)
                Buffer_SquashIntoDwordResult = (bool)arg;
            else if (arg is float)
                Buffer_SquashIntoDwordResult = (float)arg;
            else if (arg is uint)
                Buffer_SquashIntoDwordResult = (uint)arg;
            else if (arg is short)
                Buffer_SquashIntoDwordResult = (short)arg;
            else if (arg is ushort)
                Buffer_SquashIntoDwordResult = (ushort)arg;
            else if (arg is byte)
                Buffer_SquashIntoDwordResult = (byte)arg;
            else if (arg is string argStr)
            {
                var hand = new SafeRemoteHandle((argStr.Length + 1) * 2);
                var handVal = hand.GetHandle();

                Hook.WUnicodeStr((IntPtr)handVal, argStr);

                allocPtrList.Add(hand);
                Buffer_SquashIntoDwordResult = (uint)handVal;
            }
            else if (arg is IntPtr)
            {
                Buffer_SquashIntoDwordResult.Int1 = ((IntPtr)arg).ToInt32();
            }
            else
            {
                var size = Marshal.SizeOf(arg);

                if (size <= INT32_SIZE)
                {
                    IntPtr ptrToArg = Marshal.AllocHGlobal(size);
                    //Allocate a place for our arg
                    try
                    {
                        Marshal.StructureToPtr(arg, ptrToArg, true); //Move arg to where that pointer points
                        byte[] argByt = new byte[size]; //Make a new byte array the size of the arg
                        Marshal.Copy(ptrToArg, argByt, 0, size); //Copy bytes from [ptrToArg] to argByt
                        Buffer_SquashIntoDwordResult.SetBytes(argByt);
                    }
                    catch (Exception ex)
                    {
                        throw ex;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ptrToArg);
                    }
                }
                else
                {
                    //Allocate a place for our arg
                    IntPtr ptrToArg = Marshal.AllocHGlobal(size);

                    try
                    {
                        var hand = new SafeRemoteHandle(size);
                        var unmanagedArg = new SafeMarshalledHandle(arg);
                        hand.MemPatch(unmanagedArg);
                        allocPtrList.Add(hand);

                        Buffer_SquashIntoDwordResult = unmanagedArg.GetHandle().ToInt32();

                        if (unmanagedArg != null)
                        {
                            unmanagedArg.Close();
                            unmanagedArg.Dispose();
                            unmanagedArg = null;
                        }


                        //##### OLD METHOD: #####
                        //Move arg to where that pointer points
                        //Marshal.StructureToPtr(arg, ptrToArg, True)
                        //'Make a new byte array the size of the arg
                        //Dim argByt(size - 1) As Byte
                        //'Copy bytes from where we just moved that object to, over to our byte array
                        //Marshal.Copy(ptrToArg, argByt, 0, size)
                        //' > argByt NOW CONTAINS ARG AS BYTES <
                        //Dim ingamePtrToArg As New IngameAllocatedPtr(size)
                        //WriteProcessMemory(CurrentProcessHandle, ingamePtrToArg.Address, argByt, size, New Integer())
                        //allocPtrList.Add(ingamePtrToArg)
                        //Return ingamePtrToArg.Address
                    }
                    catch (Exception ex)
                    {
                        throw ex;
                        //We mainly here for dat Finally my boi
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ptrToArg);
                    }
                }
            }

            return Buffer_SquashIntoDwordResult.Int1;
        }

        public static Dictionary<Type, Func<byte[], dynamic>> TypeConvertCache = new Dictionary<Type, Func<byte[], dynamic>>()
        {
            { typeof(void), (b) => 0 },
            { typeof(byte), (b) => b[0] },
            { typeof(bool), (b) => (bool)(b[0] != 0) },
            { typeof(sbyte), (b) => (sbyte)b[0] },
            { typeof(short), (b) => BitConverter.ToInt16(b, 0) },
            { typeof(ushort), (b) => BitConverter.ToUInt16(b, 0) },
            { typeof(int), (b) => BitConverter.ToInt32(b, 0) },
            { typeof(uint), (b) => BitConverter.ToUInt32(b, 0) },
            { typeof(Int64), (b) => BitConverter.ToInt64(b, 0) },
            { typeof(float), (b) => BitConverter.ToSingle(b, 0) },
            { typeof(string), (b) => Hook.RAsciiStr(BitConverter.ToInt32(b, 0), 255 /* idk */) },
        };

        private dynamic GetFunctionCallResult<T>(byte[] result)
        {
            return TypeConvertCache[typeof(T)].Invoke(result);
        }

        public T CallIngameFuncReg<T>(Memloc functionAddress, IEnumerable<dynamic> args, 
            dynamic eax = null,
            dynamic ecx = null,
            dynamic edx = null,
            dynamic ebx = null,
            dynamic esp = null,
            dynamic esi = null,
            dynamic edi = null)
        {
            if (CodeHandle.IsClosed || CodeHandle.IsInvalid)
            {
                CompletelyReInitializeAndInjectCodeInNewLocation();
            }

            Kernel.CheckAddress(CodeHandle.GetHandle(), FUNCTION_CALL_ASM_BUFFER_SIZE, "execute function");

            Buffer_ParamPointerList.Clear();

            InitAsmBuffer(functionAddress, args, Buffer_ParamPointerList, eax, ecx, edx, ebx, esp, esi, edi);

            if (!InjectEntireCodeBuffer())
            {
                Extra.Dbg.PrintErr("WARNING: CODE INJECT FAILURE");
            }

            //luai.DebugUpdate()

            foreach (SafeRemoteHandle ptr in Buffer_ParamPointerList)
            {
                ptr.Dispose();
            }


            Buffer_ResultBytes = ExecuteAsm();

            Buffer_Result = GetFunctionCallResult<T>(Buffer_ResultBytes);

            foreach (SafeRemoteHandle ptr in Buffer_ParamPointerList)
            {
                ptr.Close();
                ptr.Dispose();
            }

            Buffer_ParamPointerList.Clear();

            return Buffer_Result;
        }

        public T CallIngameFunc64<T>(Memloc functionAddress, IEnumerable<dynamic> args)
        {
            if (CodeHandle.IsClosed || CodeHandle.IsInvalid)
            {
                CompletelyReInitializeAndInjectCodeInNewLocation();
            }

            Kernel.CheckAddress(CodeHandle.GetHandle(), FUNCTION_CALL_ASM_BUFFER_SIZE, "execute function");

            byte[] byt = InitAsm64Buffer(functionAddress, args, Buffer_ParamPointerList);

           

            if (!(WriteAsm(CodeHandle.GetHandle(), byt, byt.Length)))
            {
                Extra.Dbg.PrintErr("WARNING: CODE INJECT FAILURE");
            }

            foreach (SafeRemoteHandle ptr in Buffer_ParamPointerList)
            {
                ptr.Dispose();
            }

            Buffer_ResultBytes = ExecuteAsm();

            Buffer_Result = GetFunctionCallResult<T>(Buffer_ResultBytes);
            

            foreach (SafeRemoteHandle ptr in Buffer_ParamPointerList)
            {
                ptr.Close();
                ptr.Dispose();
            }

            Buffer_ParamPointerList.Clear();

            return Buffer_Result;
        }

        public T CallIngameFunc<T>(Memloc functionAddress, IEnumerable<dynamic> args)
        {
            if (CodeHandle.IsClosed || CodeHandle.IsInvalid)
            {
                CompletelyReInitializeAndInjectCodeInNewLocation();
            }

            Kernel.CheckAddress(CodeHandle.GetHandle(), FUNCTION_CALL_ASM_BUFFER_SIZE, "execute function");

            Buffer_ParamPointerList.Clear();

            InitAsmBuffer(functionAddress, args, Buffer_ParamPointerList);

            if (!InjectEntireCodeBuffer())
            {
                Extra.Dbg.PrintErr("WARNING: CODE INJECT FAILURE");
            }

            //luai.DebugUpdate()

            foreach (SafeRemoteHandle ptr in Buffer_ParamPointerList)
            {
                ptr.Dispose();
            }

            Buffer_ResultBytes = ExecuteAsm();

            Buffer_Result = GetFunctionCallResult<T>(Buffer_ResultBytes);

            foreach (SafeRemoteHandle ptr in Buffer_ParamPointerList)
            {
                ptr.Close();
                ptr.Dispose();
            }

            Buffer_ParamPointerList.Clear();

            return Buffer_Result;
        }

        #region "IDisposable Support"
        // To detect redundant calls
        private bool ____disposedValue;

        // IDisposable
        protected virtual void Dispose(bool disposing)
        {
            if (!____disposedValue)
            {
                if (disposing)
                {
                    ____freeClrManagedResources();
                }

                ____freeNativeUnmanagedResources();
            }
            ____disposedValue = true;
        }

        // TODO: override Finalize() only if Dispose(disposing As Boolean) above has code to free unmanaged resources.
        ~DSAsmCaller()
        {
            // Do not change this code.  Put cleanup code in Dispose(disposing As Boolean) above.
            Dispose(false);
        }

        // This code added by Visual Basic to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code.  Put cleanup code in Dispose(disposing As Boolean) above.
            Dispose(true);
            // TODO: uncomment the following line if Finalize() is overridden above.
            GC.SuppressFinalize(this);
        }
        #endregion

    }
}
