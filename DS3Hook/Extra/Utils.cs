﻿using System;
using DS3Hook.Injection;
using static DS3Hook.Hook;
//using static DarkSoulsScripting.ExtraFuncs;
using System.Threading;
using System.Diagnostics;

namespace DS3Hook.Extra
{
    public static class Utils
    {
        public const double MinLoadingScreenDur = 3.0;

        public static bool BitmaskCheck(ulong input, ulong mask)
        {
            return ((input & mask) == mask);
        }

        public static bool IsGameLoading()
        {
            IntPtr ptr = RIntPtr(0x137DC70);
            if ((Int64)ptr > (Int64)DarkSouls3Handle.BaseAddress)
                return ((Int64)RIntPtr(ptr + IntPtr.Size) < (Int64)DarkSouls3Handle.BaseAddress);
            else
                return true;
        }

        public static void WaitForLoadingScreenStart()
        {
            while (!IsGameLoading())
            {
                Thread.Sleep(33);
            }
        }

        public static void WaitForLoadingScreenEnd()
        {
            while (IsGameLoading())
            {
                Thread.Sleep(33);
            }
        }

        public static void WaitLoadCycle()
        {
            WaitForLoadingScreenStart();
            Thread.Sleep(33);
            WaitForLoadingScreenEnd();
        }

        //Function WAIT_FOR_GAME()
        //    ingameTimeStopped = True
        //    repeat
        //    ingameTime = RInt32(RInt32(0x1378700) + 0x68)
        //    ingameTimeStopped = (ingameTime == prevIngameTime)
        //    prevIngameTime = ingameTime
        //    until(Not ingameTimeStopped)
        //    End

        //public static void WaitForGame()
        //{
        //    int curIngameTime = 0;
        //    int prevIngameTime = 0;
        //    bool ingameTimeStopped = true;
        //    do
        //    {
        //        int ingameTimePointer = Hook.RInt32(0x1378700);
        //        if (ingameTimePointer != 0)
        //        {
        //            curIngameTime = Hook.RInt32(ingameTimePointer + 0x68);
        //            if (curIngameTime != 0)
        //            {
        //                //Only update time variables when a valid time value is read.
        //                ingameTimeStopped = (prevIngameTime == 0 || prevIngameTime == curIngameTime);
        //                prevIngameTime = curIngameTime; //
        //            }
        //        }

        //        ExtraFuncs.Wait(16);
        //    } while (ingameTimeStopped);
        //}

        //public static double WaitForGameAndMeasureDuration()
        //{
        //    var startTime = DateTime.Now;
        //    WaitForGame();

        //    return (1.0 * DateTime.Now.Subtract(startTime).Ticks / TimeSpan.TicksPerSecond);
        //}

        //public static void WaitUntilAfterNextLoadingScreen()
        //{
        //    double waitDuration = 0;
        //    do
        //    {
        //        waitDuration = WaitForGameAndMeasureDuration();
        //    } while (!(waitDuration >= MinLoadingScreenDur));
        //}

        private static Stopwatch FixedTimestepStopwatch = null;

        public static long GetTickSpanFromHz(double Hz)
        {
            return (long)(TimeSpan.TicksPerSecond / Hz);
        }

        public static void FixedTimestep(Action updateLoop, long timestepTicks)
        {
            if (FixedTimestepStopwatch == null)
                FixedTimestepStopwatch = Stopwatch.StartNew();
            updateLoop();
            //Sadly this will only have a resolution of every ~15 ms or so because Windows sucks.
            var modTicks = (FixedTimestepStopwatch.ElapsedTicks % timestepTicks);
            var waitTicks = timestepTicks - modTicks;
            if (modTicks > (timestepTicks / 2))
            {
                waitTicks += timestepTicks;
            }
            Thread.Sleep(TimeSpan.FromTicks(waitTicks));
            //FixedTimestepStopwatch.Restart();
        }

        public static IntPtr GetIngameDllAddress(string moduleName)
        {
            IntPtr[] modules = new IntPtr[255];
            uint cbNeeded = 0;
            PSAPI.EnumProcessModules(Hook.DarkSouls3Handle.GetHandle(), modules, 4 * 1024, ref cbNeeded);

            var numModules = cbNeeded / IntPtr.Size;

            for (int i = 0; i <= numModules - 1; i++)
            {
                var disModule = modules[i];
                System.Text.StringBuilder name = new System.Text.StringBuilder();
                PSAPI.GetModuleBaseName(Hook.DarkSouls3Handle.GetHandle(), disModule, name, 255);

                if ((name.ToString().ToUpper().Equals(moduleName.ToUpper())))
                {
                    return modules[i];
                }
            }

            return IntPtr.Zero;
        }
    }
}