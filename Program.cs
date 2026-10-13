using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using Reborn;

namespace FileHider
{
    // ==================== KEYAUTH CREDENTIALS ====================
    internal static class KeyAuthConfig
    {
        public const string NAME = "newp";
        public const string OWNERID = "VuRA53i3RR";
        public const string SECRET = "38dffa15eea53fd17c7f33d6f30adda3f2382c837f0d0c4b0f8243b48c29608d";
        public const string VERSION = "1.0";
    }

    internal static class Ioctl
    {
        const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        const uint METHOD_BUFFERED = 0;
        const uint FILE_ANY_ACCESS = 0;
        static uint CTL_CODE(uint d, uint f, uint m, uint a) => (d << 16) | (a << 14) | (f << 2) | m;

        public static readonly uint ADD_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint REMOVE_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint CLEAR_RULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint GET_COUNT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint LIST_RULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint GET_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint SET_SPOOF = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint GET_SPOOF = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint SET_HIDE_JOURNAL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint GET_HIDE_JOURNAL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint RESET = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90A, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint HIDE_NOW = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90B, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint SCRUB_JOURNAL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90C, METHOD_BUFFERED, FILE_ANY_ACCESS);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RULE_REQUEST
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string String;
        public ulong Usn;
        public override string ToString() =>
            Usn != 0 ? "USN   0x" + Usn.ToString("X16") : "STR   " + String;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct STATUS_REPLY
    {
        public uint Magic, Version;
        public ulong SessionId;
        public uint FilterAttached, RuleCount, LastError;
        public uint FsctlHits, FsctlFiltered, RecordsSeen, RecordsRemoved, ParseFailures;
        public uint ReadBlocked, QuerySpoofed, FileUsnFiltered, SpoofEmpty, HideJournal;
        public uint CreateHits, JournalBlocked;
        public uint PreOpSeen, PostOpSeen, PostOpNoBuf, PostOpInfoBad;
        public uint ReadPreSeen, ReadPostSeen, ReadNoBuf, ReadInfoBad, ReadMatched, ReadNameHits;
        public uint CreateNameHits, CreateUncacheForced;
        public uint LastCode, LastMethod, LastInfo, LastOutCap;
        public ulong LastOutBuf;
        public uint LastValidate, LastRecords, LastFiltered;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] LastRaw;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string FirstName;
        public uint FirstNameLen, Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DELETE_USN_JOURNAL_DATA { public ulong UsnJournalID; public uint DeleteFlags; }

    internal static class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFile(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle h, uint c, IntPtr ib, uint isz, IntPtr ob, uint osz, out uint br, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(SafeFileHandle h, IntPtr b, uint n, out uint r, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(SafeFileHandle h, IntPtr b, uint n, out uint w, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(SafeFileHandle h, long d, out long np, uint m);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushFileBuffers(SafeFileHandle h);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr a, UIntPtr s, uint t);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(string s, string n, out long l);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TOKEN_PRIVILEGES n, uint l, IntPtr p, IntPtr r);

        [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint SE_PRIVILEGE_ENABLED = 0x0002;
        public const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000, PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES { public long Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

        public static bool EnableBackupPrivileges()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token)) return false;
            bool allOk = true;
            foreach (var name in new[] { "SeBackupPrivilege", "SeRestorePrivilege", "SeManageVolumePrivilege", "SeDebugPrivilege" })
            {
                long luid;
                if (!LookupPrivilegeValue(null, name, out luid)) { allOk = false; continue; }
                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                };
                if (!AdjustTokenPrivileges(token, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero)) allOk = false;
                else if (Marshal.GetLastWin32Error() == 1300) allOk = false;
            }
            return allOk;
        }

        public static IntPtr AllocAligned(UIntPtr s) => VirtualAlloc(IntPtr.Zero, s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        public static void FreeAligned(IntPtr p) { if (p != IntPtr.Zero) VirtualFree(p, UIntPtr.Zero, MEM_RELEASE); }

        public const uint FILE_READ_ATTRIBUTES = 0x0080;
        public const uint FILE_SHARE_ALL = 0x00000007;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct FILE_ID_DESCRIPTOR
        {
            public uint dwSize;
            public int Type;
            public long FileId;
            public long Reserved;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenFileById(
            SafeFileHandle hVolumeHint,
            ref FILE_ID_DESCRIPTOR lpFileId,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwFlagsAndAttributes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFinalPathNameByHandle(
            IntPtr hFile,
            [Out] StringBuilder lpszFilePath,
            uint cchFilePath,
            uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);
    }

    public sealed class FileHiderClient : IDisposable
    {
        const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FH_MAGIC = 0x4F555443u;
        SafeFileHandle _handle;
        public bool IsConnected => _handle != null && !_handle.IsInvalid && !_handle.IsClosed;

        public FileHiderClient()
        {
            _handle = Win32.CreateFile(@"\\.\FileHider", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (_handle.IsInvalid) { _handle.Dispose(); _handle = null; throw new InvalidOperationException("Cannot open \\\\.\\FileHider — driver not loaded."); }
        }

        public STATUS_REPLY GetStatus()
        {
            var rep = new STATUS_REPLY { LastRaw = new byte[256], FirstName = "" };
            if (!IsConnected) return rep;
            int size = Marshal.SizeOf(typeof(STATUS_REPLY));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (Win32.DeviceIoControl(_handle, Ioctl.GET_STATUS, IntPtr.Zero, 0, buf, (uint)size, out _, IntPtr.Zero))
                    rep = (STATUS_REPLY)Marshal.PtrToStructure(buf, typeof(STATUS_REPLY));
                if (rep.LastRaw == null) rep.LastRaw = new byte[256];
                if (rep.FirstName == null) rep.FirstName = "";
                return rep;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public bool IsOurDriver() => GetStatus().Magic == FH_MAGIC;
        public void Reset() { if (IsConnected) Win32.DeviceIoControl(_handle, Ioctl.RESET, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero); }

        public int HideNow()
        {
            if (!IsConnected) return 0;
            IntPtr o = Marshal.AllocHGlobal(4);
            try { return Win32.DeviceIoControl(_handle, Ioctl.HIDE_NOW, IntPtr.Zero, 0, o, 4, out _, IntPtr.Zero) ? Marshal.ReadInt32(o) : 0; }
            finally { Marshal.FreeHGlobal(o); }
        }

        public int ScrubJournalViaDriver(List<ulong> usns)
        {
            if (!IsConnected || usns == null || usns.Count == 0) return -1;

            int size = usns.Count * sizeof(long);
            if (size > 4 * 1024 * 1024) return -1;

            IntPtr buf = Marshal.AllocHGlobal(Math.Max(size, 4));
            try
            {
                for (int i = 0; i < usns.Count; i++)
                    Marshal.WriteInt64(buf, i * 8, (long)usns[i]);

                uint br;
                if (!Win32.DeviceIoControl(_handle, Ioctl.SCRUB_JOURNAL, buf, (uint)size, buf, 4, out br, IntPtr.Zero))
                    return -1;
                if (br < 4) return -1;
                return Marshal.ReadInt32(buf);
            }
            catch { return -1; }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void AddStringRule(string s) => AddRuleInternal(s, 0);
        public void AddUsnRule(ulong u) => AddRuleInternal(null, u);

        void AddRuleInternal(string s, ulong u)
        {
            if (!IsConnected) throw new InvalidOperationException("Driver not connected.");
            var req = new RULE_REQUEST { String = s ?? "", Usn = u };
            int size = Marshal.SizeOf(typeof(RULE_REQUEST));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(req, buf, false);
                if (!Win32.DeviceIoControl(_handle, Ioctl.ADD_RULE, buf, (uint)size, IntPtr.Zero, 0, out _, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void RemoveStringRule(string s) => RemoveRuleInternal(s, 0);
        public void RemoveUsnRule(ulong u) => RemoveRuleInternal(null, u);

        void RemoveRuleInternal(string s, ulong u)
        {
            if (!IsConnected) return;
            var req = new RULE_REQUEST { String = s ?? "", Usn = u };
            int size = Marshal.SizeOf(typeof(RULE_REQUEST));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try { Marshal.StructureToPtr(req, buf, false); Win32.DeviceIoControl(_handle, Ioctl.REMOVE_RULE, buf, (uint)size, IntPtr.Zero, 0, out _, IntPtr.Zero); }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void ClearAll() { if (IsConnected) Win32.DeviceIoControl(_handle, Ioctl.CLEAR_RULES, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero); }

        public int GetCount()
        {
            if (!IsConnected) return 0;
            IntPtr b = Marshal.AllocHGlobal(4);
            try { return Win32.DeviceIoControl(_handle, Ioctl.GET_COUNT, IntPtr.Zero, 0, b, 4, out _, IntPtr.Zero) ? Marshal.ReadInt32(b) : 0; }
            finally { Marshal.FreeHGlobal(b); }
        }

        public void SetSpoof(bool v) => SetToggle(Ioctl.SET_SPOOF, v);
        public bool GetSpoof() => GetToggle(Ioctl.GET_SPOOF);
        public void SetHideJournal(bool v) => SetToggle(Ioctl.SET_HIDE_JOURNAL, v);
        public bool GetHideJournal() => GetToggle(Ioctl.GET_HIDE_JOURNAL);

        void SetToggle(uint ioctl, bool e)
        {
            if (!IsConnected) return;
            IntPtr b = Marshal.AllocHGlobal(4);
            try { Marshal.WriteInt32(b, e ? 1 : 0); Win32.DeviceIoControl(_handle, ioctl, b, 4, IntPtr.Zero, 0, out _, IntPtr.Zero); }
            finally { Marshal.FreeHGlobal(b); }
        }

        bool GetToggle(uint ioctl)
        {
            if (!IsConnected) return false;
            IntPtr b = Marshal.AllocHGlobal(4);
            try { return Win32.DeviceIoControl(_handle, ioctl, IntPtr.Zero, 0, b, 4, out _, IntPtr.Zero) && Marshal.ReadInt32(b) != 0; }
            finally { Marshal.FreeHGlobal(b); }
        }

        public void Dispose() { _handle?.Dispose(); _handle = null; }
    }

    internal static class DriverManager
    {
        public static void WipeStaleState()
        {
            try { using (var p = new FileHiderClient()) if (p.IsOurDriver()) p.Reset(); } catch { }
        }

        public static FileHiderClient LoadFresh()
        {
            WipeStaleState();
            try { KernelLoader.ForceUnload(); } catch { }
            Thread.Sleep(600);
            if (!KernelLoader.EnsureDriverLoaded())
                throw new InvalidOperationException("KernelLoader.EnsureDriverLoaded() returned false. Log: " + KernelLoader.GetLogPath());

            FileHiderClient c = null;
            Exception lastEx = null;
            for (int i = 0; i < 6; i++)
            {
                try { c = new FileHiderClient(); if (c.IsOurDriver()) break; c.Dispose(); c = null; }
                catch (Exception ex) { lastEx = ex; }
                Thread.Sleep(250);
            }
            if (c == null) throw new InvalidOperationException("Driver loaded but could not connect. " + (lastEx != null ? lastEx.Message : "No response."));
            c.Reset();
            return c;
        }

        public static void UnloadAndDisconnect(ref FileHiderClient c)
        {
            try { c?.Reset(); } catch { }
            try { c?.Dispose(); } catch { }
            c = null;
            try { KernelLoader.ForceUnload(); } catch { }
        }
    }

    public class UsnEntry
    {
        public ulong Usn;
        public ulong FileReferenceNumber;
        public ulong ParentFileReferenceNumber;
        public string Name;
        public string Volume;
        public string Path;

        public string UsnHex => "0x" + Usn.ToString("X16");

        public override string ToString()
        {
            string drive = (Volume ?? "??").PadRight(6);

            string name = Name ?? "";
            if (name.Length > 18) name = name.Substring(0, 15) + "...";
            name = name.PadRight(22);

            string path = Path ?? "";
            return drive + name + path;
        }
    }

    internal static class UsnJournalHelper
    {
        const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
        const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
        const uint FSCTL_DELETE_USN_JOURNAL = 0x0009009C;
        const uint FSCTL_CREATE_USN_JOURNAL = 0x000900E7;
        const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
        const uint FILE_SHARE_READ = 0x00000001, FILE_SHARE_WRITE = 0x00000002, FILE_SHARE_DELETE = 0x00000004;
        const uint OPEN_EXISTING = 3, FILE_ATTRIBUTE_HIDDEN = 0x02, FILE_ATTRIBUTE_SYSTEM = 0x04;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        public static Action<string> Diag = _ => { };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct READ_USN_JOURNAL_DATA_V0 { public long StartUsn; public uint ReasonMask, ReturnOnlyOnClose; public long Timeout, BytesToWaitFor; public ulong UsnJournalID; }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct USN_JOURNAL_DATA_V0 { public ulong UsnJournalID; public long FirstUsn, NextUsn, LowestValidUsn, MaxUsn; public ulong MaximumSize, AllocationDelta; }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct USN_RECORD_HEADER
        {
            public uint RecordLength; public ushort MajorVersion, MinorVersion;
            public ulong FileReferenceNumber, ParentFileReferenceNumber;
            public long Usn, TimeStamp;
            public uint Reason, SourceInfo, SecurityId, FileAttributes;
            public ushort FileNameLength, FileNameOffset;
        }

        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr h, uint d, IntPtr a, int l, int t, out IntPtr n);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int p);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);

        [DllImport("ntdll.dll")] static extern int NtCreateFile(out IntPtr fh, uint da, ref OBJECT_ATTRIBUTES oa, ref IO_STATUS_BLOCK io, IntPtr asz, uint fa, uint sa, uint cd, uint co, IntPtr eb, uint el);
        [DllImport("ntdll.dll")] static extern int RtlInitUnicodeString(out UNICODE_STRING d, string s);
        [DllImport("ntdll.dll")] static extern int RtlNtStatusToDosError(int s);

        [StructLayout(LayoutKind.Sequential)] struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
        [StructLayout(LayoutKind.Sequential)] struct IO_STATUS_BLOCK { public IntPtr Status, Information; }

        const uint FILE_OPEN_FOR_BACKUP_INTENT = 0x00002000, FILE_OPEN_REPARSE_POINT = 0x00200000, FILE_NON_DIRECTORY_FILE = 0x00000040;
        const uint OBJ_CASE_INSENSITIVE = 0x00000040, FILE_OPEN = 1, FILE_READ_DATA = 0x0001, FILE_WRITE_DATA = 0x0002, SYNCHRONIZE = 0x00100000;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, PROCESS_QUERY_INFORMATION = 0x0400;
        const uint TOKEN_DUPLICATE = 0x0002, TOKEN_IMPERSONATE = 0x0004, TOKEN_QUERY = 0x0008, TOKEN_ALL_ACCESS = 0xF01FF;
        const int SecurityImpersonation = 2, TokenImpersonation = 2;

        static SafeFileHandle OpenForBackup(string ntPath)
        {
            UNICODE_STRING us; RtlInitUnicodeString(out us, ntPath);
            IntPtr usBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(us, usBuf, false);
            var oa = new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)), ObjectName = usBuf, Attributes = OBJ_CASE_INSENSITIVE };
            var io = new IO_STATUS_BLOCK();
            IntPtr h;
            int st = NtCreateFile(out h, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, ref oa, ref io, IntPtr.Zero,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE, IntPtr.Zero, 0);
            Marshal.FreeHGlobal(usBuf);
            if (st < 0) { int w = RtlNtStatusToDosError(st); throw new Win32Exception(w, "NtCreateFile backup-intent failed (0x" + st.ToString("X8") + ", Win32 " + w + ")"); }
            return new SafeFileHandle(h, true);
        }

        static bool GetSystemToken(out IntPtr hDup)
        {
            hDup = IntPtr.Zero;
            Process wl = null;
            try
            {
                int myS = Process.GetCurrentProcess().SessionId;
                foreach (var p in Process.GetProcessesByName("winlogon")) if (p.SessionId == myS) { wl = p; break; }
                if (wl == null) { Diag("impersonate: no winlogon"); return false; }
                IntPtr hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, false, wl.Id);
                if (hp == IntPtr.Zero) { Diag("impersonate: OpenProcess err=" + Marshal.GetLastWin32Error()); return false; }
                try
                {
                    IntPtr ht;
                    if (!Win32.OpenProcessToken(hp, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out ht)) { Diag("impersonate: OpenProcessToken err=" + Marshal.GetLastWin32Error()); return false; }
                    try
                    {
                        bool ok = DuplicateTokenEx(ht, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out hDup);
                        if (!ok) Diag("impersonate: DuplicateTokenEx err=" + Marshal.GetLastWin32Error());
                        return ok;
                    }
                    finally { CloseHandle(ht); }
                }
                finally { CloseHandle(hp); }
            }
            catch (Exception ex) { Diag("impersonate: " + ex.Message); return false; }
            finally { wl?.Dispose(); }
        }

        static USN_JOURNAL_DATA_V0 QueryJournal(string vol)
        {
            using (var h = Win32.CreateFile(@"\\.\" + vol, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open volume " + vol + " failed");
                int os = Marshal.SizeOf(typeof(USN_JOURNAL_DATA_V0));
                IntPtr ob = Marshal.AllocHGlobal(os);
                try
                {
                    if (!Win32.DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, ob, (uint)os, out _, IntPtr.Zero))
                    { int e = Marshal.GetLastWin32Error(); throw new Win32Exception(e, "FSCTL_QUERY_USN_JOURNAL failed (Win32 " + e + ")"); }
                    return (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(ob, typeof(USN_JOURNAL_DATA_V0));
                }
                finally { Marshal.FreeHGlobal(ob); }
            }
        }

        public static List<UsnEntry> EnumerateAll(string vol)
        {
            var list = new List<UsnEntry>();
            var jd = QueryJournal(vol);
            using (var h = Win32.CreateFile(@"\\.\" + vol, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open volume for READ_USN_JOURNAL failed");
                var req = new READ_USN_JOURNAL_DATA_V0 { StartUsn = jd.FirstUsn, ReasonMask = 0xFFFFFFFF, UsnJournalID = jd.UsnJournalID };
                int isz = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
                int osz = 32 * 1024 * 1024;
                IntPtr ib = Marshal.AllocHGlobal(isz);
                IntPtr ob = Marshal.AllocHGlobal(osz);
                try
                {
                    int guard = 0;
                    while (req.StartUsn < jd.NextUsn && guard++ < 1000000)
                    {
                        Marshal.StructureToPtr(req, ib, false);
                        if (!Win32.DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, ib, (uint)isz, ob, (uint)osz, out uint ret, IntPtr.Zero))
                        {
                            int e = Marshal.GetLastWin32Error();
                            if (e == 38 || e == 1178 || e == 1179) break;
                            throw new Win32Exception(e, "FSCTL_READ_USN_JOURNAL failed (Win32 " + e + ")");
                        }
                        if (ret < 8) break;
                        ulong next = (ulong)Marshal.ReadInt64(ob);
                        int off = 8, cnt = 0;
                        while (off + 8 <= (int)ret)
                        {
                            uint rl = (uint)Marshal.ReadInt32(ob, off);
                            if (rl < 24 || rl > 0x10000) break;
                            if (off + rl > (int)ret) break;
                            ushort mj = (ushort)Marshal.ReadInt16(ob, off + 4);
                            if (mj != 2 && mj != 3) break;
                            int hs = (mj == 2) ? 60 : 76;
                            if (off + hs > (int)ret) break;
                            var hdr = (USN_RECORD_HEADER)Marshal.PtrToStructure(ob + off, typeof(USN_RECORD_HEADER));
                            ushort nl = (ushort)Marshal.ReadInt16(ob, off + hs - 4);
                            ushort no = (ushort)Marshal.ReadInt16(ob, off + hs - 2);
                            string nm = "";
                            if (nl > 0 && (int)(no + nl) <= rl) nm = Marshal.PtrToStringUni(ob + off + no, nl / 2);
                            list.Add(new UsnEntry { Usn = (ulong)hdr.Usn, FileReferenceNumber = hdr.FileReferenceNumber, ParentFileReferenceNumber = hdr.ParentFileReferenceNumber, Name = nm, Volume = vol });
                            off = (off + (int)rl + 7) & ~7; cnt++;
                        }
                        if (next == 0) break;
                        if ((ulong)req.StartUsn == next) break;
                        if (cnt == 0 && ret <= 8) break;
                        req.StartUsn = (long)next;
                    }
                }
                finally { Marshal.FreeHGlobal(ib); Marshal.FreeHGlobal(ob); }
            }
            return list;
        }

        public static string ResolvePath(string vol, ulong frn)
        {
            try
            {
                using (var hVol = Win32.CreateFile(@"\\.\" + vol, 0, Win32.FILE_SHARE_ALL, IntPtr.Zero, Win32.OPEN_EXISTING, 0, IntPtr.Zero))
                {
                    if (hVol.IsInvalid) return null;

                    var desc = new Win32.FILE_ID_DESCRIPTOR
                    {
                        dwSize = (uint)Marshal.SizeOf(typeof(Win32.FILE_ID_DESCRIPTOR)),
                        Type = 0,
                        FileId = (long)frn,
                        Reserved = 0
                    };

                    IntPtr hFile = Win32.OpenFileById(hVol, ref desc, Win32.FILE_READ_ATTRIBUTES,
                        Win32.FILE_SHARE_ALL, IntPtr.Zero, Win32.FILE_FLAG_BACKUP_SEMANTICS);

                    if (hFile == IntPtr.Zero || hFile == new IntPtr(-1)) return null;

                    try
                    {
                        var sb = new StringBuilder(1024);
                        uint n = Win32.GetFinalPathNameByHandle(hFile, sb, (uint)sb.Capacity, 0);
                        if (n == 0 || n >= sb.Capacity) return null;
                        string p = sb.ToString();
                        if (p.StartsWith(@"\\?\")) p = p.Substring(4);
                        if (p.StartsWith(@"\??\")) p = p.Substring(4);
                        return p;
                    }
                    finally { Win32.CloseHandle(hFile); }
                }
            }
            catch { return null; }
        }

        public static int ScrubOnDisk(string vol, List<ulong> usns, Action<int> progress = null)
        {
            if (usns.Count == 0) return 0;
            var set = new HashSet<ulong>(usns);
            bool p = Win32.EnableBackupPrivileges();
            Diag("scrub: privileges=" + p + " N=" + usns.Count);

            try
            {
                Diag("scrub: try NtCreateFile backup-intent");
                var h = OpenForBackup(@"\??\" + vol + @"\$Extend\$UsnJrnl:$J");
                if (h != null && !h.IsInvalid)
                {
                    Diag("scrub: opened via NtCreateFile");
                    try { return DoScrubHandle(h, set, progress); } finally { h.Dispose(); }
                }
            }
            catch (Exception ex) { Diag("scrub: NtCreateFile → " + ex.Message); }

            IntPtr st;
            if (GetSystemToken(out st))
            {
                try
                {
                    if (ImpersonateLoggedOnUser(st))
                    {
                        Diag("scrub: impersonating SYSTEM");
                        try
                        {
                            var h = OpenForBackup(@"\??\" + vol + @"\$Extend\$UsnJrnl:$J");
                            if (h != null && !h.IsInvalid)
                            {
                                Diag("scrub: opened as SYSTEM");
                                try { return DoScrubHandle(h, set, progress); } finally { h.Dispose(); }
                            }
                        }
                        catch (Exception ex) { Diag("scrub: SYSTEM → " + ex.Message); }
                        finally { RevertToSelf(); }
                    }
                }
                finally { CloseHandle(st); }
            }

            string[] paths = { @"\\?\" + vol + @"\$Extend\$UsnJrnl:$J", @"\\.\" + vol + @"\$Extend\$UsnJrnl:$J" };
            foreach (var p2 in paths)
            {
                try
                {
                    var h = Win32.CreateFile(p2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                    if (!h.IsInvalid) { Diag("scrub: opened via CreateFile " + p2); try { return DoScrubHandle(h, set, progress); } finally { h.Dispose(); } }
                    int e = Marshal.GetLastWin32Error(); h.Dispose();
                    Diag("scrub: CreateFile " + p2 + " err=" + e);
                }
                catch (Exception ex) { Diag("scrub: CreateFile " + p2 + " → " + ex.Message); }
            }

            Diag("scrub: all userland opens failed, not purging to avoid flagging");
            throw new Win32Exception(5,
                "Cannot open $UsnJrnl:$J for direct write (ACL on 22631). "
                + "Load the kernel driver and press LOAD, then retry — driver scrub works around this.");
        }

        static int DoScrubHandle(SafeFileHandle h, HashSet<ulong> set, Action<int> progress)
        {
            const int CHUNK = 64 * 1024 * 1024;
            IntPtr b = Win32.AllocAligned((UIntPtr)CHUNK);
            if (b == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAlloc failed");
            int patched = 0;
            try
            {
                long sz = 0; Win32.SetFilePointerEx(h, 0, out sz, 2); Win32.SetFilePointerEx(h, 0, out _, 0);
                Diag("scrub: journal size = " + sz);
                if (sz < 32) throw new InvalidOperationException("Journal too small");
                long pos = 0;
                while (pos < sz)
                {
                    uint toRead = (uint)Math.Min(CHUNK, sz - pos); if (toRead == 0) break;
                    if (!Win32.SetFilePointerEx(h, pos, out _, 0)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Seek");
                    if (!Win32.ReadFile(h, b, toRead, out uint got, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadFile");
                    if (got == 0) break;
                    bool mod = false; int off = 0;
                    while (off + 8 <= (int)got)
                    {
                        uint rl = (uint)Marshal.ReadInt32(b, off);
                        bool ok = false; int hs = 0; ushort mj = 0;
                        if (rl >= 24 && rl <= 0x10000)
                        {
                            mj = (ushort)Marshal.ReadInt16(b, off + 4);
                            if (mj == 2 || mj == 3) { hs = (mj == 2) ? 60 : 76; if (rl >= (uint)hs && off + rl <= (int)got) ok = true; }
                        }
                        if (!ok) { off += 8; continue; }
                        int uo = (mj == 2) ? 24 : 40;
                        long u = Marshal.ReadInt64(b, off + uo);
                        ushort nl = (ushort)Marshal.ReadInt16(b, off + hs - 4);
                        ushort no = (ushort)Marshal.ReadInt16(b, off + hs - 2);
                        if (set.Contains((ulong)u))
                        {
                            if (nl > 0 && no + nl <= rl) for (int i = 0; i < nl; i++) Marshal.WriteByte(b, off + no + i, 0);
                            Marshal.WriteInt16(b, off + hs - 4, 0);
                            mod = true; patched++; progress?.Invoke(patched);
                        }
                        off = (off + (int)rl + 7) & ~7;
                    }
                    if (mod)
                    {
                        if (!Win32.SetFilePointerEx(h, pos, out _, 0)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Re-seek");
                        if (!Win32.WriteFile(h, b, got, out uint w, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile");
                        if (w != got) throw new InvalidOperationException("Short write");
                    }
                    pos += got;
                }
                Win32.FlushFileBuffers(h);
            }
            finally { Win32.FreeAligned(b); }
            return patched;
        }

        public static void PurgeWholeJournal(string vol)
        {
            Win32.EnableBackupPrivileges();
            var jd = QueryJournal(vol);

            try { PurgeViaHandle(@"\\.\" + vol, jd.UsnJournalID); Diag("purge: FSCTL OK"); try { CreateJournal(vol); } catch { } return; }
            catch (Exception e1) { Diag("purge: FSCTL " + e1.Message); }

            try { PurgeViaFsutil(vol); Diag("purge: fsutil OK"); try { CreateJournal(vol); } catch { } return; }
            catch (Exception e2) { Diag("purge: fsutil " + e2.Message); }

            IntPtr st;
            if (GetSystemToken(out st))
            {
                try
                {
                    if (ImpersonateLoggedOnUser(st))
                    {
                        try { PurgeViaHandle(@"\\.\" + vol, jd.UsnJournalID); Diag("purge: SYSTEM OK"); RevertToSelf(); try { CreateJournal(vol); } catch { } return; }
                        catch (Exception e3) { Diag("purge: SYSTEM " + e3.Message); RevertToSelf(); }
                    }
                }
                finally { CloseHandle(st); }
            }

            throw new Exception("Cannot purge journal by any method.");
        }

        static void PurgeViaHandle(string path, ulong jid)
        {
            using (var h = Win32.CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid) { int e = Marshal.GetLastWin32Error(); throw new Win32Exception(e, "Open err=" + e); }
                var d = new DELETE_USN_JOURNAL_DATA { UsnJournalID = jid, DeleteFlags = 1 };
                int s = Marshal.SizeOf(typeof(DELETE_USN_JOURNAL_DATA));
                IntPtr b = Marshal.AllocHGlobal(s);
                try
                {
                    Marshal.StructureToPtr(d, b, false);
                    if (!Win32.DeviceIoControl(h, FSCTL_DELETE_USN_JOURNAL, b, (uint)s, IntPtr.Zero, 0, out _, IntPtr.Zero))
                    { int e = Marshal.GetLastWin32Error(); throw new Win32Exception(e, "FSCTL_DELETE err=" + e); }
                }
                finally { Marshal.FreeHGlobal(b); }
            }
        }

        static void CreateJournal(string vol)
        {
            using (var h = Win32.CreateFile(@"\\.\" + vol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid) return;
                var d = new CREATE_USN_JOURNAL_DATA { MaximumSize = 0x2000000, AllocationDelta = 0x800000 };
                int s = Marshal.SizeOf(typeof(CREATE_USN_JOURNAL_DATA));
                IntPtr b = Marshal.AllocHGlobal(s);
                try { Marshal.StructureToPtr(d, b, false); Win32.DeviceIoControl(h, FSCTL_CREATE_USN_JOURNAL, b, (uint)s, IntPtr.Zero, 0, out _, IntPtr.Zero); }
                finally { Marshal.FreeHGlobal(b); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CREATE_USN_JOURNAL_DATA { public ulong MaximumSize; public ulong AllocationDelta; }

        static void PurgeViaFsutil(string vol)
        {
            var psi = new ProcessStartInfo { FileName = "fsutil.exe", Arguments = "usn deletejournal /d " + vol.TrimEnd(':') + ":", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(60000);
                if (p.ExitCode != 0) throw new Exception("fsutil exit " + p.ExitCode + ": " + p.StandardError.ReadToEnd());
            }
        }
    }

    internal static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(11, 11, 15);
        public static readonly Color Card = Color.FromArgb(20, 20, 26);
        public static readonly Color CardHi = Color.FromArgb(26, 26, 34);
        public static readonly Color Input = Color.FromArgb(30, 30, 38);
        public static readonly Color Border = Color.FromArgb(42, 42, 54);
        public static readonly Color BorderHi = Color.FromArgb(64, 64, 82);
        public static readonly Color Text = Color.FromArgb(228, 228, 233);
        public static readonly Color TextMuted = Color.FromArgb(138, 138, 152);
        public static readonly Color Accent = Color.FromArgb(34, 211, 238);
        public static readonly Color AccentDark = Color.FromArgb(14, 116, 144);
        public static readonly Color Success = Color.FromArgb(52, 211, 153);
        public static readonly Color Warning = Color.FromArgb(251, 191, 36);
        public static readonly Color Danger = Color.FromArgb(248, 113, 113);
        public static readonly Color Violet = Color.FromArgb(167, 139, 250);

        public static readonly Color Neutral = Color.FromArgb(55, 55, 68);
        public static readonly Color Red = Color.FromArgb(150, 60, 60);
        public static readonly Color RedDark = Color.FromArgb(110, 35, 45);

        public const string DiscordInvite = "https://discord.gg/Xh3Tz2d8vT";
        public const string DiscordId = "@meow_x2";
        public const string Developer = "B!LLA";

        public const string LogoUrl = "https://raw.githubusercontent.com/billa9889/asdasd/main/logo.jpg";

        public static Font F(float s, FontStyle st = FontStyle.Regular) => new Font("Segoe UI", s, st);
        public static Font Mono(float s, FontStyle st = FontStyle.Regular) => new Font("Consolas", s, st);

        public static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            var path = new GraphicsPath();
            int d = radius * 2;
            if (d > r.Width) d = r.Width;
            if (d > r.Height) d = r.Height;
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d - 1, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d - 1, r.Bottom - d - 1, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d - 1, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    internal class FlatButton : Button
    {
        Color _b, _h, _p;
        public FlatButton(Color b, Color h, Color p)
        {
            _b = b; _h = h; _p = p;
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            BackColor = _b;
            ForeColor = Theme.Text;
            Font = Theme.F(8.5f, FontStyle.Bold);
            Cursor = Cursors.Hand;
            MouseEnter += (s, e) => { if (Enabled) BackColor = _h; };
            MouseLeave += (s, e) => { if (Enabled) BackColor = _b; };
            MouseDown += (s, e) => { if (Enabled) BackColor = _p; };
            MouseUp += (s, e) => { if (Enabled) BackColor = ClientRectangle.Contains(PointToClient(MousePosition)) ? _h : _b; };
            EnabledChanged += (s, e) => { BackColor = Enabled ? _b : Color.FromArgb(40, 40, 48); ForeColor = Enabled ? Theme.Text : Theme.TextMuted; };
        }
    }

    internal class CardPanel : Panel
    {
        public string Title { get; set; }
        public Color AccentColor { get; set; } = Theme.Accent;
        public CardPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Card;
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var b = new SolidBrush(Theme.Card)) g.FillRectangle(b, ClientRectangle);
            using (var p = new Pen(Theme.Border, 1)) g.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
            if (!string.IsNullOrEmpty(Title))
            {
                using (var b = new SolidBrush(AccentColor)) g.FillRectangle(b, 12, 10, 3, 12);
                using (var f = new Font("Segoe UI Semibold", 8.5f))
                using (var tb = new SolidBrush(Theme.Text))
                    g.DrawString(Title, f, tb, 22, 9);
            }
        }
    }

    // ==================== KEYAUTH LOGIN FORM ====================
    internal class LoginForm : Form
    {
        TextBox _txtUser, _txtPass;
        FlatButton _btnLogin;
        Label _lblStatus, _lblTitle, _lblSub;
        Panel _card;

        public bool Authenticated { get; private set; }
        public string AuthMessage { get; private set; }

        private readonly Reborn.api _api;

        public LoginForm(Reborn.api api)
        {
            _api = api;

            Text = "Authentication  —  " + Theme.Developer;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = Theme.F(9f);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(420, 320);
            DoubleBuffered = true;

            _card = new CardPanel
            {
                Location = new Point(20, 20),
                Size = new Size(380, 280),
                BackColor = Theme.Card
            };

            _lblTitle = new Label
            {
                Text = "USN JOURNAL SCRUBBER",
                Location = new Point(24, 30),
                AutoSize = true,
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                ForeColor = Theme.Accent,
                BackColor = Color.Transparent
            };

            _lblSub = new Label
            {
                Text = "authenticate to continue",
                Location = new Point(26, 58),
                AutoSize = true,
                Font = Theme.F(8.5f),
                ForeColor = Theme.TextMuted,
                BackColor = Color.Transparent
            };

            var lblUser = new Label
            {
                Text = "Username",
                Location = new Point(26, 100),
                AutoSize = true,
                Font = Theme.F(8.5f),
                ForeColor = Theme.TextMuted,
                BackColor = Color.Transparent
            };

            _txtUser = new TextBox
            {
                Location = new Point(26, 120),
                Width = 328,
                BackColor = Theme.Input,
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = Theme.F(10f)
            };

            var lblPass = new Label
            {
                Text = "Password",
                Location = new Point(26, 154),
                AutoSize = true,
                Font = Theme.F(8.5f),
                ForeColor = Theme.TextMuted,
                BackColor = Color.Transparent
            };

            _txtPass = new TextBox
            {
                Location = new Point(26, 174),
                Width = 328,
                BackColor = Theme.Input,
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = Theme.F(10f),
                UseSystemPasswordChar = true
            };

            _btnLogin = new FlatButton(Theme.AccentDark, Color.FromArgb(20, 150, 180), Color.FromArgb(10, 90, 115))
            {
                Text = "LOGIN",
                Location = new Point(26, 214),
                Size = new Size(328, 34)
            };
            _btnLogin.Click += async (s, e) => await DoLogin();

            _lblStatus = new Label
            {
                Text = "",
                Location = new Point(26, 252),
                Size = new Size(328, 18),
                Font = Theme.F(8.5f),
                ForeColor = Theme.Warning,
                BackColor = Color.Transparent
            };

            _card.Controls.AddRange(new Control[] {
                _lblTitle, _lblSub,
                lblUser, _txtUser,
                lblPass, _txtPass,
                _btnLogin, _lblStatus
            });

            Controls.Add(_card);

            AcceptButton = _btnLogin;
            _txtUser.Focus();
        }

        async System.Threading.Tasks.Task DoLogin()
        {
            string u = _txtUser.Text.Trim();
            string p = _txtPass.Text;

            if (string.IsNullOrWhiteSpace(u)) { SetStatus("Username cannot be empty.", true); return; }
            if (string.IsNullOrWhiteSpace(p)) { SetStatus("Password cannot be empty.", true); return; }

            _btnLogin.Enabled = false;
            _txtUser.Enabled = false;
            _txtPass.Enabled = false;
            SetStatus("Authenticating…", false);

            try
            {
                await System.Threading.Tasks.Task.Run(() =>
                {
                    _api.login(u, p);
                });

                if (_api.response != null && _api.response.success)
                {
                    Authenticated = true;
                    AuthMessage = "OK";
                    SetStatus("Authenticated. Loading…", false);
                    await System.Threading.Tasks.Task.Delay(350);
                    DialogResult = DialogResult.OK;
                    Close();
                }
                else
                {
                    string msg = _api.response != null ? _api.response.message : "No response from auth server.";
                    AuthMessage = msg;
                    SetStatus("Login failed: " + msg, true);
                    _btnLogin.Enabled = true;
                    _txtUser.Enabled = true;
                    _txtPass.Enabled = true;
                }
            }
            catch (Exception ex)
            {
                AuthMessage = ex.Message;
                SetStatus("Login error: " + ex.Message, true);
                _btnLogin.Enabled = true;
                _txtUser.Enabled = true;
                _txtPass.Enabled = true;
            }
        }

        void SetStatus(string text, bool warn)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string, bool>(SetStatus), text, warn); return; }
            _lblStatus.Text = text;
            _lblStatus.ForeColor = warn ? Theme.Danger : Theme.Success;
        }
    }

    public class MainForm : Form
    {
        ComboBox _cmbVolume;
        TextBox _txtString, _txtUsn, _txtSearch, _txtDiag;
        Button _btnAddString, _btnAddUsn, _btnRemoveRule, _btnClearRules;
        Button _btnSearch, _btnClearFound, _btnHide;
        Button _btnLoadDriver, _btnUnloadDriver, _btnVerify, _btnRefresh;
        ListBox _lstRules, _lstFound;
        CheckBox _chkHideJournal;
        Label _lblDriver, _lblStatus;

        Panel _header, _rulesCard, _searchCard, _driverCard, _diagCard, _statusBar;
        Panel _logoBox;
        Image _logoImage;

        FileHiderClient _client;
        readonly List<RULE_REQUEST> _rules = new List<RULE_REQUEST>();
        readonly List<UsnEntry> _found = new List<UsnEntry>();
        readonly Dictionary<ulong, string> _pathCache = new Dictionary<ulong, string>();
        bool _suppressToggleEvents = false;

        public MainForm(FileHiderClient client)
        {
            _client = client;
            UsnJournalHelper.Diag = LogDiag;

            AutoScaleMode = AutoScaleMode.Dpi;

            Text = "USN Journal Scrubber  —  by " + Theme.Developer;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = Theme.F(9f);
            DoubleBuffered = true;

            _logoImage = TryLoadLogo();

            var wa = Screen.PrimaryScreen.WorkingArea;
            int w = Math.Min(1120, (int)(wa.Width * 0.72));
            int h = Math.Min(800, (int)(wa.Height * 0.78));
            if (w < 1000) w = 1000;
            if (h < 700) h = 700;
            ClientSize = new Size(w, h);
            MinimumSize = new Size(1000, 700);
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = true;
            StartPosition = FormStartPosition.CenterScreen;

            BuildHeader();
            BuildRulesCard();
            BuildSearchCard();
            BuildDriverCard();
            BuildDiagCard();
            BuildStatusBar();

            Resize += (s, e) => LayoutCards();

            RedrawRulesList();
            RefreshList();
            LayoutCards();
        }

        static Image TryLoadLogo()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string cachePath = Path.Combine(baseDir, "logo_cache.jpg");

            try
            {
                if (File.Exists(cachePath))
                {
                    using (var fs = File.OpenRead(cachePath))
                    {
                        var img = Image.FromStream(fs);
                        return new Bitmap(img);
                    }
                }
            }
            catch { }

            try
            {
                var asm = Assembly.GetExecutingAssembly();
                using (var s = asm.GetManifestResourceStream("Logo"))
                    if (s != null) return Image.FromStream(s);
            }
            catch { }

            try
            {
                foreach (var name in new[] { "logo.png", "logo.jpg", "logo.jpeg", "Logo.png", "Logo.jpg" })
                {
                    string p = Path.Combine(baseDir, name);
                    if (File.Exists(p)) return Image.FromFile(p);
                }
            }
            catch { }

            try
            {
                ServicePointManager.SecurityProtocol =
                    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                using (var wc = new WebClient())
                {
                    wc.Headers.Add("User-Agent", "FileHider/" + Theme.Developer);
                    byte[] data = wc.DownloadData(Theme.LogoUrl);
                    File.WriteAllBytes(cachePath, data);
                    using (var ms = new MemoryStream(data))
                        return Image.FromStream(ms);
                }
            }
            catch { }

            return null;
        }

        public void SetLogo(Image img)
        {
            _logoImage = img;
            _logoBox?.Invalidate();
        }

        string ResolvePathCached(string vol, ulong frn)
        {
            if (_pathCache.TryGetValue(frn, out var cached)) return cached;
            string p = UsnJournalHelper.ResolvePath(vol, frn);
            _pathCache[frn] = p;
            return p;
        }

        void LayoutCards()
        {
            if (_header == null) return;

            int pad = 12;
            int gap = 8;
            int w = ClientSize.Width;
            int h = ClientSize.Height;

            int headerH = 92;
            int rulesH = 300;
            int driverH = 102;
            int statusH = 24;
            int minDiagH = 120;

            _header.Location = new Point(pad, pad);
            _header.Size = new Size(w - pad * 2, headerH);

            int rulesW = Math.Max(420, (w - pad * 2 - gap) * 54 / 100);
            int searchW = w - pad * 2 - rulesW - gap;

            _rulesCard.Location = new Point(pad, pad + headerH + gap);
            _rulesCard.Size = new Size(rulesW, rulesH);

            _searchCard.Location = new Point(pad + rulesW + gap, pad + headerH + gap);
            _searchCard.Size = new Size(searchW, rulesH);

            _driverCard.Location = new Point(pad, pad + headerH + gap + rulesH + gap);
            _driverCard.Size = new Size(w - pad * 2, driverH);

            _statusBar.Location = new Point(pad, h - pad - statusH);
            _statusBar.Size = new Size(w - pad * 2, statusH);

            int diagTop = _driverCard.Location.Y + _driverCard.Height + gap;
            int diagBot = _statusBar.Location.Y - gap;
            int diagH = Math.Max(minDiagH, diagBot - diagTop);

            _diagCard.Location = new Point(pad, diagTop);
            _diagCard.Size = new Size(w - pad * 2, diagH);

            if (_txtDiag != null)
                _txtDiag.Size = new Size(_diagCard.Width - 32, _diagCard.Height - 46);

            if (_rulesCard != null)
            {
                int rw = _rulesCard.Width;
                _btnAddString.Left = rw - 20 - _btnAddString.Width;
                _txtString.Width = Math.Max(150, _btnAddString.Left - _txtString.Left - 8);
                _btnAddUsn.Left = rw - 20 - _btnAddUsn.Width;
                _txtUsn.Width = Math.Max(150, _btnAddUsn.Left - _txtUsn.Left - 8);
                _lstRules.Width = rw - 40;
                _lstRules.Height = Math.Max(80, _rulesCard.Height - 210);
                int by = _rulesCard.Height - 40;
                _btnRemoveRule.Top = by;
                _btnClearRules.Top = by;
            }

            if (_searchCard != null)
            {
                int sw = _searchCard.Width;
                _btnSearch.Left = sw - 20 - _btnSearch.Width;
                _txtSearch.Width = Math.Max(150, _btnSearch.Left - _txtSearch.Left - 8);
                foreach (Control c in _searchCard.Controls)
                    if (c is Panel p && p.Height == 20) p.Width = sw - 40;
                _lstFound.Width = sw - 40;
                int by = _searchCard.Height - 40;
                _lstFound.Height = Math.Max(80, by - _lstFound.Top - 12);
                _btnClearFound.Top = by;
                _btnHide.Top = by;
                _btnHide.Left = sw - 20 - _btnHide.Width;

                int clearRight = _btnClearFound.Left + _btnClearFound.Width;
                if (_btnHide.Left < clearRight + 22)
                    _btnHide.Left = clearRight + 22;
            }

            if (_driverCard != null)
            {
                int rightEdge = _driverCard.Width - 16;
                int rowY = _driverCard.Height - 36;

                _btnUnloadDriver.Top = rowY;
                _btnUnloadDriver.Left = rightEdge - _btnUnloadDriver.Width;
                _btnLoadDriver.Top = rowY;
                _btnLoadDriver.Left = _btnUnloadDriver.Left - 8 - _btnLoadDriver.Width;
                _btnRefresh.Top = rowY;
                _btnRefresh.Left = _btnLoadDriver.Left - 8 - _btnRefresh.Width;
                _btnVerify.Top = rowY;
                _btnVerify.Left = _btnRefresh.Left - 8 - _btnVerify.Width;

                _chkHideJournal.Top = 14;
                _chkHideJournal.Left = rightEdge - _chkHideJournal.Width;

                _lblDriver.Left = 16;
                _lblDriver.Top = 36;
                _lblDriver.Width = _driverCard.Width - 32;
                _lblDriver.Height = 22;
            }
        }

        void BuildHeader()
        {
            const int HeaderTop = 12;
            const int HeaderSideMargin = 12;
            const int HeaderHeight = 92;
            const int DevPanelWidth = 380;
            const int DevPanelHeight = 64;
            const int JoinX = 250;
            const int JoinY = 8;
            const int JoinW = 112;
            const int JoinH = 28;

            _header = new Panel
            {
                Location = new Point(HeaderSideMargin, HeaderTop),
                Size = new Size(Math.Max(1, ClientSize.Width - HeaderSideMargin * 2), HeaderHeight),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                BackColor = Theme.Card
            };

            _header.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;

                using (var b = new SolidBrush(Theme.Card))
                    g.FillRectangle(b, _header.ClientRectangle);

                using (var p = new Pen(Theme.Border, 1))
                    g.DrawRectangle(p, 0, 0, _header.Width - 1, _header.Height - 1);
            };

            var titlePanel = new Panel
            {
                Location = new Point(20, 16),
                Size = new Size(500, 34),
                BackColor = Theme.Card
            };

            titlePanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                float fontSize = titlePanel.Width < 340 ? 14f : 17f;

                using (var f = new Font("Segoe UI", fontSize, FontStyle.Bold))
                using (var sf = new StringFormat(StringFormat.GenericTypographic))
                {
                    sf.FormatFlags |= StringFormatFlags.NoWrap;
                    var usnSize = g.MeasureString("USN", f, int.MaxValue, sf);
                    float gap = 8f;

                    using (var gradient = new LinearGradientBrush(
                        new RectangleF(0, 0, Math.Max(1f, usnSize.Width + 2f), 32),
                        Theme.Accent,
                        Theme.Violet,
                        LinearGradientMode.Horizontal))
                    {
                        g.DrawString("USN", f, gradient, 0, 0, sf);
                    }

                    using (var textBrush = new SolidBrush(Theme.Text))
                    {
                        g.DrawString("JOURNAL SCRUBBER", f, textBrush, usnSize.Width + gap, 0, sf);
                    }
                }
            };

            var subtitle = new Label
            {
                Text = "hide file entries at the journal level",
                Location = new Point(22, 54),
                AutoSize = true,
                Font = Theme.F(9.5f),
                ForeColor = Theme.TextMuted,
                BackColor = Theme.Card
            };

            var devPanel = new Panel
            {
                Location = new Point(Math.Max(0, _header.ClientSize.Width - DevPanelWidth - 14), 14),
                Size = new Size(DevPanelWidth, DevPanelHeight),
                BackColor = Theme.CardHi,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };

            devPanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using (var b = new SolidBrush(Theme.CardHi))
                    g.FillRectangle(b, devPanel.ClientRectangle);

                using (var path = Theme.RoundedRect(new Rectangle(0, 0, devPanel.Width - 1, devPanel.Height - 1), 10))
                using (var border = new Pen(Theme.Border, 1))
                {
                    g.DrawPath(border, path);
                }

                var logoRect = new Rectangle(12, 10, 40, 40);

                if (_logoImage != null)
                {
                    var oldClip = g.Clip;
                    using (var logoPath = Theme.RoundedRect(logoRect, 8))
                    {
                        g.SetClip(logoPath);
                        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                        g.DrawImage(_logoImage, logoRect);
                    }
                    g.Clip = oldClip;

                    using (var logoPath = Theme.RoundedRect(logoRect, 8))
                    using (var logoBorder = new Pen(Theme.Border, 1))
                        g.DrawPath(logoBorder, logoPath);
                }
                else
                {
                    using (var gradient = new LinearGradientBrush(logoRect, Color.FromArgb(80, 150, 255), Color.FromArgb(180, 100, 240), LinearGradientMode.ForwardDiagonal))
                    using (var logoPath = Theme.RoundedRect(logoRect, 8))
                    {
                        g.FillPath(gradient, logoPath);
                    }

                    using (var f = Theme.F(6.5f, FontStyle.Bold))
                    using (var b = new SolidBrush(Color.White))
                    {
                        var textSize = g.MeasureString("LOGO", f);
                        g.DrawString("LOGO", f, b,
                            logoRect.X + (logoRect.Width - textSize.Width) / 2f,
                            logoRect.Y + (logoRect.Height - textSize.Height) / 2f);
                    }
                }

                using (var b = new SolidBrush(Theme.Border))
                    g.FillRectangle(b, 62, 12, 1, 40);

                using (var f = Theme.F(7.5f, FontStyle.Bold))
                using (var b = new SolidBrush(Theme.TextMuted))
                    g.DrawString("DEVELOPED BY", f, b, 74, 13);

                using (var f = new Font("Segoe UI", 13f, FontStyle.Bold))
                using (var b = new SolidBrush(Theme.Accent))
                    g.DrawString(Theme.Developer, f, b, 74, 34);

                var joinRect = new Rectangle(JoinX, JoinY, JoinW, JoinH);

                using (var path = Theme.RoundedRect(joinRect, 14))
                using (var gradient = new LinearGradientBrush(joinRect, Color.FromArgb(80, 130, 250), Color.FromArgb(140, 90, 240), LinearGradientMode.Horizontal))
                {
                    g.FillPath(gradient, path);
                }

                int iconX = joinRect.X + 16;
                int iconY = joinRect.Y + joinRect.Height / 2;

                using (var white = new SolidBrush(Color.White))
                {
                    g.FillEllipse(white, iconX - 8, iconY - 3, 16, 10);
                    g.FillEllipse(white, iconX - 9, iconY - 7, 6, 8);
                    g.FillEllipse(white, iconX + 3, iconY - 7, 6, 8);

                    using (var eye = new SolidBrush(Color.FromArgb(100, 120, 240)))
                    {
                        g.FillEllipse(eye, iconX - 4, iconY - 1, 3, 3);
                        g.FillEllipse(eye, iconX + 1, iconY - 1, 3, 3);
                    }
                }

                using (var f = Theme.F(9f, FontStyle.Bold))
                using (var b = new SolidBrush(Color.White))
                    g.DrawString("JOIN", f, b, iconX + 14, joinRect.Y + 6);

                using (var p = new Pen(Color.White, 1.8f))
                {
                    p.StartCap = LineCap.Round;
                    p.EndCap = LineCap.Round;

                    int ax = joinRect.Right - 22;
                    int ay = joinRect.Y + joinRect.Height / 2;

                    g.DrawLine(p, ax, ay, ax + 9, ay);
                    g.DrawLine(p, ax + 5, ay - 4, ax + 9, ay);
                    g.DrawLine(p, ax + 5, ay + 4, ax + 9, ay);
                }

                const string dcText = "dc@meow_x2";
                using (var f = Theme.F(8f))
                using (var b = new SolidBrush(Theme.TextMuted))
                {
                    var textSize = g.MeasureString(dcText, f);
                    g.DrawString(dcText, f, b,
                        joinRect.X + (joinRect.Width - textSize.Width) / 2f, 42);
                }
            };

            devPanel.MouseClick += (s, e) =>
            {
                if (new Rectangle(JoinX, JoinY, JoinW, JoinH).Contains(e.Location))
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo { FileName = Theme.DiscordInvite, UseShellExecute = true });
                    }
                    catch { }
                }
            };

            devPanel.MouseMove += (s, e) =>
            {
                devPanel.Cursor = new Rectangle(JoinX, JoinY, JoinW, JoinH).Contains(e.Location)
                    ? Cursors.Hand : Cursors.Default;
            };

            var devMenu = new ContextMenuStrip();

            devMenu.Items.Add("Copy Discord ID", null, (s, e) =>
            { try { Clipboard.SetText(Theme.DiscordId); SetStatus("ID copied.", false); } catch { } });

            devMenu.Items.Add("Copy Discord invite", null, (s, e) =>
            { try { Clipboard.SetText(Theme.DiscordInvite); SetStatus("Invite copied.", false); } catch { } });

            devMenu.Items.Add(new ToolStripSeparator());

            devMenu.Items.Add("Open invite", null, (s, e) =>
            { try { Process.Start(new ProcessStartInfo { FileName = Theme.DiscordInvite, UseShellExecute = true }); } catch { } });

            devPanel.ContextMenuStrip = devMenu;

            _header.Controls.AddRange(new Control[] { titlePanel, subtitle, devPanel });
            Controls.Add(_header);

            void UpdateHeaderLayout()
            {
                int availableWidth = Math.Max(1, ClientSize.Width - HeaderSideMargin * 2);
                if (_header.Width != availableWidth)
                    _header.Width = availableWidth;

                int panelWidth = Math.Min(DevPanelWidth, Math.Max(280, _header.ClientSize.Width - 220));
                if (devPanel.Width != panelWidth)
                    devPanel.Width = panelWidth;

                int panelLeft = Math.Max(0, _header.ClientSize.Width - devPanel.Width - 14);
                if (devPanel.Left != panelLeft)
                    devPanel.Left = panelLeft;

                int titleWidth = Math.Max(120, devPanel.Left - titlePanel.Left - 18);
                if (titlePanel.Width != titleWidth)
                    titlePanel.Width = titleWidth;

                titlePanel.Invalidate();
            }

            _header.Resize += (s, e) => UpdateHeaderLayout();
            Resize += (s, e) => UpdateHeaderLayout();

            UpdateHeaderLayout();
        }

        void BuildRulesCard()
        {
            _rulesCard = new CardPanel { Title = "REMOVE VIA STRINGS/USN", AccentColor = Theme.Accent, Location = new Point(12, 112), Size = new Size(624, 300) };

            var lblVolume = MakeLabel("Volume", 16, 36);
            _cmbVolume = new ComboBox { Location = new Point(120, 33), Width = 82, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Theme.Input, ForeColor = Theme.Text, FlatStyle = FlatStyle.Flat, Font = Theme.Mono(9f, FontStyle.Bold) };
            PopulateVolumes();

            var lblString = MakeLabel("Filename", 16, 66);
            _txtString = MakeTextBox(120, 63, 340, "secret.txt");
            _btnAddString = MakeButton("+ STRING", 500, 62, 110, 24, Theme.Neutral);
            _btnAddString.Click += AddStringRule;

            var lblUsn = MakeLabel("USN (0x…)", 16, 96);
            _txtUsn = MakeTextBox(120, 93, 340, "0x0000000000");
            _btnAddUsn = MakeButton("+ USN", 500, 92, 110, 24, Theme.Neutral);
            _btnAddUsn.Click += AddUsnRule;

            _lstRules = new ListBox
            {
                Location = new Point(16, 126),
                Size = new Size(600, 130),
                BackColor = Theme.Input,
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = Theme.Mono(8.5f),
                IntegralHeight = false
            };

            _btnRemoveRule = MakeButton("REMOVE", 16, 264, 90, 26, Theme.Neutral);
            _btnRemoveRule.Click += RemoveSelectedRule;

            _btnClearRules = MakeButton("CLEAR ALL", 114, 264, 96, 26, Theme.Neutral);
            _btnClearRules.Click += (s, e) => ClearAllRules();

            _rulesCard.Controls.AddRange(new Control[] {
                lblVolume, _cmbVolume,
                lblString, _txtString, _btnAddString,
                lblUsn, _txtUsn, _btnAddUsn,
                _lstRules, _btnRemoveRule, _btnClearRules
            });
            Controls.Add(_rulesCard);
        }

        Panel _searchHeaderRow;

        void BuildSearchCard()
        {
            _searchCard = new CardPanel { Title = "MANUAL SEARCH", AccentColor = Theme.Violet, Location = new Point(644, 112), Size = new Size(560, 300) };

            var lblSearch = MakeLabel("Search", 16, 36);
            _txtSearch = MakeTextBox(80, 33, 300, "filename");
            _txtSearch.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; SearchJournal(); } };

            _btnSearch = MakeButton("SEARCH", 440, 32, 104, 24, Theme.Neutral);
            _btnSearch.ForeColor = Color.White;
            _btnSearch.Click += (s, e) => SearchJournal();

            _searchHeaderRow = new Panel { Location = new Point(16, 66), Size = new Size(528, 20), BackColor = Theme.Input };
            _searchHeaderRow.Paint += (s, e) => { using (var p = new Pen(Theme.Border, 1)) e.Graphics.DrawRectangle(p, 0, 0, _searchHeaderRow.Width - 1, _searchHeaderRow.Height - 1); };

            _searchHeaderRow.Controls.Add(new Label { Text = "DRIVE", Location = new Point(6, 2), Size = new Size(40, 16), Font = Theme.Mono(8f, FontStyle.Bold), ForeColor = Theme.TextMuted, BackColor = Color.Transparent });
            _searchHeaderRow.Controls.Add(new Label { Text = "FILENAME", Location = new Point(48, 2), Size = new Size(150, 16), Font = Theme.Mono(8f, FontStyle.Bold), ForeColor = Theme.TextMuted, BackColor = Color.Transparent });
            _searchHeaderRow.Controls.Add(new Label { Text = "PATH", Location = new Point(200, 2), Size = new Size(320, 16), Font = Theme.Mono(8f, FontStyle.Bold), ForeColor = Theme.TextMuted, BackColor = Color.Transparent });

            _lstFound = new ListBox
            {
                Location = new Point(16, 88),
                Size = new Size(528, 172),
                BackColor = Theme.Input,
                ForeColor = Theme.Success,
                BorderStyle = BorderStyle.FixedSingle,
                Font = Theme.Mono(8.5f),
                IntegralHeight = false,
                HorizontalScrollbar = true,
                SelectionMode = SelectionMode.MultiExtended
            };

            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy USN (hex)", null, (s, e) => CopyFoundUsnHex());
            menu.Items.Add("Copy USN (decimal)", null, (s, e) => CopyFoundUsnDec());
            menu.Items.Add("Copy filename", null, (s, e) => CopyFoundName());
            menu.Items.Add("Copy full path", null, (s, e) => CopyFoundPath());
            menu.Items.Add("Copy full row", null, (s, e) => CopyFoundRow());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Send USN to rule box", null, (s, e) => SendFoundUsnToRuleBox());
            _lstFound.ContextMenuStrip = menu;
            _lstFound.DoubleClick += (s, e) => CopyFoundUsnHex();

            _btnClearFound = MakeButton("CLEAR", 16, 264, 100, 26, Theme.Neutral);
            _btnClearFound.Click += (s, e) => { _lstFound.Items.Clear(); _found.Clear(); SetStatus("Found list cleared.", false); };

            _btnHide = MakeButton("HIDE", 138, 264, 150, 26, Theme.Red);
            _btnHide.Click += (s, e) => HideFound();

            _searchCard.Controls.AddRange(new Control[] {
                lblSearch, _txtSearch, _btnSearch,
                _searchHeaderRow, _lstFound,
                _btnClearFound, _btnHide
            });
            Controls.Add(_searchCard);
        }

        void BuildDriverCard()
        {
            _driverCard = new CardPanel { Title = "STATUS", AccentColor = Theme.Success, Location = new Point(12, 420), Size = new Size(1096, 102) };

            _lblDriver = new Label
            {
                Location = new Point(16, 36),
                Size = new Size(1060, 22),
                ForeColor = Theme.TextMuted,
                Font = Theme.Mono(8.5f),
                BackColor = Color.Transparent,
                Text = "CORE ENGINE: (checking…)"
            };

            _chkHideJournal = new CheckBox
            {
                Text = "Hide $UsnJrnl runtime",
                Location = new Point(880, 14),
                Size = new Size(200, 20),
                ForeColor = Theme.TextMuted,
                BackColor = Color.Transparent,
                Font = Theme.F(8.5f)
            };
            _chkHideJournal.CheckedChanged += (s, e) => ApplyToggle(v => _client.SetHideJournal(v), _chkHideJournal.Checked, "Hide $UsnJrnl");

            _btnVerify = MakeButton("VERIFY", 620, 66, 110, 26, Theme.Neutral);
            _btnVerify.Click += (s, e) => VerifyDriver();

            _btnRefresh = MakeButton("REFRESH", 738, 66, 110, 26, Theme.Neutral);
            _btnRefresh.Click += (s, e) => RefreshList();

            _btnLoadDriver = MakeButton("LOAD", 856, 66, 118, 26, Theme.Neutral);
            _btnLoadDriver.Click += (s, e) => LoadDriver();

            _btnUnloadDriver = MakeButton("UNLOAD", 982, 66, 100, 26, Theme.Neutral);
            _btnUnloadDriver.Click += (s, e) => UnloadDriver();

            _driverCard.Controls.AddRange(new Control[] {
                _lblDriver,
                _chkHideJournal,
                _btnVerify, _btnRefresh, _btnLoadDriver, _btnUnloadDriver
            });
            Controls.Add(_driverCard);
        }

        void BuildDiagCard()
        {
            _diagCard = new CardPanel { Title = "DIAGNOSTICS", AccentColor = Theme.Warning, Location = new Point(12, 530), Size = new Size(1096, 200) };

            _txtDiag = new TextBox
            {
                Location = new Point(16, 34),
                Size = new Size(1064, 154),
                BackColor = Color.FromArgb(8, 8, 12),
                ForeColor = Color.FromArgb(190, 190, 165),
                BorderStyle = BorderStyle.FixedSingle,
                Font = Theme.Mono(8f),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = false,
                Text = "Diagnostics will appear here."
            };

            _diagCard.Controls.Add(_txtDiag);
            Controls.Add(_diagCard);
        }

        void BuildStatusBar()
        {
            _statusBar = new Panel { Location = new Point(12, 742), Size = new Size(1096, 24), BackColor = Theme.Card };
            _statusBar.Paint += (s, e) =>
            {
                var g = e.Graphics;
                using (var p = new Pen(Theme.Border, 1)) g.DrawRectangle(p, 0, 0, _statusBar.Width - 1, _statusBar.Height - 1);
                using (var b = new SolidBrush(Theme.Success)) g.FillEllipse(b, 8, 9, 6, 6);
            };

            _lblStatus = new Label
            {
                Location = new Point(22, 3),
                Size = new Size(1060, 18),
                ForeColor = Theme.Success,
                Font = Theme.F(8.5f),
                BackColor = Color.Transparent,
                Text = "Ready.",
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            _statusBar.Controls.Add(_lblStatus);
            Controls.Add(_statusBar);
        }

        Label MakeLabel(string text, int x, int y) =>
            new Label { Text = text, Location = new Point(x, y + 3), AutoSize = true, ForeColor = Theme.TextMuted, BackColor = Color.Transparent, Font = Theme.F(8.5f) };

        TextBox MakeTextBox(int x, int y, int w, string ph)
        {
            var tb = new TextBox { Location = new Point(x, y), Width = w, BackColor = Theme.Input, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle, Font = Theme.F(9f) };
            tb.GotFocus += (s, e) => { if (tb.ForeColor == Theme.TextMuted) { tb.Text = ""; tb.ForeColor = Theme.Text; } };
            tb.LostFocus += (s, e) => { if (string.IsNullOrEmpty(tb.Text)) { tb.Text = ph; tb.ForeColor = Theme.TextMuted; } };
            tb.Text = ph; tb.ForeColor = Theme.TextMuted;
            return tb;
        }

        string RealText(TextBox tb, string ph) => tb.ForeColor == Theme.TextMuted ? "" : tb.Text;

        FlatButton MakeButton(string text, int x, int y, int w, int h, Color baseC) =>
            new FlatButton(baseC, Lighten(baseC, 18), Darken(baseC, 12)) { Text = text, Location = new Point(x, y), Size = new Size(w, h) };

        static Color Lighten(Color c, int a) => Color.FromArgb(Math.Min(255, c.R + a), Math.Min(255, c.G + a), Math.Min(255, c.B + a));
        static Color Darken(Color c, int a) => Color.FromArgb(Math.Max(0, c.R - a), Math.Max(0, c.G - a), Math.Max(0, c.B - a));

        void PopulateVolumes()
        {
            _cmbVolume.Items.Clear();
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (!d.IsReady) continue;
                        if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable) continue;
                        _cmbVolume.Items.Add(d.Name.TrimEnd('\\'));
                    }
                    catch { }
                }
            }
            catch { }
            if (_cmbVolume.Items.Count == 0) _cmbVolume.Items.Add("C:");
            _cmbVolume.SelectedIndex = 0;
        }

        string GetVolume()
        {
            string v = _cmbVolume.SelectedItem as string;
            if (string.IsNullOrWhiteSpace(v)) v = "C:";
            if (!v.EndsWith(":")) v += ":";
            return v;
        }

        void LogDiag(string line)
        {
            try
            {
                if (InvokeRequired) { BeginInvoke(new Action<string>(LogDiag), line); return; }
                _txtDiag.AppendText(DateTime.Now.ToString("HH:mm:ss.fff") + "  " + line + Environment.NewLine);
                _txtDiag.SelectionStart = _txtDiag.Text.Length;
                _txtDiag.ScrollToCaret();
            }
            catch { }
        }

        void RedrawRulesList() { _lstRules.Items.Clear(); foreach (var r in _rules) _lstRules.Items.Add(r.ToString()); }

        UsnEntry SelectedFound() { int i = _lstFound.SelectedIndex; if (i < 0 || i >= _found.Count) return null; return _found[i]; }

        void CopyFoundUsnHex() { var e = SelectedFound(); if (e == null) { SetStatus("Select a row first.", true); return; } try { Clipboard.SetText(e.UsnHex); SetStatus("Copied " + e.UsnHex, false); } catch { } }
        void CopyFoundUsnDec() { var e = SelectedFound(); if (e == null) return; try { Clipboard.SetText(e.Usn.ToString()); } catch { } }
        void CopyFoundName() { var e = SelectedFound(); if (e == null) return; try { Clipboard.SetText(e.Name ?? ""); } catch { } }
        void CopyFoundPath() { var e = SelectedFound(); if (e == null) return; try { Clipboard.SetText(e.Path ?? ("?" + (e.Name ?? ""))); SetStatus("Path copied.", false); } catch { } }
        void CopyFoundRow() { var e = SelectedFound(); if (e == null) return; try { Clipboard.SetText(e.ToString()); } catch { } }
        void SendFoundUsnToRuleBox() { var e = SelectedFound(); if (e == null) return; _txtUsn.ForeColor = Theme.Text; _txtUsn.Text = e.UsnHex; SetStatus("USN loaded — click + USN.", false); }

        List<UsnEntry> EnumerateWithDriverPaused(string vol)
        {
            bool savedHide = false;
            if (_client != null && _client.IsConnected)
            {
                try { savedHide = _client.GetHideJournal(); } catch { }
                _client.ClearAll(); _client.SetSpoof(false); _client.SetHideJournal(false);
            }
            try { return UsnJournalHelper.EnumerateAll(vol); }
            finally
            {
                if (_client != null && _client.IsConnected)
                {
                    foreach (var r in _rules) { try { if (r.Usn != 0) _client.AddUsnRule(r.Usn); else _client.AddStringRule(r.String); } catch { } }
                    _client.SetHideJournal(savedHide);
                }
            }
        }

        // ═══════════════════════════════════════════════════
        //  HIDE — turns found entries into runtime rules
        // ═══════════════════════════════════════════════════
        void HideFound()
        {
            if (_found.Count == 0)
            {
                SetStatus("Nothing found. Click Search first.", true);
                MessageBox.Show("Nothing to hide.\n\nSearch for a filename first.", "Hide",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var items = new List<UsnEntry>();
            if (_lstFound.SelectedIndices.Count > 0)
            {
                foreach (int i in _lstFound.SelectedIndices) items.Add(_found[i]);
            }
            else
            {
                items.AddRange(_found);
            }

            int added = 0, skipped = 0, empties = 0;
            foreach (var e in items)
            {
                if (string.IsNullOrEmpty(e.Name)) { empties++; continue; }
                if (RuleExists(e.Name, 0)) { skipped++; continue; }

                _rules.Add(new RULE_REQUEST { String = e.Name, Usn = 0 });
                if (_client != null && _client.IsConnected)
                {
                    try { _client.AddStringRule(e.Name); } catch { }
                }
                added++;
            }

            RedrawRulesList();
            SetStatus("Hidden " + added + " name(s). Skipped " + skipped + " already active. Click UNLOAD to reveal.", false);

            if (added > 0)
                MessageBox.Show("Added " + added + " entry name(s) to the runtime filter.\n\n" +
                    "They will be hidden from any $UsnJrnl read while the driver is loaded.\n" +
                    "Click UNLOAD to reveal them again.",
                    "Hide", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void ApplyToggle(Action<bool> setter, bool desired, string name)
        {
            if (_suppressToggleEvents) return;
            if (_client == null || !_client.IsConnected) { SetStatus(name + ": no driver.", true); _suppressToggleEvents = true; try { _chkHideJournal.Checked = false; } catch { } _suppressToggleEvents = false; return; }
            try { setter(desired); SetStatus(name + (desired ? " ON." : " OFF."), false); RefreshList(); }
            catch (Exception ex) { SetStatus(name + " failed: " + ex.Message, true); }
        }

        bool RuleExists(string s, ulong u)
        {
            foreach (var r in _rules)
            {
                if (u != 0 && r.Usn == u) return true;
                if (u == 0 && r.Usn == 0 && string.Equals(r.String, s, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        void AddStringRule(object sender, EventArgs e)
        {
            string s = RealText(_txtString, "secret.txt").Trim();
            if (string.IsNullOrEmpty(s)) { SetStatus("Enter substring.", true); return; }
            if (RuleExists(s, 0)) { SetStatus("Already active.", true); _txtString.Clear(); ResetPlaceholder(_txtString, "secret.txt"); return; }
            _rules.Add(new RULE_REQUEST { String = s, Usn = 0 });
            if (_client != null && _client.IsConnected) { try { _client.AddStringRule(s); } catch { } }
            _txtString.Clear(); ResetPlaceholder(_txtString, "secret.txt");
            RedrawRulesList();
            SetStatus("Rule added — hidden at runtime. Click UNLOAD to reveal.", false);
        }

        void AddUsnRule(object sender, EventArgs e)
        {
            string s = RealText(_txtUsn, "").Trim();
            if (!TryParseUsn(s, out ulong u)) { SetStatus("Bad USN.", true); return; }
            if (RuleExists(null, u)) { SetStatus("Already active.", true); _txtUsn.Clear(); ResetPlaceholder(_txtUsn, "0x0000000000"); return; }
            _rules.Add(new RULE_REQUEST { String = "", Usn = u });
            if (_client != null && _client.IsConnected) { try { _client.AddUsnRule(u); } catch { } }
            _txtUsn.Clear(); ResetPlaceholder(_txtUsn, "0x0000000000");
            RedrawRulesList();
            SetStatus("USN added — hidden at runtime. Click UNLOAD to reveal.", false);
        }

        void ResetPlaceholder(TextBox tb, string ph) { if (string.IsNullOrEmpty(tb.Text)) { tb.Text = ph; tb.ForeColor = Theme.TextMuted; } }

        static bool TryParseUsn(string s, out ulong u)
        {
            u = 0; if (string.IsNullOrWhiteSpace(s)) return false; s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return ulong.TryParse(s.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out u);
            return ulong.TryParse(s, out u);
        }

        void RemoveSelectedRule(object sender, EventArgs e)
        {
            if (_lstRules.SelectedIndex < 0 || _lstRules.SelectedIndex >= _rules.Count) { SetStatus("Select rule.", true); return; }
            var r = _rules[_lstRules.SelectedIndex];
            _rules.RemoveAt(_lstRules.SelectedIndex);
            if (_client != null && _client.IsConnected) { try { if (r.Usn != 0) _client.RemoveUsnRule(r.Usn); else _client.RemoveStringRule(r.String); } catch { } }
            RedrawRulesList(); SetStatus("Removed.", false);
        }

        void ClearAllRules() { _rules.Clear(); if (_client != null && _client.IsConnected) { try { _client.ClearAll(); } catch { } } RedrawRulesList(); SetStatus("Cleared.", false); }

        void SearchJournal()
        {
            string term = RealText(_txtSearch, "filename").Trim();
            if (string.IsNullOrEmpty(term)) { SetStatus("Enter term.", true); return; }
            _btnSearch.Enabled = false;
            try
            {
                string vol = GetVolume();
                SetStatus("Searching " + vol + "…", false);
                LogDiag("search: " + vol + " '" + term + "'");
                _lstFound.Items.Clear(); _found.Clear(); _pathCache.Clear();
                var all = EnumerateWithDriverPaused(vol);
                int m = 0;
                foreach (var e in all)
                {
                    if (!string.IsNullOrEmpty(e.Name) && e.Name.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        e.Volume = vol;
                        e.Path = ResolvePathCached(vol, e.FileReferenceNumber);
                        _found.Add(e);
                        _lstFound.Items.Add(e.ToString());
                        m++;
                    }
                }
                SetStatus(all.Count + " scanned, " + m + " matched. Select rows and click HIDE.", false);
                LogDiag("search: " + m);
                RefreshList();
            }
            catch (Exception ex) { SetStatus("Search failed: " + ex.Message, true); MessageBox.Show("Search failed.\n" + ex.Message, "Search", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            finally { _btnSearch.Enabled = true; }
        }

        void LoadDriver()
        {
            _btnLoadDriver.Enabled = false;
            try
            {
                SetStatus("Loading driver…", false);
                LogDiag("load: start");
                FileHiderClient fresh = DriverManager.LoadFresh();
                try { _client?.Dispose(); } catch { }
                _client = fresh;
                try { _client.ClearAll(); } catch { }
                foreach (var r in _rules) { try { if (r.Usn != 0) _client.AddUsnRule(r.Usn); else _client.AddStringRule(r.String); } catch { } }
                int renamed = 0; try { renamed = _client.HideNow(); } catch { }
                SetStatus("Driver loaded. Rules: " + _rules.Count + ".", false);
                LogDiag("load: OK renamed=" + renamed);
                RefreshList();
            }
            catch (Exception ex) { SetStatus("Load failed: " + ex.Message, true); LogDiag("load FAILED: " + ex.Message); }
            finally { _btnLoadDriver.Enabled = true; }
        }

        void UnloadDriver()
        {
            _suppressToggleEvents = true;
            try { _chkHideJournal.Checked = false; }
            catch { }
            finally { _suppressToggleEvents = false; }
            try
            {
                var local = _client;
                DriverManager.UnloadAndDisconnect(ref local);
                _client = local;
                SetStatus("Unloaded — hidden entries are visible again.", false);
                LogDiag("unload: done");
            }
            catch (Exception ex) { SetStatus("Unload error: " + ex.Message, true); }
            RefreshList();
        }

        void VerifyDriver()
        {
            if (_client == null || !_client.IsConnected) { SetStatus("No driver.", true); return; }
            var st = _client.GetStatus();
            bool ok = st.Magic == FileHiderClient.FH_MAGIC;
            SetStatus(ok ? "Verify OK — v" + st.Version : "Verify FAILED", !ok);
            RefreshList();
        }

        void RefreshList()
        {
            RedrawRulesList();
            if (_client == null || !_client.IsConnected)
            {
                _lblDriver.Text = "Red Engine:  ●  NOT CONNECTED      rules persist in UI  ·  on-disk scrub works without driver";
                _lblDriver.ForeColor = Theme.Warning;
                _suppressToggleEvents = true;
                try { _chkHideJournal.Checked = false; } catch { }
                _suppressToggleEvents = false;
                return;
            }
            try
            {
                var st = _client.GetStatus();
                if (st.Magic != FileHiderClient.FH_MAGIC) { _lblDriver.Text = "Driver:  ●  FOREIGN   magic=0x" + st.Magic.ToString("X8"); _lblDriver.ForeColor = Theme.Danger; return; }
                bool att = st.FilterAttached != 0;
                _lblDriver.Text = string.Format("Red Engine:  ●  {0}      v{1}  ·  UI rules: {2}  ·  Engine rules: {3}  ·  hideJ: {4}",
                    att ? "CONNECTED" : "NOT CONNECTED", st.Version, _rules.Count, st.RuleCount, st.HideJournal != 0 ? "on" : "off");
                _lblDriver.ForeColor = att ? Theme.Success : Theme.Danger;
                _suppressToggleEvents = true;
                try { _chkHideJournal.Checked = st.HideJournal != 0; } catch { }
                _suppressToggleEvents = false;
            }
            catch (Exception ex) { _lblDriver.Text = "Driver:  ●  error — " + ex.Message; _lblDriver.ForeColor = Theme.Danger; }
        }

        void SetStatus(string text, bool warn)
        {
            _lblStatus.Text = text;
            _lblStatus.ForeColor = warn ? Theme.Warning : Theme.Success;
        }
    }

    static class Program
    {
        static void EnsureAdmin()
        {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            if (p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)) return;

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = System.Reflection.Assembly.GetExecutingAssembly().Location,
                UseShellExecute = true,
                Verb = "runas"
            };
            try { System.Diagnostics.Process.Start(psi); }
            catch { MessageBox.Show("Admin required.", "USN Scrubber", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            Environment.Exit(0);
        }

        // ═══════════════════════════════════════════════════
        //  KEYAUTH GATE
        // ═══════════════════════════════════════════════════
        static bool RunKeyAuth()
        {
            var api = new Reborn.api(
                name: KeyAuthConfig.NAME,
                ownerid: KeyAuthConfig.OWNERID,
                secret: KeyAuthConfig.SECRET,
                version: KeyAuthConfig.VERSION);

            try
            {
                api.init();
            }
            catch (Exception ex)
            {
                MessageBox.Show("KeyAuth init failed:\n" + ex.Message,
                    "USN Journal Scrubber", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            using (var login = new LoginForm(api))
            {
                var result = login.ShowDialog();
                if (result != DialogResult.OK || !login.Authenticated)
                    return false;
            }

            return true;
        }

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--unload")
            {
                DriverManager.WipeStaleState();
                KernelLoader.ForceUnload();
                MessageBox.Show("Unloaded. Log: " + KernelLoader.GetLogPath(), "USN Scrubber");
                return;
            }

            EnsureAdmin();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // ---- KeyAuth gate ----
            if (!RunKeyAuth())
            {
                Environment.Exit(1);
            }

            FileHiderClient client = null;
            string startupError = null;
            try { client = DriverManager.LoadFresh(); }
            catch (Exception ex) { startupError = ex.Message; }

            if (client != null && client.IsConnected) { try { client.HideNow(); } catch { } }

            var form = new MainForm(client);
            if (client == null)
                MessageBox.Show("Driver not loaded. On-disk scrub still works.\n" + (startupError != null ? "\nReason: " + startupError : ""),
                    "USN JOURNAL SCRUBBER  —  by " + Theme.Developer, MessageBoxButtons.OK, MessageBoxIcon.Information);

            Application.Run(form);
        }
    }
}