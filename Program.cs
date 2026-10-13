using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

namespace FileHider
{
    internal static class Ioctl
    {
        const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        const uint METHOD_BUFFERED = 0;
        const uint FILE_ANY_ACCESS = 0;

        static uint CTL_CODE(uint d, uint f, uint m, uint a) =>
            (d << 16) | (a << 14) | (f << 2) | m;

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
        public uint Magic;
        public uint Version;
        public ulong SessionId;
        public uint FilterAttached;
        public uint RuleCount;
        public uint LastError;
        public uint FsctlHits;
        public uint FsctlFiltered;
        public uint RecordsSeen;
        public uint RecordsRemoved;
        public uint ParseFailures;
        public uint ReadBlocked;
        public uint QuerySpoofed;
        public uint FileUsnFiltered;
        public uint SpoofEmpty;
        public uint HideJournal;
        public uint CreateHits;
        public uint JournalBlocked;
        public uint PreOpSeen;
        public uint PostOpSeen;
        public uint PostOpNoBuf;
        public uint PostOpInfoBad;
        public uint ReadPreSeen;
        public uint ReadPostSeen;
        public uint ReadNoBuf;
        public uint ReadInfoBad;
        public uint ReadMatched;
        public uint ReadNameHits;
        public uint CreateNameHits;
        public uint CreateUncacheForced;
        public uint LastCode;
        public uint LastMethod;
        public uint LastInfo;
        public uint LastOutCap;
        public ulong LastOutBuf;
        public uint LastValidate;
        public uint LastRecords;
        public uint LastFiltered;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] LastRaw;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string FirstName;
        public uint FirstNameLen;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DELETE_USN_JOURNAL_DATA
    {
        public ulong UsnJournalID;
        public uint DeleteFlags;
    }

    internal static class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            SafeFileHandle hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(
            SafeFileHandle hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(
            SafeFileHandle hFile, long liDistanceToMove,
            out long lpNewFilePointer, uint dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushFileBuffers(SafeFileHandle hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName, string lpName, out long lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength,
            IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint SE_PRIVILEGE_ENABLED = 0x0002;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public long Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        public static void EnableBackupPrivileges()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                return;

            foreach (var name in new[]
                     {
                         "SeBackupPrivilege",
                         "SeRestorePrivilege",
                         "SeManageVolumePrivilege"
                     })
            {
                long luid;
                if (!LookupPrivilegeValue(null, name, out luid)) continue;

                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    }
                };
                AdjustTokenPrivileges(token, false, ref tp,
                    (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            }
        }

        public static IntPtr AllocAligned(UIntPtr size)
        {
            return VirtualAlloc(IntPtr.Zero, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        public static void FreeAligned(IntPtr p)
        {
            if (p != IntPtr.Zero) VirtualFree(p, UIntPtr.Zero, MEM_RELEASE);
        }
    }

    public sealed class FileHiderClient : IDisposable
    {
        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint OPEN_EXISTING = 3;
        const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        public const uint FH_MAGIC = 0x4F555443u;

        SafeFileHandle _handle;

        public bool IsConnected => _handle != null && !_handle.IsInvalid && !_handle.IsClosed;

        public FileHiderClient()
        {
            _handle = Win32.CreateFile(
                @"\\.\FileHider",
                GENERIC_READ | GENERIC_WRITE,
                0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (_handle.IsInvalid)
            {
                _handle.Dispose();
                _handle = null;
                throw new InvalidOperationException(
                    "Cannot open \\\\.\\FileHider — driver not loaded.");
            }
        }

        public STATUS_REPLY GetStatus()
        {
            var rep = new STATUS_REPLY { LastRaw = new byte[256], FirstName = "" };
            if (!IsConnected) return rep;

            int size = Marshal.SizeOf(typeof(STATUS_REPLY));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (Win32.DeviceIoControl(_handle, Ioctl.GET_STATUS,
                        IntPtr.Zero, 0, buf, (uint)size, out _, IntPtr.Zero))
                    rep = (STATUS_REPLY)Marshal.PtrToStructure(buf, typeof(STATUS_REPLY));
                if (rep.LastRaw == null) rep.LastRaw = new byte[256];
                if (rep.FirstName == null) rep.FirstName = "";
                return rep;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public bool IsOurDriver() => GetStatus().Magic == FH_MAGIC;

        public void Reset()
        {
            if (!IsConnected) return;
            Win32.DeviceIoControl(_handle, Ioctl.RESET,
                IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        /// <summary>
        /// Tells the driver to rename its own LDR entry and any known
        /// vulnerable drivers' entries. Returns the number of extra
        /// entries renamed (0 if just the self-hide ran).
        /// </summary>
        public int HideNow()
        {
            if (!IsConnected) return 0;

            IntPtr outBuf = Marshal.AllocHGlobal(4);
            try
            {
                if (!Win32.DeviceIoControl(_handle, Ioctl.HIDE_NOW,
                        IntPtr.Zero, 0, outBuf, 4, out _, IntPtr.Zero))
                    return 0;
                return Marshal.ReadInt32(outBuf);
            }
            finally { Marshal.FreeHGlobal(outBuf); }
        }

        public void AddStringRule(string substring) => AddRuleInternal(substring, 0);
        public void AddUsnRule(ulong usn) => AddRuleInternal(null, usn);

        void AddRuleInternal(string substring, ulong usn)
        {
            if (!IsConnected) throw new InvalidOperationException("Driver not connected.");
            var req = new RULE_REQUEST { String = substring ?? "", Usn = usn };
            int size = Marshal.SizeOf(typeof(RULE_REQUEST));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(req, buf, false);
                if (!Win32.DeviceIoControl(_handle, Ioctl.ADD_RULE,
                        buf, (uint)size, IntPtr.Zero, 0, out _, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void RemoveStringRule(string substring) => RemoveRuleInternal(substring, 0);
        public void RemoveUsnRule(ulong usn) => RemoveRuleInternal(null, usn);

        void RemoveRuleInternal(string substring, ulong usn)
        {
            if (!IsConnected) return;
            var req = new RULE_REQUEST { String = substring ?? "", Usn = usn };
            int size = Marshal.SizeOf(typeof(RULE_REQUEST));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(req, buf, false);
                Win32.DeviceIoControl(_handle, Ioctl.REMOVE_RULE,
                    buf, (uint)size, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void ClearAll()
        {
            if (!IsConnected) return;
            Win32.DeviceIoControl(_handle, Ioctl.CLEAR_RULES,
                IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        public int GetCount()
        {
            if (!IsConnected) return 0;
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                return Win32.DeviceIoControl(_handle, Ioctl.GET_COUNT,
                    IntPtr.Zero, 0, buf, 4, out _, IntPtr.Zero)
                    ? Marshal.ReadInt32(buf) : 0;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public List<RULE_REQUEST> ListRules()
        {
            var list = new List<RULE_REQUEST>();
            if (!IsConnected) return list;
            int count = GetCount();
            if (count == 0) return list;
            int size = Marshal.SizeOf(typeof(RULE_REQUEST));
            IntPtr buf = Marshal.AllocHGlobal(size * count);
            try
            {
                if (Win32.DeviceIoControl(_handle, Ioctl.LIST_RULES,
                        IntPtr.Zero, 0, buf, (uint)(size * count),
                        out uint ret, IntPtr.Zero))
                {
                    int n = (int)(ret / (uint)size);
                    for (int i = 0; i < n; i++)
                    {
                        var req = (RULE_REQUEST)Marshal.PtrToStructure(
                            buf + i * size, typeof(RULE_REQUEST));
                        if (req.String == null) req.String = "";
                        list.Add(req);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return list;
        }

        public void SetSpoof(bool v) => SetToggle(Ioctl.SET_SPOOF, v);
        public bool GetSpoof() => GetToggle(Ioctl.GET_SPOOF);
        public void SetHideJournal(bool v) => SetToggle(Ioctl.SET_HIDE_JOURNAL, v);
        public bool GetHideJournal() => GetToggle(Ioctl.GET_HIDE_JOURNAL);

        void SetToggle(uint ioctl, bool enabled)
        {
            if (!IsConnected) return;
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(buf, enabled ? 1 : 0);
                Win32.DeviceIoControl(_handle, ioctl, buf, 4, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        bool GetToggle(uint ioctl)
        {
            if (!IsConnected) return false;
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                return Win32.DeviceIoControl(_handle, ioctl,
                    IntPtr.Zero, 0, buf, 4, out _, IntPtr.Zero)
                    && Marshal.ReadInt32(buf) != 0;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void Dispose() { _handle?.Dispose(); _handle = null; }
    }

    internal static class DriverManager
    {
        public static void WipeStaleState()
        {
            try { using (var p = new FileHiderClient()) if (p.IsOurDriver()) p.Reset(); }
            catch { }
        }

        public static FileHiderClient LoadFresh()
        {
            WipeStaleState();
            try { KernelLoader.ForceUnload(); } catch { }
            Thread.Sleep(600);
            if (!KernelLoader.EnsureDriverLoaded())
                throw new InvalidOperationException(
                    "KernelLoader.EnsureDriverLoaded() returned false. Log: "
                    + KernelLoader.GetLogPath());

            FileHiderClient client = null;
            Exception lastEx = null;
            for (int i = 0; i < 6; i++)
            {
                try
                {
                    client = new FileHiderClient();
                    if (client.IsOurDriver()) break;
                    client.Dispose(); client = null;
                }
                catch (Exception ex) { lastEx = ex; }
                Thread.Sleep(250);
            }
            if (client == null)
                throw new InvalidOperationException(
                    "Driver loaded but could not connect. "
                    + (lastEx != null ? lastEx.Message : "No response."));
            client.Reset();
            return client;
        }

        public static void UnloadAndDisconnect(ref FileHiderClient client)
        {
            try { client?.Reset(); } catch { }
            try { client?.Dispose(); } catch { }
            client = null;
            try { KernelLoader.ForceUnload(); } catch { }
        }
    }

    // ─── USN helper ────────────────────────────────────────────────

    public class UsnEntry
    {
        public ulong Usn;
        public ulong FileReferenceNumber;
        public ulong ParentFileReferenceNumber;
        public string Name;
        public override string ToString() =>
            "0x" + Usn.ToString("X16") + "  " + Name;
    }

    internal static class UsnJournalHelper
    {
        const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
        const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
        const uint FSCTL_DELETE_USN_JOURNAL = 0x0009009C;
        const uint FSCTL_CREATE_USN_JOURNAL = 0x000900E7;

        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint FILE_SHARE_DELETE = 0x00000004;
        const uint OPEN_EXISTING = 3;
        const uint FILE_ATTRIBUTE_HIDDEN = 0x02;
        const uint FILE_ATTRIBUTE_SYSTEM = 0x04;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct READ_USN_JOURNAL_DATA_V0
        {
            public long StartUsn;
            public uint ReasonMask;
            public uint ReturnOnlyOnClose;
            public long Timeout;
            public long BytesToWaitFor;
            public ulong UsnJournalID;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct USN_JOURNAL_DATA_V0
        {
            public ulong UsnJournalID;
            public long FirstUsn;
            public long NextUsn;
            public long LowestValidUsn;
            public long MaxUsn;
            public ulong MaximumSize;
            public ulong AllocationDelta;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct USN_RECORD_HEADER
        {
            public uint RecordLength;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public ulong FileReferenceNumber;
            public ulong ParentFileReferenceNumber;
            public long Usn;
            public long TimeStamp;
            public uint Reason;
            public uint SourceInfo;
            public uint SecurityId;
            public uint FileAttributes;
            public ushort FileNameLength;
            public ushort FileNameOffset;
        }

        static USN_JOURNAL_DATA_V0 QueryJournal(string volume)
        {
            using (var h = Win32.CreateFile(
                @"\\.\" + volume,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Open volume " + volume + " failed");

                int outSize = Marshal.SizeOf(typeof(USN_JOURNAL_DATA_V0));
                IntPtr outBuf = Marshal.AllocHGlobal(outSize);
                try
                {
                    if (!Win32.DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL,
                            IntPtr.Zero, 0, outBuf, (uint)outSize, out _, IntPtr.Zero))
                    {
                        int err = Marshal.GetLastWin32Error();
                        throw new Win32Exception(err,
                            "FSCTL_QUERY_USN_JOURNAL failed (Win32 " + err + ")");
                    }
                    return (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(
                        outBuf, typeof(USN_JOURNAL_DATA_V0));
                }
                finally { Marshal.FreeHGlobal(outBuf); }
            }
        }

        public static List<UsnEntry> EnumerateAll(string volume)
        {
            var list = new List<UsnEntry>();
            var jd = QueryJournal(volume);

            using (var h = Win32.CreateFile(
                @"\\.\" + volume,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Open volume for READ_USN_JOURNAL failed");

                var req = new READ_USN_JOURNAL_DATA_V0
                {
                    StartUsn = jd.FirstUsn,
                    ReasonMask = 0xFFFFFFFF,
                    ReturnOnlyOnClose = 0,
                    Timeout = 0,
                    BytesToWaitFor = 0,
                    UsnJournalID = jd.UsnJournalID
                };

                int inSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
                int outSize = 32 * 1024 * 1024;
                IntPtr inBuf = Marshal.AllocHGlobal(inSize);
                IntPtr outBuf = Marshal.AllocHGlobal(outSize);

                try
                {
                    int guard = 0;

                    while (req.StartUsn < jd.NextUsn && guard++ < 1000000)
                    {
                        Marshal.StructureToPtr(req, inBuf, false);

                        if (!Win32.DeviceIoControl(h, FSCTL_READ_USN_JOURNAL,
                                inBuf, (uint)inSize,
                                outBuf, (uint)outSize,
                                out uint ret, IntPtr.Zero))
                        {
                            int err = Marshal.GetLastWin32Error();
                            if (err == 38) break;
                            if (err == 1178 || err == 1179) break;
                            throw new Win32Exception(err,
                                "FSCTL_READ_USN_JOURNAL failed (Win32 " + err + ")");
                        }

                        if (ret < 8) break;

                        ulong nextUsn = (ulong)Marshal.ReadInt64(outBuf);
                        int offset = 8;
                        int recordsInBatch = 0;

                        while (offset + 8 <= (int)ret)
                        {
                            uint recLen = (uint)Marshal.ReadInt32(outBuf, offset);
                            if (recLen < 24 || recLen > 0x10000) break;
                            if (offset + recLen > (int)ret) break;

                            ushort major = (ushort)Marshal.ReadInt16(outBuf, offset + 4);
                            if (major != 2 && major != 3) break;

                            int headerSize = (major == 2) ? 60 : 76;
                            if (offset + headerSize > (int)ret) break;

                            var hdr = (USN_RECORD_HEADER)Marshal.PtrToStructure(
                                outBuf + offset, typeof(USN_RECORD_HEADER));

                            ushort nameLen = (ushort)Marshal.ReadInt16(
                                outBuf, offset + headerSize - 4);
                            ushort nameOff = (ushort)Marshal.ReadInt16(
                                outBuf, offset + headerSize - 2);

                            string name = "";
                            if (nameLen > 0 && (int)(nameOff + nameLen) <= recLen)
                            {
                                name = Marshal.PtrToStringUni(
                                    outBuf + offset + nameOff, nameLen / 2);
                            }

                            list.Add(new UsnEntry
                            {
                                Usn = (ulong)hdr.Usn,
                                FileReferenceNumber = hdr.FileReferenceNumber,
                                ParentFileReferenceNumber = hdr.ParentFileReferenceNumber,
                                Name = name
                            });

                            offset = (offset + (int)recLen + 7) & ~7;
                            recordsInBatch++;
                        }

                        if (nextUsn == 0) break;
                        if ((ulong)req.StartUsn == nextUsn) break;
                        if (recordsInBatch == 0 && ret <= 8) break;

                        req.StartUsn = (long)nextUsn;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(inBuf);
                    Marshal.FreeHGlobal(outBuf);
                }
            }

            return list;
        }

        public static List<UsnEntry> FindMatches(List<UsnEntry> all,
            IEnumerable<RULE_REQUEST> rules)
        {
            var matches = new List<UsnEntry>();
            foreach (var e in all)
            {
                foreach (var r in rules)
                {
                    if (r.Usn != 0)
                    {
                        if (e.Usn == r.Usn) { matches.Add(e); break; }
                    }
                    else if (!string.IsNullOrEmpty(r.String))
                    {
                        if (e.Name.IndexOf(r.String, StringComparison.OrdinalIgnoreCase) >= 0)
                        { matches.Add(e); break; }
                    }
                }
            }
            return matches;
        }

        public static int ScrubOnDisk(string volume, List<ulong> usnsToErase,
                                      Action<int> progress = null)
        {
            Win32.EnableBackupPrivileges();

            if (usnsToErase.Count == 0) return 0;
            var usnSet = new HashSet<ulong>(usnsToErase);

            string[] paths = {
                @"\\?\" + volume + @"\$Extend\$UsnJrnl:$J",
                @"\\.\" + volume + @"\$Extend\$UsnJrnl:$J",
                @"\\?\" + volume + @"\$Extend\$UsnJrnl",
                @"\\.\" + volume + @"\$Extend\$UsnJrnl"
            };

            Exception lastOpenEx = null;
            SafeFileHandle h = null;

            foreach (var path in paths)
            {
                try
                {
                    h = Win32.CreateFile(
                        path,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        IntPtr.Zero, OPEN_EXISTING,
                        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
                        FILE_FLAG_BACKUP_SEMANTICS,
                        IntPtr.Zero);
                    if (!h.IsInvalid) break;
                    h.Dispose(); h = null;
                }
                catch (Exception ex) { lastOpenEx = ex; }
            }

            if (h == null || h.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                throw new Win32Exception(err,
                    "Cannot open $UsnJrnl:$J on any path."
                    + (lastOpenEx != null ? " — " + lastOpenEx.Message : ""));
            }

            using (h)
            {
                const int CHUNK = 64 * 1024 * 1024;

                IntPtr buf = Win32.AllocAligned((UIntPtr)CHUNK);
                if (buf == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "VirtualAlloc failed");

                int patched = 0;

                try
                {
                    long fileSize = 0;
                    Win32.SetFilePointerEx(h, 0, out fileSize, 2);
                    Win32.SetFilePointerEx(h, 0, out _, 0);

                    if (fileSize < 32)
                        throw new InvalidOperationException(
                            "Journal size is " + fileSize + " bytes.");

                    long pos = 0;

                    while (pos < fileSize)
                    {
                        long remaining = fileSize - pos;
                        uint toRead = (uint)Math.Min(CHUNK, remaining);
                        if (toRead == 0) break;

                        if (!Win32.SetFilePointerEx(h, pos, out _, 0))
                            throw new Win32Exception(Marshal.GetLastWin32Error(),
                                "Seek to " + pos + " failed");

                        if (!Win32.ReadFile(h, buf, toRead, out uint got, IntPtr.Zero))
                        {
                            int err = Marshal.GetLastWin32Error();
                            throw new Win32Exception(err,
                                "ReadFile at " + pos + " failed (Win32 " + err + ")");
                        }
                        if (got == 0) break;

                        bool chunkModified = false;
                        int offset = 0;

                        while (offset + 8 <= (int)got)
                        {
                            uint recLen = (uint)Marshal.ReadInt32(buf, offset);

                            bool valid = false;
                            int headerSize = 0;
                            ushort major = 0;

                            if (recLen >= 24 && recLen <= 0x10000)
                            {
                                major = (ushort)Marshal.ReadInt16(buf, offset + 4);
                                if (major == 2 || major == 3)
                                {
                                    headerSize = (major == 2) ? 60 : 76;
                                    if (recLen >= (uint)headerSize &&
                                        offset + recLen <= (int)got)
                                        valid = true;
                                }
                            }

                            if (!valid)
                            {
                                offset += 8;
                                continue;
                            }

                            int usnOff = (major == 2) ? 24 : 40;
                            long usn = Marshal.ReadInt64(buf, offset + usnOff);
                            ushort nameLen = (ushort)Marshal.ReadInt16(buf,
                                offset + headerSize - 4);
                            ushort nameOff = (ushort)Marshal.ReadInt16(buf,
                                offset + headerSize - 2);

                            if (usnSet.Contains((ulong)usn))
                            {
                                if (nameLen > 0 && nameOff + nameLen <= recLen)
                                {
                                    for (int i = 0; i < nameLen; i++)
                                        Marshal.WriteByte(buf, offset + nameOff + i, 0);
                                }
                                Marshal.WriteInt16(buf, offset + headerSize - 4, 0);
                                chunkModified = true;
                                patched++;
                                if (progress != null) progress(patched);
                            }

                            offset = (offset + (int)recLen + 7) & ~7;
                        }

                        if (chunkModified)
                        {
                            if (!Win32.SetFilePointerEx(h, pos, out _, 0))
                                throw new Win32Exception(Marshal.GetLastWin32Error(),
                                    "Re-seek to " + pos + " failed");

                            if (!Win32.WriteFile(h, buf, got, out uint wrote, IntPtr.Zero))
                            {
                                int err = Marshal.GetLastWin32Error();
                                throw new Win32Exception(err,
                                    "WriteFile at " + pos + " failed (Win32 " + err + ")");
                            }
                            if (wrote != got)
                                throw new InvalidOperationException(
                                    "Short write " + wrote + " of " + got);
                        }

                        pos += got;
                    }

                    Win32.FlushFileBuffers(h);
                }
                finally { Win32.FreeAligned(buf); }

                return patched;
            }
        }

        public static void PurgeWholeJournal(string volume)
        {
            Win32.EnableBackupPrivileges();
            var jd = QueryJournal(volume);

            try
            {
                PurgeViaHandle(@"\\.\" + volume, jd.UsnJournalID);
                return;
            }
            catch (Exception directEx)
            {
                try
                {
                    PurgeViaFsutil(volume);
                    return;
                }
                catch (Exception fsutilEx)
                {
                    throw new Exception(
                        "Direct FSCTL failed: " + directEx.Message
                        + "\n\nfsutil fallback also failed: " + fsutilEx.Message);
                }
            }
        }

        static void PurgeViaHandle(string path, ulong journalId)
        {
            using (var h = Win32.CreateFile(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (h.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new Win32Exception(err,
                        "Open " + path + " failed (Win32 " + err + ")");
                }

                var data = new DELETE_USN_JOURNAL_DATA
                {
                    UsnJournalID = journalId,
                    DeleteFlags = 1
                };

                int size = Marshal.SizeOf(typeof(DELETE_USN_JOURNAL_DATA));
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(data, buf, false);
                    if (!Win32.DeviceIoControl(h, FSCTL_DELETE_USN_JOURNAL,
                            buf, (uint)size, IntPtr.Zero, 0, out _, IntPtr.Zero))
                    {
                        int err = Marshal.GetLastWin32Error();
                        throw new Win32Exception(err,
                            "FSCTL_DELETE_USN_JOURNAL failed (Win32 " + err + ")");
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }

        static void PurgeViaFsutil(string volume)
        {
            string drive = volume.TrimEnd(':') + ":";

            var psi = new ProcessStartInfo
            {
                FileName = "fsutil.exe",
                Arguments = "usn deletejournal /d " + drive,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var proc = Process.Start(psi))
            {
                proc.WaitForExit(60000);
                if (proc.ExitCode != 0)
                {
                    string err = proc.StandardError.ReadToEnd();
                    string outStr = proc.StandardOutput.ReadToEnd();
                    throw new Exception(
                        "fsutil exited with code " + proc.ExitCode
                        + "\nSTDERR: " + err
                        + "\nSTDOUT: " + outStr);
                }
            }
        }
    }

    // ─── UI ────────────────────────────────────────────────────────

    public class MainForm : Form
    {
        TextBox _txtVolume;
        TextBox _txtString;
        Button _btnAddString;
        TextBox _txtUsn;
        Button _btnAddUsn;
        ListBox _lstRules;
        Button _btnRemoveRule;
        Button _btnClearRules;
        Button _btnScrubAll;
        CheckBox _chkAutoRescrub;
        System.Windows.Forms.Timer _rescrubTimer;

        TextBox _txtSearch;
        Button _btnSearch;
        ListBox _lstFound;
        Button _btnDiscover;
        Button _btnScrub;
        Button _btnPurge;

        Label _lblDriver;
        CheckBox _chkSpoof;
        CheckBox _chkHideJournal;
        Button _btnLoadDriver;
        Button _btnUnloadDriver;
        Button _btnVerify;
        Button _btnRefresh;

        Label _lblStatus;
        TextBox _txtDiag;

        FileHiderClient _client;
        readonly List<RULE_REQUEST> _rules = new List<RULE_REQUEST>();
        readonly List<UsnEntry> _found = new List<UsnEntry>();
        bool _suppressToggleEvents = false;

        public MainForm(FileHiderClient client)
        {
            _client = client;

            Text = "USN Journal Scrubber";
            ClientSize = new System.Drawing.Size(1240, 820);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = System.Drawing.Color.FromArgb(22, 22, 26);
            ForeColor = System.Drawing.Color.FromArgb(220, 220, 225);
            Font = new System.Drawing.Font("Segoe UI", 9f);

            var lblTitle = new Label
            {
                Text = "USN Journal Scrubber",
                Location = new System.Drawing.Point(16, 12),
                Size = new System.Drawing.Size(1200, 26),
                Font = new System.Drawing.Font("Segoe UI Semibold", 14f),
                ForeColor = System.Drawing.Color.FromArgb(240, 240, 245)
            };

            var lblSub = new Label
            {
                Text = "Rules persist regardless of driver state. On-disk scrub makes the hide permanent.",
                Location = new System.Drawing.Point(18, 38),
                Size = new System.Drawing.Size(1200, 16),
                ForeColor = System.Drawing.Color.FromArgb(150, 150, 160)
            };

            var grpRules = new GroupBox
            {
                Text = "Removal Rules  (auto-scrubs on Add)",
                Location = new System.Drawing.Point(16, 62),
                Size = new System.Drawing.Size(600, 300),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };

            var lblVolume = new Label
            {
                Text = "Volume:",
                Location = new System.Drawing.Point(12, 28),
                Size = new System.Drawing.Size(60, 20),
                TextAlign = System.Drawing.ContentAlignment.MiddleLeft
            };

            _txtVolume = new TextBox
            {
                Location = new System.Drawing.Point(72, 26),
                Width = 50,
                Text = "C:",
                BackColor = System.Drawing.Color.FromArgb(38, 38, 44),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225),
                BorderStyle = BorderStyle.FixedSingle
            };

            var lblString = new Label
            {
                Text = "Filename substring:",
                Location = new System.Drawing.Point(12, 60),
                Size = new System.Drawing.Size(120, 20),
                TextAlign = System.Drawing.ContentAlignment.MiddleLeft
            };

            _txtString = new TextBox
            {
                Location = new System.Drawing.Point(138, 58),
                Width = 320,
                BackColor = System.Drawing.Color.FromArgb(38, 38, 44),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225),
                BorderStyle = BorderStyle.FixedSingle
            };

            _btnAddString = new Button
            {
                Text = "Add String",
                Location = new System.Drawing.Point(466, 57),
                Width = 122,
                Height = 24,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(50, 80, 50),
                ForeColor = System.Drawing.Color.FromArgb(210, 240, 210)
            };
            _btnAddString.Click += AddStringRule;

            var lblUsn = new Label
            {
                Text = "USN (dec or 0x…):",
                Location = new System.Drawing.Point(12, 92),
                Size = new System.Drawing.Size(120, 20),
                TextAlign = System.Drawing.ContentAlignment.MiddleLeft
            };

            _txtUsn = new TextBox
            {
                Location = new System.Drawing.Point(138, 90),
                Width = 320,
                BackColor = System.Drawing.Color.FromArgb(38, 38, 44),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225),
                BorderStyle = BorderStyle.FixedSingle
            };

            _btnAddUsn = new Button
            {
                Text = "Add USN",
                Location = new System.Drawing.Point(466, 89),
                Width = 122,
                Height = 24,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(80, 55, 40),
                ForeColor = System.Drawing.Color.FromArgb(240, 210, 180)
            };
            _btnAddUsn.Click += AddUsnRule;

            _lstRules = new ListBox
            {
                Location = new System.Drawing.Point(12, 122),
                Size = new System.Drawing.Size(576, 130),
                BackColor = System.Drawing.Color.FromArgb(30, 30, 36),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new System.Drawing.Font("Consolas", 8.5f),
                IntegralHeight = false
            };

            _btnRemoveRule = new Button
            {
                Text = "Remove",
                Location = new System.Drawing.Point(12, 260),
                Width = 110,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(60, 45, 45),
                ForeColor = System.Drawing.Color.FromArgb(240, 200, 200)
            };
            _btnRemoveRule.Click += RemoveSelectedRule;

            _btnClearRules = new Button
            {
                Text = "Clear All",
                Location = new System.Drawing.Point(128, 260),
                Width = 110,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(50, 50, 60),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225)
            };
            _btnClearRules.Click += (s, e) => ClearAllRules();

            _btnScrubAll = new Button
            {
                Text = "Scrub All Rules Now",
                Location = new System.Drawing.Point(244, 260),
                Width = 170,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(100, 60, 60),
                ForeColor = System.Drawing.Color.FromArgb(255, 220, 220)
            };
            _btnScrubAll.Click += (s, e) => ScrubAllRulesNow(false);

            _chkAutoRescrub = new CheckBox
            {
                Text = "Auto-rescrub 5s",
                Location = new System.Drawing.Point(424, 262),
                Size = new System.Drawing.Size(160, 22),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };
            _chkAutoRescrub.CheckedChanged += (s, e) =>
            {
                _rescrubTimer.Enabled = _chkAutoRescrub.Checked;
                SetStatus(_chkAutoRescrub.Checked
                    ? "Auto-rescrub ON — matches removed from journal every 5 s."
                    : "Auto-rescrub OFF.", false);
            };

            _rescrubTimer = new System.Windows.Forms.Timer { Interval = 5000 };
            _rescrubTimer.Tick += (s, e) =>
            {
                if (_chkAutoRescrub.Checked) ScrubAllRulesNow(true);
            };

            grpRules.Controls.AddRange(new Control[] {
                lblVolume, _txtVolume,
                lblString, _txtString, _btnAddString,
                lblUsn, _txtUsn, _btnAddUsn,
                _lstRules, _btnRemoveRule, _btnClearRules, _btnScrubAll,
                _chkAutoRescrub
            });

            var grpDiscovery = new GroupBox
            {
                Text = "Manual Search / Scrub",
                Location = new System.Drawing.Point(624, 62),
                Size = new System.Drawing.Size(600, 300),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };

            var lblSearch = new Label
            {
                Text = "Search journal:",
                Location = new System.Drawing.Point(12, 26),
                Size = new System.Drawing.Size(100, 20),
                TextAlign = System.Drawing.ContentAlignment.MiddleLeft
            };

            _txtSearch = new TextBox
            {
                Location = new System.Drawing.Point(114, 24),
                Width = 340,
                BackColor = System.Drawing.Color.FromArgb(38, 38, 44),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225),
                BorderStyle = BorderStyle.FixedSingle
            };
            _txtSearch.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    e.SuppressKeyPress = true;
                    SearchJournal();
                }
            };

            _btnSearch = new Button
            {
                Text = "Search",
                Location = new System.Drawing.Point(460, 23),
                Width = 128,
                Height = 24,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(60, 70, 90),
                ForeColor = System.Drawing.Color.FromArgb(210, 220, 240)
            };
            _btnSearch.Click += (s, e) => SearchJournal();

            var lblFound = new Label
            {
                Text = "Matching records in journal (USN ← filename):",
                Location = new System.Drawing.Point(12, 54),
                Size = new System.Drawing.Size(576, 18)
            };

            _lstFound = new ListBox
            {
                Location = new System.Drawing.Point(12, 76),
                Size = new System.Drawing.Size(576, 170),
                BackColor = System.Drawing.Color.FromArgb(26, 32, 26),
                ForeColor = System.Drawing.Color.FromArgb(200, 240, 200),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new System.Drawing.Font("Consolas", 8.5f),
                IntegralHeight = false,
                HorizontalScrollbar = true
            };

            _btnDiscover = new Button
            {
                Text = "Discover (by rules)",
                Location = new System.Drawing.Point(12, 254),
                Width = 170,
                Height = 30,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(60, 70, 90),
                ForeColor = System.Drawing.Color.FromArgb(210, 220, 240)
            };
            _btnDiscover.Click += (s, e) => Discover();

            _btnScrub = new Button
            {
                Text = "Scrub Found On Disk",
                Location = new System.Drawing.Point(190, 254),
                Width = 190,
                Height = 30,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(100, 50, 50),
                ForeColor = System.Drawing.Color.FromArgb(255, 220, 220)
            };
            _btnScrub.Click += (s, e) => ScrubOnDisk();

            _btnPurge = new Button
            {
                Text = "Purge Whole Journal",
                Location = new System.Drawing.Point(388, 254),
                Width = 160,
                Height = 30,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(120, 40, 40),
                ForeColor = System.Drawing.Color.FromArgb(255, 210, 210)
            };
            _btnPurge.Click += (s, e) => PurgeJournal();

            grpDiscovery.Controls.AddRange(new Control[] {
                lblSearch, _txtSearch, _btnSearch,
                lblFound, _lstFound,
                _btnDiscover, _btnScrub, _btnPurge
            });

            var grpDriver = new GroupBox
            {
                Text = "Driver Control",
                Location = new System.Drawing.Point(16, 372),
                Size = new System.Drawing.Size(1208, 90),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };

            _lblDriver = new Label
            {
                Location = new System.Drawing.Point(12, 20),
                Width = 800,
                Height = 60,
                ForeColor = System.Drawing.Color.FromArgb(170, 170, 180),
                Font = new System.Drawing.Font("Consolas", 8f),
                Text = "Driver: (checking…)"
            };

            _chkSpoof = new CheckBox
            {
                Text = "Spoof empty journal",
                Location = new System.Drawing.Point(824, 22),
                Size = new System.Drawing.Size(180, 22),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };
            _chkSpoof.CheckedChanged += (s, e) => ApplyToggle(
                v => _client.SetSpoof(v), _chkSpoof.Checked, "Spoof Empty Journal");

            _chkHideJournal = new CheckBox
            {
                Text = "Hide $UsnJrnl runtime",
                Location = new System.Drawing.Point(824, 46),
                Size = new System.Drawing.Size(200, 22),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };
            _chkHideJournal.CheckedChanged += (s, e) => ApplyToggle(
                v => _client.SetHideJournal(v), _chkHideJournal.Checked, "Hide $UsnJrnl");

            _btnLoadDriver = new Button
            {
                Text = "Load",
                Location = new System.Drawing.Point(1030, 20),
                Width = 80,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(45, 70, 45),
                ForeColor = System.Drawing.Color.FromArgb(200, 240, 200)
            };
            _btnLoadDriver.Click += (s, e) => LoadDriver();

            _btnUnloadDriver = new Button
            {
                Text = "Unload",
                Location = new System.Drawing.Point(1116, 20),
                Width = 80,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(70, 45, 45),
                ForeColor = System.Drawing.Color.FromArgb(240, 200, 200)
            };
            _btnUnloadDriver.Click += (s, e) => UnloadDriver();

            _btnVerify = new Button
            {
                Text = "Verify",
                Location = new System.Drawing.Point(1030, 50),
                Width = 80,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(50, 50, 60),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225)
            };
            _btnVerify.Click += (s, e) => VerifyDriver();

            _btnRefresh = new Button
            {
                Text = "Refresh",
                Location = new System.Drawing.Point(1116, 50),
                Width = 80,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = System.Drawing.Color.FromArgb(50, 50, 60),
                ForeColor = System.Drawing.Color.FromArgb(220, 220, 225)
            };
            _btnRefresh.Click += (s, e) => RefreshList();

            grpDriver.Controls.AddRange(new Control[] {
                _lblDriver,
                _chkSpoof, _chkHideJournal,
                _btnLoadDriver, _btnUnloadDriver,
                _btnVerify, _btnRefresh
            });

            var grpDiag = new GroupBox
            {
                Text = "Diagnostics",
                Location = new System.Drawing.Point(16, 468),
                Size = new System.Drawing.Size(1208, 300),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 210)
            };

            _txtDiag = new TextBox
            {
                Location = new System.Drawing.Point(12, 22),
                Size = new System.Drawing.Size(1184, 240),
                BackColor = System.Drawing.Color.FromArgb(16, 16, 20),
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 180),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new System.Drawing.Font("Consolas", 8f),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = false,
                Text = "Diagnostics will appear here."
            };

            grpDiag.Controls.Add(_txtDiag);

            _lblStatus = new Label
            {
                Location = new System.Drawing.Point(16, 778),
                Width = 1208,
                Height = 24,
                ForeColor = System.Drawing.Color.FromArgb(140, 200, 140),
                Font = new System.Drawing.Font("Segoe UI", 9f),
                Text = "Ready."
            };

            Controls.AddRange(new Control[]
            {
                lblTitle, lblSub,
                grpRules, grpDiscovery, grpDriver, grpDiag,
                _lblStatus
            });

            RedrawRulesList();
            RefreshList();
        }

        // ── helpers ────────────────────────────────────────────────

        void RedrawRulesList()
        {
            _lstRules.Items.Clear();
            foreach (var r in _rules)
                _lstRules.Items.Add(r.ToString());
        }

        List<UsnEntry> EnumerateWithDriverPaused(string vol)
        {
            bool savedSpoof = false, savedHide = false;

            if (_client != null && _client.IsConnected)
            {
                try { savedSpoof = _client.GetSpoof(); } catch { }
                try { savedHide = _client.GetHideJournal(); } catch { }

                _client.ClearAll();
                _client.SetSpoof(false);
                _client.SetHideJournal(false);
            }

            try
            {
                return UsnJournalHelper.EnumerateAll(vol);
            }
            finally
            {
                if (_client != null && _client.IsConnected)
                {
                    foreach (var r in _rules)
                    {
                        try
                        {
                            if (r.Usn != 0) _client.AddUsnRule(r.Usn);
                            else _client.AddStringRule(r.String);
                        }
                        catch { }
                    }
                    _client.SetSpoof(savedSpoof);
                    _client.SetHideJournal(savedHide);
                }
            }
        }

        int ScrubUsnsSilently(string vol, List<ulong> usns, Action<int> progress)
        {
            if (_client != null && _client.IsConnected)
            {
                try { _client.ClearAll(); } catch { }
            }
            try
            {
                return UsnJournalHelper.ScrubOnDisk(vol, usns, progress);
            }
            finally
            {
                if (_client != null && _client.IsConnected)
                {
                    foreach (var r in _rules)
                    {
                        try
                        {
                            if (r.Usn != 0) _client.AddUsnRule(r.Usn);
                            else _client.AddStringRule(r.String);
                        }
                        catch { }
                    }
                }
            }
        }

        void ScrubAllRulesNow(bool silent)
        {
            if (_rules.Count == 0)
            {
                if (!silent) SetStatus("No rules to scrub.", true);
                return;
            }

            try
            {
                string vol = _txtVolume.Text.Trim();
                if (!vol.EndsWith(":")) vol += ":";

                if (!silent) SetStatus("Enumerating journal for scrub-all…", false);

                var all = EnumerateWithDriverPaused(vol);
                var toErase = new List<ulong>();

                foreach (var e in all)
                {
                    foreach (var r in _rules)
                    {
                        bool hit = r.Usn != 0
                            ? e.Usn == r.Usn
                            : (!string.IsNullOrEmpty(e.Name) &&
                               !string.IsNullOrEmpty(r.String) &&
                               e.Name.IndexOf(r.String, StringComparison.OrdinalIgnoreCase) >= 0);
                        if (hit) { toErase.Add(e.Usn); break; }
                    }
                }

                if (toErase.Count == 0)
                {
                    if (!silent) SetStatus("Scrub all: no matching records found.", false);
                    return;
                }

                int patched = ScrubUsnsSilently(vol, toErase,
                    silent ? (Action<int>)null
                           : (n => SetStatus("Scrub all: patched " + n + " / " + toErase.Count, false)));

                SetStatus("Scrub all: " + patched + " of " + toErase.Count + " record(s) zeroed on disk.", false);
            }
            catch (Exception ex)
            {
                if (!silent) SetStatus("Scrub all failed: " + ex.Message, true);
            }
        }

        void AutoHide(string substring, ulong usn)
        {
            try
            {
                string vol = _txtVolume.Text.Trim();
                if (!vol.EndsWith(":")) vol += ":";

                string label = usn != 0 ? "USN 0x" + usn.ToString("X16") : "'" + substring + "'";
                SetStatus("Auto-hide: scanning journal for " + label + "…", false);

                var all = EnumerateWithDriverPaused(vol);
                var toErase = new List<ulong>();

                foreach (var en in all)
                {
                    bool hit = usn != 0
                        ? en.Usn == usn
                        : (!string.IsNullOrEmpty(en.Name) &&
                           en.Name.IndexOf(substring, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (hit) toErase.Add(en.Usn);
                }

                if (toErase.Count == 0)
                {
                    SetStatus("Hiding " + label + " — no matching records found in journal.", false);
                    return;
                }

                SetStatus("Auto-hide: zeroing " + toErase.Count + " record(s) on disk…", false);

                int patched = ScrubUsnsSilently(vol, toErase,
                    n => SetStatus("Auto-hide: patched " + n + " / " + toErase.Count, false));

                SetStatus("Hiding " + label + ". " + patched + " record(s) physically zeroed on disk.", false);
            }
            catch (Exception ex)
            {
                SetStatus("On-disk scrub failed: " + ex.Message, true);
            }
        }

        // ── handlers ───────────────────────────────────────────────

        void ApplyToggle(Action<bool> setter, bool desired, string name)
        {
            if (_suppressToggleEvents) return;
            if (_client == null || !_client.IsConnected)
            {
                SetStatus(name + ": not applied — driver not connected.", true);
                _suppressToggleEvents = true;
                try { _chkSpoof.Checked = _client != null && _client.GetSpoof(); } catch { }
                try { _chkHideJournal.Checked = _client != null && _client.GetHideJournal(); } catch { }
                _suppressToggleEvents = false;
                return;
            }
            try
            {
                setter(desired);
                SetStatus(name + (desired ? " ON." : " OFF."), false);
                RefreshList();
            }
            catch (Exception ex) { SetStatus(name + " failed: " + ex.Message, true); }
        }

        bool RuleExists(string substring, ulong usn)
        {
            foreach (var r in _rules)
            {
                if (usn != 0 && r.Usn == usn) return true;
                if (usn == 0 && r.Usn == 0 &&
                    string.Equals(r.String, substring, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        void AddStringRule(object sender, EventArgs e)
        {
            string s = _txtString.Text.Trim();
            if (string.IsNullOrEmpty(s)) { SetStatus("Enter a filename substring.", true); return; }

            if (RuleExists(s, 0))
            {
                SetStatus("Rule already active: '" + s + "'.", true);
                _txtString.Clear();
                return;
            }

            var newRule = new RULE_REQUEST { String = s, Usn = 0 };
            _rules.Add(newRule);

            if (_client != null && _client.IsConnected)
            {
                try { _client.AddStringRule(s); }
                catch (Exception ex) { SetStatus("Driver rule failed: " + ex.Message, true); }
            }

            _txtString.Clear();
            RedrawRulesList();
            AutoHide(s, 0);
        }

        void AddUsnRule(object sender, EventArgs e)
        {
            string s = _txtUsn.Text.Trim();
            if (!TryParseUsn(s, out ulong usn))
            { SetStatus("Enter a decimal USN or 0x-prefixed hex.", true); return; }

            if (RuleExists(null, usn))
            {
                SetStatus("USN already active: 0x" + usn.ToString("X16"), true);
                _txtUsn.Clear();
                return;
            }

            var newRule = new RULE_REQUEST { String = "", Usn = usn };
            _rules.Add(newRule);

            if (_client != null && _client.IsConnected)
            {
                try { _client.AddUsnRule(usn); }
                catch (Exception ex) { SetStatus("Driver rule failed: " + ex.Message, true); }
            }

            _txtUsn.Clear();
            RedrawRulesList();
            AutoHide(null, usn);
        }

        static bool TryParseUsn(string s, out ulong usn)
        {
            usn = 0;
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.TryParse(s.Substring(2),
                    System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out usn);
            return ulong.TryParse(s, out usn);
        }

        void RemoveSelectedRule(object sender, EventArgs e)
        {
            if (_lstRules.SelectedIndex < 0 || _lstRules.SelectedIndex >= _rules.Count)
            { SetStatus("Select a rule first.", true); return; }

            var r = _rules[_lstRules.SelectedIndex];
            _rules.RemoveAt(_lstRules.SelectedIndex);

            if (_client != null && _client.IsConnected)
            {
                try
                {
                    if (r.Usn != 0) _client.RemoveUsnRule(r.Usn);
                    else _client.RemoveStringRule(r.String);
                }
                catch { }
            }

            RedrawRulesList();
            SetStatus("Removed: " + r.ToString() + " (on-disk records stay scrubbed).", false);
        }

        void ClearAllRules()
        {
            _rules.Clear();
            if (_client != null && _client.IsConnected)
            {
                try { _client.ClearAll(); } catch { }
            }
            RedrawRulesList();
            SetStatus("All rules cleared.", false);
        }

        void SearchJournal()
        {
            string term = _txtSearch.Text.Trim();
            if (string.IsNullOrEmpty(term))
            { SetStatus("Enter something to search for.", true); return; }

            _btnSearch.Enabled = false;
            try
            {
                string vol = _txtVolume.Text.Trim();
                if (!vol.EndsWith(":")) vol += ":";

                SetStatus("Searching journal for '" + term + "'…", false);

                _lstFound.Items.Clear();
                _found.Clear();

                var all = EnumerateWithDriverPaused(vol);

                int matches = 0;
                foreach (var e in all)
                {
                    if (!string.IsNullOrEmpty(e.Name) &&
                        e.Name.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        _found.Add(e);
                        _lstFound.Items.Add(e.ToString());
                        matches++;
                    }
                }

                SetStatus(string.Format(
                    "Searched {0} records for '{1}'. {2} match. Click 'Scrub Found On Disk' to remove.",
                    all.Count, term, matches), false);

                RefreshList();
            }
            catch (Exception ex)
            {
                SetStatus("Search failed: " + ex.Message, true);
                MessageBox.Show("Search failed.\n\n" + ex.Message,
                    "Search", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally { _btnSearch.Enabled = true; }
        }

        void Discover()
        {
            if (_rules.Count == 0)
            { SetStatus("Add at least one rule before discovering.", true); return; }

            _btnDiscover.Enabled = false;
            try
            {
                string vol = _txtVolume.Text.Trim();
                if (!vol.EndsWith(":")) vol += ":";

                SetStatus("Enumerating journal…", false);

                _lstFound.Items.Clear();
                _found.Clear();

                var all = EnumerateWithDriverPaused(vol);
                var matches = UsnJournalHelper.FindMatches(all, _rules);

                foreach (var m in matches)
                {
                    _found.Add(m);
                    _lstFound.Items.Add(m.ToString());
                }

                SetStatus(string.Format(
                    "Scanned {0} records. {1} match your rules. Click 'Scrub Found On Disk' next.",
                    all.Count, matches.Count), false);

                RefreshList();
            }
            catch (Exception ex)
            {
                SetStatus("Discover failed: " + ex.Message, true);
                MessageBox.Show("Discover failed.\n\n" + ex.Message,
                    "Discover", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally { _btnDiscover.Enabled = true; }
        }

        void ScrubOnDisk()
        {
            if (_found.Count == 0)
            { SetStatus("Nothing found. Search or Discover first.", true); return; }

            var usns = new List<ulong>();
            foreach (var f in _found) usns.Add(f.Usn);

            var confirm = MessageBox.Show(
                "Permanently zero the FILE_NAME of " + usns.Count
                + " journal record(s) on disk?\n\n"
                + "Close JournalTrace++ first — it holds handles that block the write.\n\n"
                + "This cannot be undone.",
                "Scrub Found On Disk", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            _btnScrub.Enabled = false;
            try
            {
                SetStatus("Patching on-disk journal…", false);
                string vol = _txtVolume.Text.Trim();
                if (!vol.EndsWith(":")) vol += ":";

                int patched = ScrubUsnsSilently(vol, usns,
                    n => SetStatus("Patched " + n + " record(s)…", false));

                SetStatus("Done. " + patched + " record(s) permanently zeroed.", false);

                MessageBox.Show(
                    "Scrub complete.\n\n"
                    + "Records patched: " + patched + "\n\n"
                    + "Now close AND reopen JournalTrace++. The entries will be gone.",
                    "Scrub Found On Disk", MessageBoxButtons.OK, MessageBoxIcon.Information);

                _lstFound.Items.Clear();
                _found.Clear();
            }
            catch (Exception ex)
            {
                SetStatus("Scrub failed.", true);
                MessageBox.Show("Scrub failed.\n\n" + ex.Message,
                    "Scrub Found On Disk", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                _btnScrub.Enabled = true;
                RefreshList();
            }
        }

        void PurgeJournal()
        {
            var confirm = MessageBox.Show(
                "Delete the ENTIRE USN journal and recreate it empty?\n\n"
                + "Close JournalTrace++ first.\n\n"
                + "Every record on the volume will be gone. Cannot be undone.",
                "Purge Whole Journal",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            try
            {
                if (_client != null && _client.IsConnected)
                {
                    try { _client.ClearAll(); } catch { }
                }

                SetStatus("Purging journal…", false);
                string vol = _txtVolume.Text.Trim();
                if (!vol.EndsWith(":")) vol += ":";
                UsnJournalHelper.PurgeWholeJournal(vol);
                SetStatus("Journal purged and recreated empty.", false);

                MessageBox.Show(
                    "Journal purged successfully.\n\n"
                    + "Close AND reopen JournalTrace++. The journal is now empty.",
                    "Purge Whole Journal",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                _lstFound.Items.Clear();
                _found.Clear();
            }
            catch (Exception ex)
            {
                SetStatus("Purge failed.", true);
                MessageBox.Show("Purge failed.\n\n" + ex.Message,
                    "Purge Whole Journal", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                if (_client != null && _client.IsConnected)
                {
                    foreach (var r in _rules)
                    {
                        try
                        {
                            if (r.Usn != 0) _client.AddUsnRule(r.Usn);
                            else _client.AddStringRule(r.String);
                        }
                        catch { }
                    }
                }

                RefreshList();
            }
        }

        void LoadDriver()
        {
            _btnLoadDriver.Enabled = false;
            try
            {
                SetStatus("Loading driver…", false);
                FileHiderClient fresh = DriverManager.LoadFresh();
                try { _client?.Dispose(); } catch { }
                _client = fresh;

                // Push any persisted rules to the fresh driver.
                try { _client.ClearAll(); } catch { }
                foreach (var r in _rules)
                {
                    try
                    {
                        if (r.Usn != 0) _client.AddUsnRule(r.Usn);
                        else _client.AddStringRule(r.String);
                    }
                    catch { }
                }

                // Now that the connection is established, ask the driver
                // to hide its own LDR entry (and known vulnerable drivers).
                int renamed = 0;
                try { renamed = _client.HideNow(); } catch { }

                SetStatus("Driver loaded and hidden. Rules: " + _rules.Count
                    + ". Extra renames: " + renamed + ".", false);
                RefreshList();
            }
            catch (Exception ex) { SetStatus("Load failed: " + ex.Message, true); }
            finally { _btnLoadDriver.Enabled = true; }
        }

        void UnloadDriver()
        {
            if (_rules.Count > 0)
            {
                SetStatus("Unloading: scrubbing all rules on disk first…", false);
                try { ScrubAllRulesNow(true); } catch { }
            }

            _suppressToggleEvents = true;
            try
            {
                try { _chkSpoof.Checked = false; } catch { }
                try { _chkHideJournal.Checked = false; } catch { }
            }
            finally { _suppressToggleEvents = false; }

            try
            {
                var local = _client;
                DriverManager.UnloadAndDisconnect(ref local);
                _client = local;
                SetStatus("Driver unloaded. Rules remain in UI.", false);
            }
            catch (Exception ex) { SetStatus("Unload error: " + ex.Message, true); }
            RefreshList();
        }

        void VerifyDriver()
        {
            if (_client == null || !_client.IsConnected)
            { SetStatus("No driver connected.", true); return; }
            var st = _client.GetStatus();
            bool ok = st.Magic == FileHiderClient.FH_MAGIC;
            SetStatus(ok ? "Verify OK — v" + st.Version
                         + " session 0x" + st.SessionId.ToString("X16")
                         : "Verify FAILED — magic=0x" + st.Magic.ToString("X8"), !ok);
            RefreshList();
        }

        static string HexDump(byte[] b)
        {
            if (b == null || b.Length == 0) return "";
            var sb = new StringBuilder();
            for (int row = 0; row < b.Length; row += 16)
            {
                sb.Append(row.ToString("X4")).Append(": ");
                for (int i = 0; i < 16 && row + i < b.Length; i++)
                    sb.Append(b[row + i].ToString("X2")).Append(' ');
                sb.Append(' ');
                for (int i = 0; i < 16 && row + i < b.Length; i++)
                {
                    byte c = b[row + i];
                    sb.Append(c >= 32 && c < 127 ? (char)c : '.');
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        void RefreshList()
        {
            RedrawRulesList();

            if (_client == null || !_client.IsConnected)
            {
                _lblDriver.Text = "Driver: NOT CONNECTED — rules persist in UI; Scrub All Rules still works";
                _lblDriver.ForeColor = System.Drawing.Color.FromArgb(230, 170, 120);
                _txtDiag.Text = "Diagnostics: no driver connected.\n"
                    + "Rules: " + _rules.Count + " active in UI.\n"
                    + "On-disk scrub still functional.";
                _suppressToggleEvents = true;
                try { _chkSpoof.Checked = false; } catch { }
                try { _chkHideJournal.Checked = false; } catch { }
                _suppressToggleEvents = false;
                return;
            }

            try
            {
                var st = _client.GetStatus();
                if (st.Magic != FileHiderClient.FH_MAGIC)
                {
                    _lblDriver.Text = "Driver: FOREIGN INSTANCE — magic=0x"
                        + st.Magic.ToString("X8");
                    _lblDriver.ForeColor = System.Drawing.Color.FromArgb(230, 120, 120);
                    return;
                }

                bool attached = st.FilterAttached != 0;
                _lblDriver.Text = string.Format(
                    "Driver: {0} | v{1} | session 0x{2:X16} | UI rules: {3} | driver rules: {4} | "
                    + "spoof: {5}  hideJ: {6}",
                    attached ? "ATTACHED" : "NOT ATTACHED",
                    st.Version, st.SessionId, _rules.Count, st.RuleCount,
                    st.SpoofEmpty != 0 ? "on" : "off",
                    st.HideJournal != 0 ? "on" : "off");
                _lblDriver.ForeColor = attached
                    ? System.Drawing.Color.FromArgb(140, 200, 140)
                    : System.Drawing.Color.FromArgb(230, 120, 120);

                string validateTxt = st.LastValidate switch
                {
                    1 => "ok@8",
                    2 => "ok@0",
                    3 => "FAILED",
                    4 => "single",
                    _ => "never"
                };

                var sb = new StringBuilder();
                sb.AppendLine(string.Format(
                    "FSCTL : preOp={0} postOp={1} noBuf={2} infoBad={3}",
                    st.PreOpSeen, st.PostOpSeen, st.PostOpNoBuf, st.PostOpInfoBad));
                sb.AppendLine(string.Format(
                    "READ  : preOp={0} postOp={1} noBuf={2} infoBad={3} matched={4}",
                    st.ReadPreSeen, st.ReadPostSeen, st.ReadNoBuf, st.ReadInfoBad, st.ReadMatched));
                sb.AppendLine(string.Format(
                    "CREATE: hits={0} nameHits={1} uncacheForced={2} journalBlocked={3}",
                    st.CreateHits, st.CreateNameHits, st.CreateUncacheForced, st.JournalBlocked));
                sb.AppendLine(string.Format(
                    "Last  : code=0x{0:X8} method={1} info={2} cap={3}",
                    st.LastCode, st.LastMethod, st.LastInfo, st.LastOutCap));
                sb.AppendLine(string.Format(
                    "        validate={0} recs={1} filtered={2}  parseFails={3}",
                    validateTxt, st.LastRecords, st.LastFiltered, st.ParseFailures));
                sb.AppendLine(string.Format(
                    "First record name (len {0}): \"{1}\"",
                    st.FirstNameLen, st.FirstName));
                sb.Append(HexDump(st.LastRaw));

                _txtDiag.Text = sb.ToString();

                _suppressToggleEvents = true;
                try { _chkSpoof.Checked = st.SpoofEmpty != 0; } catch { }
                try { _chkHideJournal.Checked = st.HideJournal != 0; } catch { }
                _suppressToggleEvents = false;
            }
            catch (Exception ex)
            {
                _lblDriver.Text = "Driver: state error — " + ex.Message;
                _lblDriver.ForeColor = System.Drawing.Color.FromArgb(230, 120, 120);
            }
        }

        void SetStatus(string text, bool warn)
        {
            _lblStatus.Text = text;
            _lblStatus.ForeColor = warn
                ? System.Drawing.Color.FromArgb(220, 160, 120)
                : System.Drawing.Color.FromArgb(140, 200, 140);
        }
    }

    static class Program
    {
        static void EnsureAdmin()
        {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            if (p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                return;

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = System.Reflection.Assembly.GetExecutingAssembly().Location,
                UseShellExecute = true,
                Verb = "runas"
            };
            try { System.Diagnostics.Process.Start(psi); }
            catch
            {
                MessageBox.Show("Administrator privileges required.", "USN Scrubber",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            Environment.Exit(0);
        }

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--unload")
            {
                DriverManager.WipeStaleState();
                KernelLoader.ForceUnload();
                MessageBox.Show("Unloaded. Log: " + KernelLoader.GetLogPath(),
                    "USN Journal Scrubber");
                return;
            }

            EnsureAdmin();

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            FileHiderClient client = null;
            string startupError = null;

            try
            {
                client = DriverManager.LoadFresh();
            }
            catch (Exception ex)
            {
                startupError = ex.Message;
            }

            // Hide the driver after the connection works — never during load.
            if (client != null && client.IsConnected)
            {
                try { client.HideNow(); } catch { }
            }

            var form = new MainForm(client);

            if (client == null)
            {
                MessageBox.Show(
                    "Driver not loaded. The app still works — on-disk scrub does not need a driver.\n\n"
                    + "Use 'Scrub All Rules Now' any time, or Load Driver for runtime filtering.\n"
                    + (startupError != null ? "\nReason: " + startupError : ""),
                    "USN Journal Scrubber",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }

            try { Application.Run(form); }
            finally
            {
                try
                {
                    var local = client;
                    DriverManager.UnloadAndDisconnect(ref local);
                }
                catch { }
            }
        }
    }
}