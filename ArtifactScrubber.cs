using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace FileHider
{
    internal enum ArtifactKind
    {
        Prefetch,
        AmCache,
        ShimCache,
        TempLeftover,
        ServiceKey,
        ProjectFile,
        EventLog,
        UsnJournal
    }

    internal class DetectedArtifact
    {
        public ArtifactKind Kind;
        public string Path;
        public string Detail;
        public bool CanScrub;
        public DateTime? LastWrite;
        public long Size;
    }

    internal static class ArtifactScrubber
    {
        // ─── project fingerprint strings ────────────────────
        static readonly string[] PROJECT_NAMES = new[]
        {
            "FileHider", "FsPolicySvc", "NvStreamKms",
            "RTCore64", "NvStreamKms", "FsPolicySvcInst"
        };

        static readonly string[] PROJECT_PATHS = new[]
        {
            @"USNJOURNAL BYPASS",
            @"~FsPolicySvc_", "~NvStreamKms_"
        };

        static bool MatchAny(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            foreach (var n in PROJECT_NAMES)
                if (s.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            foreach (var p in PROJECT_PATHS)
                if (s.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        // ═════════════════════════════════════════════════════
        //  SCAN — returns every trace found
        // ═════════════════════════════════════════════════════
        public static List<DetectedArtifact> ScanAll()
        {
            var all = new List<DetectedArtifact>();
            SafeScan(all, ScanPrefetch);
            SafeScan(all, ScanAmCache);
            SafeScan(all, ScanShimCache);
            SafeScan(all, ScanTempLeftovers);
            SafeScan(all, ScanServiceKeys);
            SafeScan(all, ScanProjectDir);
            SafeScan(all, ScanEventLog);
            SafeScan(all, ScanUsnJournal);
            return all;
        }

        static void SafeScan(List<DetectedArtifact> into, Action<List<DetectedArtifact>> fn)
        {
            try { fn(into); }
            catch (Exception ex)
            {
                into.Add(new DetectedArtifact
                {
                    Kind = ArtifactKind.ProjectFile,
                    Path = "(scan error)",
                    Detail = ex.Message,
                    CanScrub = false
                });
            }
        }

        // ─── Prefetch ────────────────────────────────────────
        static void ScanPrefetch(List<DetectedArtifact> into)
        {
            string pfDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Prefetch");
            if (!Directory.Exists(pfDir)) return;

            foreach (var f in Directory.EnumerateFiles(pfDir, "*.pf"))
            {
                string name = Path.GetFileName(f);
                bool hit = false;
                foreach (var n in PROJECT_NAMES)
                    if (name.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) { hit = true; break; }
                if (!hit) continue;

                var fi = new FileInfo(f);
                into.Add(new DetectedArtifact
                {
                    Kind = ArtifactKind.Prefetch,
                    Path = f,
                    Detail = "Prefetch entry — contains run count + loaded DLL paths",
                    CanScrub = true,
                    LastWrite = fi.LastWriteTimeUtc,
                    Size = fi.Length
                });
            }
        }

        // ─── AmCache ─────────────────────────────────────────
        static void ScanAmCache(List<DetectedArtifact> into)
        {
            string hive = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"AppCompat\Programs\Amcache.hve");
            if (!File.Exists(hive)) return;

            string mount = "AmcacheScrubTmp";
            if (!LoadHive(mount, hive)) return;
            try
            {
                using (var root = Registry.LocalMachine.OpenSubKey(mount + @"\Root\InventoryApplicationFile"))
                {
                    if (root != null)
                    {
                        foreach (var sub in root.GetSubKeyNames())
                        {
                            using (var sk = root.OpenSubKey(sub))
                            {
                                if (sk == null) continue;
                                string p = sk.GetValue("LowerCaseLongPath") as string
                                        ?? sk.GetValue("LongPath") as string;
                                if (MatchAny(p))
                                {
                                    into.Add(new DetectedArtifact
                                    {
                                        Kind = ArtifactKind.AmCache,
                                        Path = mount + @"\Root\InventoryApplicationFile\" + sub,
                                        Detail = p,
                                        CanScrub = true
                                    });
                                }
                            }
                        }
                    }
                }

                using (var files = Registry.LocalMachine.OpenSubKey(mount + @"\Root\File"))
                {
                    if (files != null)
                    {
                        foreach (var vol in files.GetSubKeyNames())
                        {
                            using (var volk = files.OpenSubKey(vol))
                            {
                                if (volk == null) continue;
                                foreach (var fk in volk.GetSubKeyNames())
                                {
                                    using (var fv = volk.OpenSubKey(fk))
                                    {
                                        if (fv == null) continue;
                                        string p = fv.GetValue("15") as string
                                                ?? fv.GetValue("Path") as string;
                                        if (MatchAny(p))
                                        {
                                            into.Add(new DetectedArtifact
                                            {
                                                Kind = ArtifactKind.AmCache,
                                                Path = mount + @"\Root\File\" + vol + @"\" + fk,
                                                Detail = p,
                                                CanScrub = true
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            finally { UnloadHive(mount); }
        }

        // ─── ShimCache ───────────────────────────────────────
        static void ScanShimCache(List<DetectedArtifact> into)
        {
            const string key = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
            using (var k = Registry.LocalMachine.OpenSubKey(key))
            {
                if (k == null) return;
                byte[] blob = k.GetValue("AppCompatCache") as byte[];
                if (blob == null || blob.Length < 32) return;

                // UTF-16 scan for our names
                string wide = Encoding.Unicode.GetString(blob);
                bool found = false;
                foreach (var n in PROJECT_NAMES)
                    if (wide.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) { found = true; break; }
                if (!found) return;

                into.Add(new DetectedArtifact
                {
                    Kind = ArtifactKind.ShimCache,
                    Path = @"HKLM\" + key + @"\AppCompatCache",
                    Detail = "ShimCache blob contains project paths (" + blob.Length + " bytes)",
                    CanScrub = true,
                    Size = blob.Length
                });
            }
        }

        // ─── temp leftovers ──────────────────────────────────
        static void ScanTempLeftovers(List<DetectedArtifact> into)
        {
            string temp = Path.GetTempPath();
            foreach (var pat in new[] { "~FsPolicySvc_*.tmp", "~NvStreamKms_*.tmp",
                                        "RTCore64.bin", "FileHider.bin" })
            {
                foreach (var f in SafeGlob(temp, pat))
                {
                    var fi = new FileInfo(f);
                    into.Add(new DetectedArtifact
                    {
                        Kind = ArtifactKind.TempLeftover,
                        Path = f,
                        Detail = "leftover from previous run",
                        CanScrub = true,
                        LastWrite = fi.LastWriteTimeUtc,
                        Size = fi.Length
                    });
                }
            }
        }

        static IEnumerable<string> SafeGlob(string dir, string pattern)
        {
            try { return Directory.EnumerateFiles(dir, pattern); }
            catch { return Enumerable.Empty<string>(); }
        }

        // ─── service keys ────────────────────────────────────
        static void ScanServiceKeys(List<DetectedArtifact> into)
        {
            string[] names = { "FsPolicySvc", "NvStreamKms", "FileHider", "RTCore64", "NtfsCleanup" };
            foreach (var n in names)
            {
                string path = @"SYSTEM\CurrentControlSet\Services\" + n;
                using (var k = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (k == null) continue;
                    string img = k.GetValue("ImagePath") as string;
                    into.Add(new DetectedArtifact
                    {
                        Kind = ArtifactKind.ServiceKey,
                        Path = @"HKLM\" + path,
                        Detail = "ImagePath=" + (img ?? "(null)"),
                        CanScrub = true
                    });
                }
            }
        }

        // ─── project build artifacts ────────────────────────
        static void ScanProjectDir(List<DetectedArtifact> into)
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            foreach (var pat in new[] { "FileHider.bin", "FileHider.sys", "FileHider.exe",
                                        "FileHider.pdb", "FileHider_load.log", "*.obj" })
            {
                foreach (var f in SafeGlob(dir, pat))
                {
                    var fi = new FileInfo(f);
                    into.Add(new DetectedArtifact
                    {
                        Kind = ArtifactKind.ProjectFile,
                        Path = f,
                        Detail = "build/run artifact in app directory",
                        CanScrub = true,
                        LastWrite = fi.LastWriteTimeUtc,
                        Size = fi.Length
                    });
                }
            }
        }

        // ─── event log ───────────────────────────────────────
        static void ScanEventLog(List<DetectedArtifact> into)
        {
            try
            {
                var psi = new ProcessStartInfo("wevtutil",
                    "qe System /q:\"*[System[Provider[@Name='Service Control Manager'] and " +
                    "(EventID=7045 or EventID=7000 or EventID=7009 or EventID=7026)]]\" " +
                    "/f:text /c:50")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                {
                    string outp = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    foreach (var n in PROJECT_NAMES)
                    {
                        if (outp.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            into.Add(new DetectedArtifact
                            {
                                Kind = ArtifactKind.EventLog,
                                Path = @"System log — Service Control Manager",
                                Detail = "found reference to " + n + " in System event log",
                                CanScrub = false
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        // ─── USN journal ─────────────────────────────────────
        static void ScanUsnJournal(List<DetectedArtifact> into)
        {
            // only report — scrubbing USN requires journal deletion, which is
            // a bigger forensic flag than leaving it
            try
            {
                var psi = new ProcessStartInfo("fsutil",
                    "usn readjournal C: csv")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                // readjournal dumps the whole journal — huge. Instead just
                // note that it likely contains our entries; report without reading.
                into.Add(new DetectedArtifact
                {
                    Kind = ArtifactKind.UsnJournal,
                    Path = @"C:\$Extend\$UsnJrnl",
                    Detail = "USN journal — contains CREATE/DELETE entries for ~FsPolicySvc_*.tmp, ~NvStreamKms_*.tmp",
                    CanScrub = false
                });
            }
            catch { }
        }

        // ═════════════════════════════════════════════════════
        //  SCRUB — remove the artifact
        // ═════════════════════════════════════════════════════
        public static bool ScrubOne(DetectedArtifact a, out string message)
        {
            message = "";
            try
            {
                switch (a.Kind)
                {
                    case ArtifactKind.Prefetch:
                        return ScrubFile(a.Path, out message);

                    case ArtifactKind.TempLeftover:
                    case ArtifactKind.ProjectFile:
                        return ScrubFile(a.Path, out message);

                    case ArtifactKind.ServiceKey:
                        return ScrubServiceKey(a.Path, out message);

                    case ArtifactKind.AmCache:
                        return ScrubAmCache(a.Path, out message);

                    case ArtifactKind.ShimCache:
                        return ScrubShimCache(out message);

                    case ArtifactKind.EventLog:
                        message = "manual: log scrub leaves more traces than it removes";
                        return false;

                    case ArtifactKind.UsnJournal:
                        message = "manual: USN is append-only, deletion flags as anti-forensics";
                        return false;

                    default:
                        message = "unknown artifact kind";
                        return false;
                }
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        public static int ScrubAll(List<DetectedArtifact> all, out List<string> log)
        {
            log = new List<string>();
            int ok = 0;
            foreach (var a in all)
            {
                if (!a.CanScrub)
                {
                    log.Add("SKIP " + a.Kind + " — not scrubbable");
                    continue;
                }
                string msg;
                if (ScrubOne(a, out msg))
                {
                    ok++;
                    log.Add("OK   " + a.Kind + " — " + a.Path);
                }
                else
                {
                    log.Add("FAIL " + a.Kind + " — " + a.Path + " :: " + msg);
                }
            }
            return ok;
        }

        // ─── file scrub ──────────────────────────────────────
        static bool ScrubFile(string path, out string message)
        {
            message = "";
            if (!File.Exists(path)) { message = "already gone"; return true; }
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
            try
            {
                File.Delete(path);
                message = "deleted";
                return true;
            }
            catch (Exception ex)
            {
                // fall back to reboot-delayed delete
                try
                {
                    if (MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
                    {
                        message = "locked — scheduled delete on reboot";
                        return true;
                    }
                }
                catch { }
                message = ex.Message;
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);
        const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        // ─── service key scrub ───────────────────────────────
        static bool ScrubServiceKey(string fullPath, out string message)
        {
            message = "";
            string sub = fullPath.StartsWith(@"HKLM\")
                ? fullPath.Substring(5)
                : fullPath;
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(sub, true))
                {
                    if (k == null) { message = "already gone"; return true; }
                }
                Registry.LocalMachine.DeleteSubKeyTree(sub, false);
                message = "deleted";
                return true;
            }
            catch (Exception ex) { message = ex.Message; return false; }
        }

        // ─── AmCache scrub ───────────────────────────────────
        static bool ScrubAmCache(string mountedPath, out string message)
        {
            message = "";
            // the path already contains the mount name; scrub key
            try
            {
                Registry.LocalMachine.DeleteSubKeyTree(mountedPath, false);
                message = "deleted from Amcache hive";
                return true;
            }
            catch (Exception ex) { message = ex.Message; return false; }
        }

        // ─── ShimCache scrub (needs SYSTEM) ─────────────────
        static bool ScrubShimCache(out string message)
        {
            message = "";
            const string key = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";

            // try as admin first (works if we have SeBackupPrivilege)
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(key, true))
                {
                    if (k == null) { message = "key not writable as admin"; }
                    else
                    {
                        k.DeleteValue("AppCompatCache", false);
                        message = "deleted as admin";
                        return true;
                    }
                }
            }
            catch { }

            // fall back to SYSTEM impersonation
            IntPtr sysTok;
            if (!DuplicateSystemToken(out sysTok))
            { message = "cannot impersonate SYSTEM"; return false; }

            bool ok = false;
            try
            {
                ImpersonateLoggedOnUser(sysTok);
                using (var k = Registry.LocalMachine.OpenSubKey(key, true))
                {
                    if (k != null)
                    {
                        k.DeleteValue("AppCompatCache", false);
                        message = "deleted as SYSTEM";
                        ok = true;
                    }
                }
            }
            catch (Exception ex) { message = ex.Message; }
            finally
            {
                RevertToSelf();
                CloseHandle(sysTok);
            }
            return ok;
        }

        // ─── hive mount ──────────────────────────────────────
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int RegLoadKey(IntPtr hKey, string subKey, string file);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int RegUnLoadKey(IntPtr hKey, string subKey);

        static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));

        static bool LoadHive(string mountName, string hivePath)
        {
            // copy first — Amcache.hve is locked while in use
            string tmp = Path.Combine(Path.GetTempPath(),
                "~" + mountName + "_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".hive");
            try { File.Copy(hivePath, tmp, true); }
            catch { return false; }

            int r = RegLoadKey(HKEY_LOCAL_MACHINE, mountName, tmp);
            if (r != 0) { try { File.Delete(tmp); } catch { } return false; }
            return true;
        }

        static void UnloadHive(string mountName)
        {
            try { RegUnLoadKey(HKEY_LOCAL_MACHINE, mountName); } catch { }
            // tmp file is now unlocked; delete it
            string temp = Path.GetTempPath();
            foreach (var f in SafeGlob(temp, "~" + mountName + "_*.hive"))
                try { File.Delete(f); } catch { }
        }

        // ─── SYSTEM token dup ────────────────────────────────
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr hProc, uint access, out IntPtr hTok);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExisting, uint desired,
            IntPtr attrs, int impLevel, int tokType, out IntPtr hNew);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hTok);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);

        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ALL_ACCESS = 0xF01FF;
        const int SecurityImpersonation = 2;
        const int TokenImpersonation = 2;

        static bool DuplicateSystemToken(out IntPtr hDup)
        {
            hDup = IntPtr.Zero;
            var wl = Process.GetProcessesByName("winlogon").FirstOrDefault();
            if (wl == null) return false;

            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, wl.Id);
            if (hProc == IntPtr.Zero) return false;
            try
            {
                IntPtr hTok;
                if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, out hTok))
                    return false;
                try
                {
                    return DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, IntPtr.Zero,
                        SecurityImpersonation, TokenImpersonation, out hDup);
                }
                finally { CloseHandle(hTok); }
            }
            finally { CloseHandle(hProc); }
        }
    }
}