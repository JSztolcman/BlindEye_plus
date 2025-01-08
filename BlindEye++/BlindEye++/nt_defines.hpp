#pragma once
#include <ntifs.h>

#pragma warning (disable: 4214) // nonstandard extension used : bit field types other than int
#pragma warning (disable: 4201) // nonstandard extension used : nameless struct / union

typedef struct _EX_PUSH_LOCK
{
    union
    {
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 0 */
            /* 0x0000 */ unsigned __int64 Waiting : 1; /* bit position: 1 */
            /* 0x0000 */ unsigned __int64 Waking : 1; /* bit position: 2 */
            /* 0x0000 */ unsigned __int64 MultipleShared : 1; /* bit position: 3 */
            /* 0x0000 */ unsigned __int64 Shared : 60; /* bit position: 4 */
        }; /* bitfield */
        /* 0x0000 */ unsigned __int64 Value;
        /* 0x0000 */ void* Ptr;
    }; /* size: 0x0008 */
} __EX_PUSH_LOCK; /* size: 0x0008 */

typedef struct _OBJECT_DIRECTORY_ENTRY
{
    /* 0x0000 */ struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
    /* 0x0008 */ void* Object;
    /* 0x0010 */ unsigned long HashValue;
    /* 0x0014 */ long __PADDING__[1];
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY; /* size: 0x0018 */

typedef struct _OBJECT_DIRECTORY
{
    /* 0x0000 */ struct _OBJECT_DIRECTORY_ENTRY* HashBuckets[37];
    /* 0x0128 */ struct _EX_PUSH_LOCK Lock;
    /* 0x0130 */ struct _DEVICE_MAP* DeviceMap;
    /* 0x0138 */ struct _OBJECT_DIRECTORY* ShadowDirectory;
    /* 0x0140 */ void* NamespaceEntry;
    /* 0x0148 */ void* SessionObject;
    /* 0x0150 */ unsigned long Flags;
    /* 0x0154 */ unsigned long SessionId;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY; /* size: 0x0158 */

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[0x0100];
}RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    struct _RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
}RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// ----------------------------------------------------------------------------------------------------- // --

typedef struct _KAFFINITY_EX
{
    /* 0x0000 */ unsigned short Count;
    /* 0x0002 */ unsigned short Size;
    /* 0x0004 */ unsigned long Reserved;
    /* 0x0008 */ unsigned __int64 Bitmap[20];
} KAFFINITY_EX, * PKAFFINITY_EX; /* size: 0x00a8 */

typedef union _KEXECUTE_OPTIONS
{
    union
    {
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned char ExecuteDisable : 1; /* bit position: 0 */
            /* 0x0000 */ unsigned char ExecuteEnable : 1; /* bit position: 1 */
            /* 0x0000 */ unsigned char DisableThunkEmulation : 1; /* bit position: 2 */
            /* 0x0000 */ unsigned char Permanent : 1; /* bit position: 3 */
            /* 0x0000 */ unsigned char ExecuteDispatchEnable : 1; /* bit position: 4 */
            /* 0x0000 */ unsigned char ImageDispatchEnable : 1; /* bit position: 5 */
            /* 0x0000 */ unsigned char DisableExceptionChainValidation : 1; /* bit position: 6 */
            /* 0x0000 */ unsigned char Spare : 1; /* bit position: 7 */
        }; /* bitfield */
        /* 0x0000 */ volatile unsigned char ExecuteOptions;
        /* 0x0000 */ unsigned char ExecuteOptionsNV;
    }; /* size: 0x0001 */
} KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS; /* size: 0x0001 */

typedef union _KSTACK_COUNT
{
    union
    {
        /* 0x0000 */ long Value;
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned long State : 3; /* bit position: 0 */
            /* 0x0000 */ unsigned long StackCount : 29; /* bit position: 3 */
        }; /* bitfield */
    }; /* size: 0x0004 */
} KSTACK_COUNT, * PKSTACK_COUNT; /* size: 0x0004 */

typedef struct _KPROCESS
{
    /* 0x0000 */ struct _DISPATCHER_HEADER Header;
    /* 0x0018 */ struct _LIST_ENTRY ProfileListHead;
    /* 0x0028 */ unsigned __int64 DirectoryTableBase;
    /* 0x0030 */ struct _LIST_ENTRY ThreadListHead;
    /* 0x0040 */ unsigned long ProcessLock;
    /* 0x0044 */ unsigned long ProcessTimerDelay;
    /* 0x0048 */ unsigned __int64 DeepFreezeStartTime;
    /* 0x0050 */ struct _KAFFINITY_EX Affinity;
    /* 0x00f8 */ unsigned __int64 AffinityPadding[12];
    /* 0x0158 */ struct _LIST_ENTRY ReadyListHead;
    /* 0x0168 */ struct _SINGLE_LIST_ENTRY SwapListEntry;
    /* 0x0170 */ volatile struct _KAFFINITY_EX ActiveProcessors;
    /* 0x0218 */ unsigned __int64 ActiveProcessorsPadding[12];
    union
    {
        struct /* bitfield */
        {
            /* 0x0278 */ unsigned long AutoAlignment : 1; /* bit position: 0 */
            /* 0x0278 */ unsigned long DisableBoost : 1; /* bit position: 1 */
            /* 0x0278 */ unsigned long DisableQuantum : 1; /* bit position: 2 */
            /* 0x0278 */ unsigned long DeepFreeze : 1; /* bit position: 3 */
            /* 0x0278 */ unsigned long TimerVirtualization : 1; /* bit position: 4 */
            /* 0x0278 */ unsigned long CheckStackExtents : 1; /* bit position: 5 */
            /* 0x0278 */ unsigned long CacheIsolationEnabled : 1; /* bit position: 6 */
            /* 0x0278 */ unsigned long PpmPolicy : 3; /* bit position: 7 */
            /* 0x0278 */ unsigned long VaSpaceDeleted : 1; /* bit position: 10 */
            /* 0x0278 */ unsigned long ReservedFlags : 21; /* bit position: 11 */
        }; /* bitfield */
        /* 0x0278 */ volatile long ProcessFlags;
    }; /* size: 0x0004 */
    /* 0x027c */ unsigned long ActiveGroupsMask;
    /* 0x0280 */ char BasePriority;
    /* 0x0281 */ char QuantumReset;
    /* 0x0282 */ char Visited;
    /* 0x0283 */ union _KEXECUTE_OPTIONS Flags;
    /* 0x0284 */ unsigned short ThreadSeed[20];
    /* 0x02ac */ unsigned short ThreadSeedPadding[12];
    /* 0x02c4 */ unsigned short IdealProcessor[20];
    /* 0x02ec */ unsigned short IdealProcessorPadding[12];
    /* 0x0304 */ unsigned short IdealNode[20];
    /* 0x032c */ unsigned short IdealNodePadding[12];
    /* 0x0344 */ unsigned short IdealGlobalNode;
    /* 0x0346 */ unsigned short Spare1;
    /* 0x0348 */ volatile union _KSTACK_COUNT StackCount;
    /* 0x034c */ long Padding_0;
    /* 0x0350 */ struct _LIST_ENTRY ProcessListEntry;
    /* 0x0360 */ unsigned __int64 CycleTime;
    /* 0x0368 */ unsigned __int64 ContextSwitches;
    /* 0x0370 */ struct _KSCHEDULING_GROUP* SchedulingGroup;
    /* 0x0378 */ unsigned long FreezeCount;
    /* 0x037c */ unsigned long KernelTime;
    /* 0x0380 */ unsigned long UserTime;
    /* 0x0384 */ unsigned long ReadyTime;
    /* 0x0388 */ unsigned __int64 UserDirectoryTableBase;
    /* 0x0390 */ unsigned char AddressPolicy;
    /* 0x0391 */ unsigned char Spare2[71];
    /* 0x03d8 */ void* InstrumentationCallback;
    union
    {
        union
        {
            /* 0x03e0 */ unsigned __int64 SecureHandle;
            struct
            {
                struct /* bitfield */
                {
                    /* 0x03e0 */ unsigned __int64 SecureProcess : 1; /* bit position: 0 */
                    /* 0x03e0 */ unsigned __int64 Unused : 1; /* bit position: 1 */
                }; /* bitfield */
            } /* size: 0x0008 */ Flags;
        }; /* size: 0x0008 */
    } /* size: 0x0008 */ SecureState;
    /* 0x03e8 */ unsigned __int64 KernelWaitTime;
    /* 0x03f0 */ unsigned __int64 UserWaitTime;
    /* 0x03f8 */ unsigned __int64 EndPadding[8];
} KPROCESS, * PKPROCESS; /* size: 0x0438 */

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    /* 0x0000 */ struct _OBJECT_NAME_INFORMATION* ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO; /* size: 0x0008 */

typedef struct _ALPC_PROCESS_CONTEXT
{
    /* 0x0000 */ struct _EX_PUSH_LOCK Lock;
    /* 0x0008 */ struct _LIST_ENTRY ViewListHead;
    /* 0x0018 */ volatile unsigned __int64 PagedPoolQuotaCache;
} ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT; /* size: 0x0020 */

typedef struct _MMSUPPORT_FLAGS
{
    union
    {
        struct
        {
            struct /* bitfield */
            {
                /* 0x0000 */ unsigned char WorkingSetType : 3; /* bit position: 0 */
                /* 0x0000 */ unsigned char Reserved0 : 3; /* bit position: 3 */
                /* 0x0000 */ unsigned char MaximumWorkingSetHard : 1; /* bit position: 6 */
                /* 0x0000 */ unsigned char MinimumWorkingSetHard : 1; /* bit position: 7 */
            }; /* bitfield */
            struct /* bitfield */
            {
                /* 0x0001 */ unsigned char SessionMaster : 1; /* bit position: 0 */
                /* 0x0001 */ unsigned char TrimmerState : 2; /* bit position: 1 */
                /* 0x0001 */ unsigned char Reserved : 1; /* bit position: 3 */
                /* 0x0001 */ unsigned char PageStealers : 4; /* bit position: 4 */
            }; /* bitfield */
        }; /* size: 0x0002 */
        /* 0x0000 */ unsigned short u1;
    }; /* size: 0x0002 */
    /* 0x0002 */ unsigned char MemoryPriority;
    union
    {
        struct /* bitfield */
        {
            /* 0x0003 */ unsigned char WsleDeleted : 1; /* bit position: 0 */
            /* 0x0003 */ unsigned char SvmEnabled : 1; /* bit position: 1 */
            /* 0x0003 */ unsigned char ForceAge : 1; /* bit position: 2 */
            /* 0x0003 */ unsigned char ForceTrim : 1; /* bit position: 3 */
            /* 0x0003 */ unsigned char NewMaximum : 1; /* bit position: 4 */
            /* 0x0003 */ unsigned char CommitReleaseState : 2; /* bit position: 5 */
        }; /* bitfield */
        /* 0x0003 */ unsigned char u2;
    }; /* size: 0x0001 */
} MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS; /* size: 0x0004 */

typedef struct _MMSUPPORT_INSTANCE
{
    /* 0x0000 */ unsigned long NextPageColor;
    /* 0x0004 */ unsigned long PageFaultCount;
    /* 0x0008 */ unsigned __int64 TrimmedPageCount;
    /* 0x0010 */ struct _MMWSL_INSTANCE* VmWorkingSetList;
    /* 0x0018 */ struct _LIST_ENTRY WorkingSetExpansionLinks;
    /* 0x0028 */ unsigned __int64 AgeDistribution[8];
    /* 0x0068 */ struct _KGATE* ExitOutswapGate;
    /* 0x0070 */ unsigned __int64 MinimumWorkingSetSize;
    /* 0x0078 */ unsigned __int64 WorkingSetLeafSize;
    /* 0x0080 */ unsigned __int64 WorkingSetLeafPrivateSize;
    /* 0x0088 */ unsigned __int64 WorkingSetSize;
    /* 0x0090 */ unsigned __int64 WorkingSetPrivateSize;
    /* 0x0098 */ unsigned __int64 MaximumWorkingSetSize;
    /* 0x00a0 */ unsigned __int64 PeakWorkingSetSize;
    /* 0x00a8 */ unsigned long HardFaultCount;
    /* 0x00ac */ unsigned short LastTrimStamp;
    /* 0x00ae */ unsigned short PartitionId;
    /* 0x00b0 */ unsigned __int64 SelfmapLock;
    /* 0x00b8 */ struct _MMSUPPORT_FLAGS Flags;
    /* 0x00bc */ long __PADDING__[1];
} MMSUPPORT_INSTANCE, * PMMSUPPORT_INSTANCE; /* size: 0x00c0 */

typedef struct _MMSUPPORT_SHARED
{
    /* 0x0000 */ volatile long WorkingSetLock;
    /* 0x0004 */ long GoodCitizenWaiting;
    /* 0x0008 */ unsigned __int64 ReleasedCommitDebt;
    /* 0x0010 */ unsigned __int64 ResetPagesRepurposedCount;
    /* 0x0018 */ void* WsSwapSupport;
    /* 0x0020 */ void* CommitReleaseContext;
    /* 0x0028 */ void* AccessLog;
    /* 0x0030 */ volatile unsigned __int64 ChargedWslePages;
    /* 0x0038 */ unsigned __int64 ActualWslePages;
    /* 0x0040 */ unsigned __int64 WorkingSetCoreLock;
    /* 0x0048 */ void* ShadowMapping;
    /* 0x0050 */ long __PADDING__[12];
} MMSUPPORT_SHARED, * PMMSUPPORT_SHARED; /* size: 0x0080 */

typedef struct _MMSUPPORT_FULL
{
    /* 0x0000 */ struct _MMSUPPORT_INSTANCE Instance;
    /* 0x00c0 */ struct _MMSUPPORT_SHARED Shared;
} MMSUPPORT_FULL, * PMMSUPPORT_FULL; /* size: 0x0140 */

typedef struct _EX_FAST_REF
{
    union
    {
        /* 0x0000 */ void* Object;
        /* 0x0000 */ unsigned __int64 RefCnt : 4; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 Value;
    }; /* size: 0x0008 */
} EX_FAST_REF, * PEX_FAST_REF; /* size: 0x0008 */

typedef struct _RTL_AVL_TREE
{
    /* 0x0000 */ struct _RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, * PRTL_AVL_TREE; /* size: 0x0008 */

typedef struct _PS_PROTECTION
{
    union
    {
        /* 0x0000 */ unsigned char Level;
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned char Type : 3; /* bit position: 0 */
            /* 0x0000 */ unsigned char Audit : 1; /* bit position: 3 */
            /* 0x0000 */ unsigned char Signer : 4; /* bit position: 4 */
        }; /* bitfield */
    }; /* size: 0x0001 */
} PS_PROTECTION, * PPS_PROTECTION; /* size: 0x0001 */

typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    union
    {
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned __int64 DelayMs : 30; /* bit position: 0 */
            /* 0x0000 */ unsigned __int64 CoalescingWindowMs : 30; /* bit position: 30 */
            /* 0x0000 */ unsigned __int64 Reserved : 1; /* bit position: 60 */
            /* 0x0000 */ unsigned __int64 NewTimerWheel : 1; /* bit position: 61 */
            /* 0x0000 */ unsigned __int64 Retry : 1; /* bit position: 62 */
            /* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 63 */
        }; /* bitfield */
        /* 0x0000 */ unsigned __int64 All;
    }; /* size: 0x0008 */
} PS_INTERLOCKED_TIMER_DELAY_VALUES, * PPS_INTERLOCKED_TIMER_DELAY_VALUES; /* size: 0x0008 */

typedef struct _JOBOBJECT_WAKE_FILTER
{
    /* 0x0000 */ unsigned long HighEdgeFilter;
    /* 0x0004 */ unsigned long LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER; /* size: 0x0008 */

typedef struct _PS_PROCESS_WAKE_INFORMATION
{
    /* 0x0000 */ unsigned __int64 NotificationChannel;
    /* 0x0008 */ unsigned long WakeCounters[7];
    /* 0x0024 */ struct _JOBOBJECT_WAKE_FILTER WakeFilter;
    /* 0x002c */ unsigned long NoWakeCounter;
} PS_PROCESS_WAKE_INFORMATION, * PPS_PROCESS_WAKE_INFORMATION; /* size: 0x0030 */

typedef struct _EPROCESS
{
    /* 0x0000 */ struct _KPROCESS Pcb;
    /* 0x0438 */ struct _EX_PUSH_LOCK ProcessLock;
    /* 0x0440 */ void* UniqueProcessId;
    /* 0x0448 */ struct _LIST_ENTRY ActiveProcessLinks;
    /* 0x0458 */ struct _EX_RUNDOWN_REF RundownProtect;
    union
    {
        /* 0x0460 */ unsigned long Flags2;
        struct /* bitfield */
        {
            /* 0x0460 */ unsigned long JobNotReallyActive : 1; /* bit position: 0 */
            /* 0x0460 */ unsigned long AccountingFolded : 1; /* bit position: 1 */
            /* 0x0460 */ unsigned long NewProcessReported : 1; /* bit position: 2 */
            /* 0x0460 */ unsigned long ExitProcessReported : 1; /* bit position: 3 */
            /* 0x0460 */ unsigned long ReportCommitChanges : 1; /* bit position: 4 */
            /* 0x0460 */ unsigned long LastReportMemory : 1; /* bit position: 5 */
            /* 0x0460 */ unsigned long ForceWakeCharge : 1; /* bit position: 6 */
            /* 0x0460 */ unsigned long CrossSessionCreate : 1; /* bit position: 7 */
            /* 0x0460 */ unsigned long NeedsHandleRundown : 1; /* bit position: 8 */
            /* 0x0460 */ unsigned long RefTraceEnabled : 1; /* bit position: 9 */
            /* 0x0460 */ unsigned long PicoCreated : 1; /* bit position: 10 */
            /* 0x0460 */ unsigned long EmptyJobEvaluated : 1; /* bit position: 11 */
            /* 0x0460 */ unsigned long DefaultPagePriority : 3; /* bit position: 12 */
            /* 0x0460 */ unsigned long PrimaryTokenFrozen : 1; /* bit position: 15 */
            /* 0x0460 */ unsigned long ProcessVerifierTarget : 1; /* bit position: 16 */
            /* 0x0460 */ unsigned long RestrictSetThreadContext : 1; /* bit position: 17 */
            /* 0x0460 */ unsigned long AffinityPermanent : 1; /* bit position: 18 */
            /* 0x0460 */ unsigned long AffinityUpdateEnable : 1; /* bit position: 19 */
            /* 0x0460 */ unsigned long PropagateNode : 1; /* bit position: 20 */
            /* 0x0460 */ unsigned long ExplicitAffinity : 1; /* bit position: 21 */
            /* 0x0460 */ unsigned long ProcessExecutionState : 2; /* bit position: 22 */
            /* 0x0460 */ unsigned long EnableReadVmLogging : 1; /* bit position: 24 */
            /* 0x0460 */ unsigned long EnableWriteVmLogging : 1; /* bit position: 25 */
            /* 0x0460 */ unsigned long FatalAccessTerminationRequested : 1; /* bit position: 26 */
            /* 0x0460 */ unsigned long DisableSystemAllowedCpuSet : 1; /* bit position: 27 */
            /* 0x0460 */ unsigned long ProcessStateChangeRequest : 2; /* bit position: 28 */
            /* 0x0460 */ unsigned long ProcessStateChangeInProgress : 1; /* bit position: 30 */
            /* 0x0460 */ unsigned long InPrivate : 1; /* bit position: 31 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    union
    {
        /* 0x0464 */ unsigned long Flags;
        struct /* bitfield */
        {
            /* 0x0464 */ unsigned long CreateReported : 1; /* bit position: 0 */
            /* 0x0464 */ unsigned long NoDebugInherit : 1; /* bit position: 1 */
            /* 0x0464 */ unsigned long ProcessExiting : 1; /* bit position: 2 */
            /* 0x0464 */ unsigned long ProcessDelete : 1; /* bit position: 3 */
            /* 0x0464 */ unsigned long ManageExecutableMemoryWrites : 1; /* bit position: 4 */
            /* 0x0464 */ unsigned long VmDeleted : 1; /* bit position: 5 */
            /* 0x0464 */ unsigned long OutswapEnabled : 1; /* bit position: 6 */
            /* 0x0464 */ unsigned long Outswapped : 1; /* bit position: 7 */
            /* 0x0464 */ unsigned long FailFastOnCommitFail : 1; /* bit position: 8 */
            /* 0x0464 */ unsigned long Wow64VaSpace4Gb : 1; /* bit position: 9 */
            /* 0x0464 */ unsigned long AddressSpaceInitialized : 2; /* bit position: 10 */
            /* 0x0464 */ unsigned long SetTimerResolution : 1; /* bit position: 12 */
            /* 0x0464 */ unsigned long BreakOnTermination : 1; /* bit position: 13 */
            /* 0x0464 */ unsigned long DeprioritizeViews : 1; /* bit position: 14 */
            /* 0x0464 */ unsigned long WriteWatch : 1; /* bit position: 15 */
            /* 0x0464 */ unsigned long ProcessInSession : 1; /* bit position: 16 */
            /* 0x0464 */ unsigned long OverrideAddressSpace : 1; /* bit position: 17 */
            /* 0x0464 */ unsigned long HasAddressSpace : 1; /* bit position: 18 */
            /* 0x0464 */ unsigned long LaunchPrefetched : 1; /* bit position: 19 */
            /* 0x0464 */ unsigned long Background : 1; /* bit position: 20 */
            /* 0x0464 */ unsigned long VmTopDown : 1; /* bit position: 21 */
            /* 0x0464 */ unsigned long ImageNotifyDone : 1; /* bit position: 22 */
            /* 0x0464 */ unsigned long PdeUpdateNeeded : 1; /* bit position: 23 */
            /* 0x0464 */ unsigned long VdmAllowed : 1; /* bit position: 24 */
            /* 0x0464 */ unsigned long ProcessRundown : 1; /* bit position: 25 */
            /* 0x0464 */ unsigned long ProcessInserted : 1; /* bit position: 26 */
            /* 0x0464 */ unsigned long DefaultIoPriority : 3; /* bit position: 27 */
            /* 0x0464 */ unsigned long ProcessSelfDelete : 1; /* bit position: 30 */
            /* 0x0464 */ unsigned long SetTimerResolutionLink : 1; /* bit position: 31 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x0468 */ union _LARGE_INTEGER CreateTime;
    /* 0x0470 */ unsigned __int64 ProcessQuotaUsage[2];
    /* 0x0480 */ unsigned __int64 ProcessQuotaPeak[2];
    /* 0x0490 */ unsigned __int64 PeakVirtualSize;
    /* 0x0498 */ unsigned __int64 VirtualSize;
    /* 0x04a0 */ struct _LIST_ENTRY SessionProcessLinks;
    union
    {
        /* 0x04b0 */ void* ExceptionPortData;
        /* 0x04b0 */ unsigned __int64 ExceptionPortValue;
        /* 0x04b0 */ unsigned __int64 ExceptionPortState : 3; /* bit position: 0 */
    }; /* size: 0x0008 */
    /* 0x04b8 */ struct _EX_FAST_REF Token;
    /* 0x04c0 */ unsigned __int64 MmReserved;
    /* 0x04c8 */ struct _EX_PUSH_LOCK AddressCreationLock;
    /* 0x04d0 */ struct _EX_PUSH_LOCK PageTableCommitmentLock;
    /* 0x04d8 */ struct _ETHREAD* RotateInProgress;
    /* 0x04e0 */ struct _ETHREAD* ForkInProgress;
    /* 0x04e8 */ struct _EJOB* volatile CommitChargeJob;
    /* 0x04f0 */ struct _RTL_AVL_TREE CloneRoot;
    /* 0x04f8 */ volatile unsigned __int64 NumberOfPrivatePages;
    /* 0x0500 */ volatile unsigned __int64 NumberOfLockedPages;
    /* 0x0508 */ void* Win32Process;
    /* 0x0510 */ struct _EJOB* volatile Job;
    /* 0x0518 */ void* SectionObject;
    /* 0x0520 */ void* SectionBaseAddress;
    /* 0x0528 */ unsigned long Cookie;
    /* 0x052c */ long Padding_1;
    /* 0x0530 */ struct _PAGEFAULT_HISTORY* WorkingSetWatch;
    /* 0x0538 */ void* Win32WindowStation;
    /* 0x0540 */ void* InheritedFromUniqueProcessId;
    /* 0x0548 */ volatile unsigned __int64 OwnerProcessId;
    /* 0x0550 */ struct _PEB* Peb;
    /* 0x0558 */ struct _MM_SESSION_SPACE* Session;
    /* 0x0560 */ void* Spare1;
    /* 0x0568 */ struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
    /* 0x0570 */ struct _HANDLE_TABLE* ObjectTable;
    /* 0x0578 */ void* DebugPort;
    /* 0x0580 */ struct _EWOW64PROCESS* WoW64Process;
    /* 0x0588 */ void* DeviceMap;
    /* 0x0590 */ void* EtwDataSource;
    /* 0x0598 */ unsigned __int64 PageDirectoryPte;
    /* 0x05a0 */ struct _FILE_OBJECT* ImageFilePointer;
    /* 0x05a8 */ unsigned char ImageFileName[15];
    /* 0x05b7 */ unsigned char PriorityClass;
    /* 0x05b8 */ void* SecurityPort;
    /* 0x05c0 */ struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
    /* 0x05c8 */ struct _LIST_ENTRY JobLinks;
    /* 0x05d8 */ void* HighestUserAddress;
    /* 0x05e0 */ struct _LIST_ENTRY ThreadListHead;
    /* 0x05f0 */ volatile unsigned long ActiveThreads;
    /* 0x05f4 */ unsigned long ImagePathHash;
    /* 0x05f8 */ unsigned long DefaultHardErrorProcessing;
    /* 0x05fc */ long LastThreadExitStatus;
    /* 0x0600 */ struct _EX_FAST_REF PrefetchTrace;
    /* 0x0608 */ void* LockedPagesList;
    /* 0x0610 */ union _LARGE_INTEGER ReadOperationCount;
    /* 0x0618 */ union _LARGE_INTEGER WriteOperationCount;
    /* 0x0620 */ union _LARGE_INTEGER OtherOperationCount;
    /* 0x0628 */ union _LARGE_INTEGER ReadTransferCount;
    /* 0x0630 */ union _LARGE_INTEGER WriteTransferCount;
    /* 0x0638 */ union _LARGE_INTEGER OtherTransferCount;
    /* 0x0640 */ unsigned __int64 CommitChargeLimit;
    /* 0x0648 */ volatile unsigned __int64 CommitCharge;
    /* 0x0650 */ volatile unsigned __int64 CommitChargePeak;
    /* 0x0658 */ long Padding_2[10];
    /* 0x0680 */ struct _MMSUPPORT_FULL Vm;
    /* 0x07c0 */ struct _LIST_ENTRY MmProcessLinks;
    /* 0x07d0 */ unsigned long ModifiedPageCount;
    /* 0x07d4 */ long ExitStatus;
    /* 0x07d8 */ struct _RTL_AVL_TREE VadRoot;
    /* 0x07e0 */ void* VadHint;
    /* 0x07e8 */ unsigned __int64 VadCount;
    /* 0x07f0 */ volatile unsigned __int64 VadPhysicalPages;
    /* 0x07f8 */ unsigned __int64 VadPhysicalPagesLimit;
    /* 0x0800 */ struct _ALPC_PROCESS_CONTEXT AlpcContext;
    /* 0x0820 */ struct _LIST_ENTRY TimerResolutionLink;
    /* 0x0830 */ struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
    /* 0x0838 */ unsigned long RequestedTimerResolution;
    /* 0x083c */ unsigned long SmallestTimerResolution;
    /* 0x0840 */ union _LARGE_INTEGER ExitTime;
    /* 0x0848 */ struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;
    /* 0x0850 */ struct _EX_PUSH_LOCK InvertedFunctionTableLock;
    /* 0x0858 */ unsigned long ActiveThreadsHighWatermark;
    /* 0x085c */ unsigned long LargePrivateVadCount;
    /* 0x0860 */ struct _EX_PUSH_LOCK ThreadListLock;
    /* 0x0868 */ void* WnfContext;
    /* 0x0870 */ struct _EJOB* ServerSilo;
    /* 0x0878 */ unsigned char SignatureLevel;
    /* 0x0879 */ unsigned char SectionSignatureLevel;
    /* 0x087a */ struct _PS_PROTECTION Protection;
    struct /* bitfield */
    {
        /* 0x087b */ unsigned char HangCount : 3; /* bit position: 0 */
        /* 0x087b */ unsigned char GhostCount : 3; /* bit position: 3 */
        /* 0x087b */ unsigned char PrefilterException : 1; /* bit position: 6 */
    }; /* bitfield */
    union
    {
        /* 0x087c */ unsigned long Flags3;
        struct /* bitfield */
        {
            /* 0x087c */ unsigned long Minimal : 1; /* bit position: 0 */
            /* 0x087c */ unsigned long ReplacingPageRoot : 1; /* bit position: 1 */
            /* 0x087c */ unsigned long Crashed : 1; /* bit position: 2 */
            /* 0x087c */ unsigned long JobVadsAreTracked : 1; /* bit position: 3 */
            /* 0x087c */ unsigned long VadTrackingDisabled : 1; /* bit position: 4 */
            /* 0x087c */ unsigned long AuxiliaryProcess : 1; /* bit position: 5 */
            /* 0x087c */ unsigned long SubsystemProcess : 1; /* bit position: 6 */
            /* 0x087c */ unsigned long IndirectCpuSets : 1; /* bit position: 7 */
            /* 0x087c */ unsigned long RelinquishedCommit : 1; /* bit position: 8 */
            /* 0x087c */ unsigned long HighGraphicsPriority : 1; /* bit position: 9 */
            /* 0x087c */ unsigned long CommitFailLogged : 1; /* bit position: 10 */
            /* 0x087c */ unsigned long ReserveFailLogged : 1; /* bit position: 11 */
            /* 0x087c */ unsigned long SystemProcess : 1; /* bit position: 12 */
            /* 0x087c */ unsigned long HideImageBaseAddresses : 1; /* bit position: 13 */
            /* 0x087c */ unsigned long AddressPolicyFrozen : 1; /* bit position: 14 */
            /* 0x087c */ unsigned long ProcessFirstResume : 1; /* bit position: 15 */
            /* 0x087c */ unsigned long ForegroundExternal : 1; /* bit position: 16 */
            /* 0x087c */ unsigned long ForegroundSystem : 1; /* bit position: 17 */
            /* 0x087c */ unsigned long HighMemoryPriority : 1; /* bit position: 18 */
            /* 0x087c */ unsigned long EnableProcessSuspendResumeLogging : 1; /* bit position: 19 */
            /* 0x087c */ unsigned long EnableThreadSuspendResumeLogging : 1; /* bit position: 20 */
            /* 0x087c */ unsigned long SecurityDomainChanged : 1; /* bit position: 21 */
            /* 0x087c */ unsigned long SecurityFreezeComplete : 1; /* bit position: 22 */
            /* 0x087c */ unsigned long VmProcessorHost : 1; /* bit position: 23 */
            /* 0x087c */ unsigned long VmProcessorHostTransition : 1; /* bit position: 24 */
            /* 0x087c */ unsigned long AltSyscall : 1; /* bit position: 25 */
            /* 0x087c */ unsigned long TimerResolutionIgnore : 1; /* bit position: 26 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x0880 */ long DeviceAsid;
    /* 0x0884 */ long Padding_3;
    /* 0x0888 */ void* SvmData;
    /* 0x0890 */ struct _EX_PUSH_LOCK SvmProcessLock;
    /* 0x0898 */ unsigned __int64 SvmLock;
    /* 0x08a0 */ struct _LIST_ENTRY SvmProcessDeviceListHead;
    /* 0x08b0 */ unsigned __int64 LastFreezeInterruptTime;
    /* 0x08b8 */ struct _PROCESS_DISK_COUNTERS* DiskCounters;
    /* 0x08c0 */ void* PicoContext;
    /* 0x08c8 */ void* EnclaveTable;
    /* 0x08d0 */ unsigned __int64 EnclaveNumber;
    /* 0x08d8 */ struct _EX_PUSH_LOCK EnclaveLock;
    /* 0x08e0 */ unsigned long HighPriorityFaultsAllowed;
    /* 0x08e4 */ long Padding_4;
    /* 0x08e8 */ struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;
    /* 0x08f0 */ void* VmContext;
    /* 0x08f8 */ unsigned __int64 SequenceNumber;
    /* 0x0900 */ unsigned __int64 CreateInterruptTime;
    /* 0x0908 */ unsigned __int64 CreateUnbiasedInterruptTime;
    /* 0x0910 */ unsigned __int64 TotalUnbiasedFrozenTime;
    /* 0x0918 */ unsigned __int64 LastAppStateUpdateTime;
    struct /* bitfield */
    {
        /* 0x0920 */ unsigned __int64 LastAppStateUptime : 61; /* bit position: 0 */
        /* 0x0920 */ unsigned __int64 LastAppState : 3; /* bit position: 61 */
    }; /* bitfield */
    /* 0x0928 */ volatile unsigned __int64 SharedCommitCharge;
    /* 0x0930 */ struct _EX_PUSH_LOCK SharedCommitLock;
    /* 0x0938 */ struct _LIST_ENTRY SharedCommitLinks;
    union
    {
        struct
        {
            /* 0x0948 */ unsigned __int64 AllowedCpuSets;
            /* 0x0950 */ unsigned __int64 DefaultCpuSets;
        }; /* size: 0x0010 */
        struct
        {
            /* 0x0948 */ unsigned __int64* AllowedCpuSetsIndirect;
            /* 0x0950 */ unsigned __int64* DefaultCpuSetsIndirect;
        }; /* size: 0x0010 */
    }; /* size: 0x0010 */
    /* 0x0958 */ void* DiskIoAttribution;
    /* 0x0960 */ void* DxgProcess;
    /* 0x0968 */ unsigned long Win32KFilterSet;
    /* 0x096c */ long Padding_5;
    /* 0x0970 */ volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;
    /* 0x0978 */ volatile unsigned long KTimerSets;
    /* 0x097c */ volatile unsigned long KTimer2Sets;
    /* 0x0980 */ volatile unsigned long ThreadTimerSets;
    /* 0x0984 */ long Padding_6;
    /* 0x0988 */ unsigned __int64 VirtualTimerListLock;
    /* 0x0990 */ struct _LIST_ENTRY VirtualTimerListHead;
    union
    {
        /* 0x09a0 */ struct _WNF_STATE_NAME WakeChannel;
        /* 0x09a0 */ struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;
    }; /* size: 0x0030 */
    union
    {
        /* 0x09d0 */ unsigned long MitigationFlags;
        struct
        {
            struct /* bitfield */
            {
                /* 0x09d0 */ unsigned long ControlFlowGuardEnabled : 1; /* bit position: 0 */
                /* 0x09d0 */ unsigned long ControlFlowGuardExportSuppressionEnabled : 1; /* bit position: 1 */
                /* 0x09d0 */ unsigned long ControlFlowGuardStrict : 1; /* bit position: 2 */
                /* 0x09d0 */ unsigned long DisallowStrippedImages : 1; /* bit position: 3 */
                /* 0x09d0 */ unsigned long ForceRelocateImages : 1; /* bit position: 4 */
                /* 0x09d0 */ unsigned long HighEntropyASLREnabled : 1; /* bit position: 5 */
                /* 0x09d0 */ unsigned long StackRandomizationDisabled : 1; /* bit position: 6 */
                /* 0x09d0 */ unsigned long ExtensionPointDisable : 1; /* bit position: 7 */
                /* 0x09d0 */ unsigned long DisableDynamicCode : 1; /* bit position: 8 */
                /* 0x09d0 */ unsigned long DisableDynamicCodeAllowOptOut : 1; /* bit position: 9 */
                /* 0x09d0 */ unsigned long DisableDynamicCodeAllowRemoteDowngrade : 1; /* bit position: 10 */
                /* 0x09d0 */ unsigned long AuditDisableDynamicCode : 1; /* bit position: 11 */
                /* 0x09d0 */ unsigned long DisallowWin32kSystemCalls : 1; /* bit position: 12 */
                /* 0x09d0 */ unsigned long AuditDisallowWin32kSystemCalls : 1; /* bit position: 13 */
                /* 0x09d0 */ unsigned long EnableFilteredWin32kAPIs : 1; /* bit position: 14 */
                /* 0x09d0 */ unsigned long AuditFilteredWin32kAPIs : 1; /* bit position: 15 */
                /* 0x09d0 */ unsigned long DisableNonSystemFonts : 1; /* bit position: 16 */
                /* 0x09d0 */ unsigned long AuditNonSystemFontLoading : 1; /* bit position: 17 */
                /* 0x09d0 */ unsigned long PreferSystem32Images : 1; /* bit position: 18 */
                /* 0x09d0 */ unsigned long ProhibitRemoteImageMap : 1; /* bit position: 19 */
                /* 0x09d0 */ unsigned long AuditProhibitRemoteImageMap : 1; /* bit position: 20 */
                /* 0x09d0 */ unsigned long ProhibitLowILImageMap : 1; /* bit position: 21 */
                /* 0x09d0 */ unsigned long AuditProhibitLowILImageMap : 1; /* bit position: 22 */
                /* 0x09d0 */ unsigned long SignatureMitigationOptIn : 1; /* bit position: 23 */
                /* 0x09d0 */ unsigned long AuditBlockNonMicrosoftBinaries : 1; /* bit position: 24 */
                /* 0x09d0 */ unsigned long AuditBlockNonMicrosoftBinariesAllowStore : 1; /* bit position: 25 */
                /* 0x09d0 */ unsigned long LoaderIntegrityContinuityEnabled : 1; /* bit position: 26 */
                /* 0x09d0 */ unsigned long AuditLoaderIntegrityContinuity : 1; /* bit position: 27 */
                /* 0x09d0 */ unsigned long EnableModuleTamperingProtection : 1; /* bit position: 28 */
                /* 0x09d0 */ unsigned long EnableModuleTamperingProtectionNoInherit : 1; /* bit position: 29 */
                /* 0x09d0 */ unsigned long RestrictIndirectBranchPrediction : 1; /* bit position: 30 */
                /* 0x09d0 */ unsigned long IsolateSecurityDomain : 1; /* bit position: 31 */
            }; /* bitfield */
        } /* size: 0x0004 */ MitigationFlagsValues;
    }; /* size: 0x0004 */
    union
    {
        /* 0x09d4 */ unsigned long MitigationFlags2;
        struct
        {
            struct /* bitfield */
            {
                /* 0x09d4 */ unsigned long EnableExportAddressFilter : 1; /* bit position: 0 */
                /* 0x09d4 */ unsigned long AuditExportAddressFilter : 1; /* bit position: 1 */
                /* 0x09d4 */ unsigned long EnableExportAddressFilterPlus : 1; /* bit position: 2 */
                /* 0x09d4 */ unsigned long AuditExportAddressFilterPlus : 1; /* bit position: 3 */
                /* 0x09d4 */ unsigned long EnableRopStackPivot : 1; /* bit position: 4 */
                /* 0x09d4 */ unsigned long AuditRopStackPivot : 1; /* bit position: 5 */
                /* 0x09d4 */ unsigned long EnableRopCallerCheck : 1; /* bit position: 6 */
                /* 0x09d4 */ unsigned long AuditRopCallerCheck : 1; /* bit position: 7 */
                /* 0x09d4 */ unsigned long EnableRopSimExec : 1; /* bit position: 8 */
                /* 0x09d4 */ unsigned long AuditRopSimExec : 1; /* bit position: 9 */
                /* 0x09d4 */ unsigned long EnableImportAddressFilter : 1; /* bit position: 10 */
                /* 0x09d4 */ unsigned long AuditImportAddressFilter : 1; /* bit position: 11 */
                /* 0x09d4 */ unsigned long DisablePageCombine : 1; /* bit position: 12 */
                /* 0x09d4 */ unsigned long SpeculativeStoreBypassDisable : 1; /* bit position: 13 */
                /* 0x09d4 */ unsigned long CetUserShadowStacks : 1; /* bit position: 14 */
                /* 0x09d4 */ unsigned long AuditCetUserShadowStacks : 1; /* bit position: 15 */
                /* 0x09d4 */ unsigned long AuditCetUserShadowStacksLogged : 1; /* bit position: 16 */
                /* 0x09d4 */ unsigned long UserCetSetContextIpValidation : 1; /* bit position: 17 */
                /* 0x09d4 */ unsigned long AuditUserCetSetContextIpValidation : 1; /* bit position: 18 */
                /* 0x09d4 */ unsigned long AuditUserCetSetContextIpValidationLogged : 1; /* bit position: 19 */
            }; /* bitfield */
        } /* size: 0x0004 */ MitigationFlags2Values;
    }; /* size: 0x0004 */
    /* 0x09d8 */ void* PartitionObject;
    /* 0x09e0 */ unsigned __int64 SecurityDomain;
    /* 0x09e8 */ unsigned __int64 ParentSecurityDomain;
    /* 0x09f0 */ void* CoverageSamplerContext;
    /* 0x09f8 */ void* MmHotPatchContext;
    /* 0x0a00 */ struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;
    /* 0x0a08 */ struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;
    /* 0x0a10 */ long __PADDING__[12];
} EPROCESS, *_PEPROCESS; /* size: 0x0a40 */

// ----------------------------------------------------------------------------------------------------- // --

typedef struct _LDR_DATA_TABLE_ENTRY
{
    /* 0x0000 */ struct _LIST_ENTRY InLoadOrderLinks;
    /* 0x0010 */ struct _LIST_ENTRY InMemoryOrderLinks;
    /* 0x0020 */ struct _LIST_ENTRY InInitializationOrderLinks;
    /* 0x0030 */ void* DllBase;
    /* 0x0038 */ void* EntryPoint;
    /* 0x0040 */ unsigned long SizeOfImage;
    /* 0x0044 */ long Padding_1;
    /* 0x0048 */ struct _UNICODE_STRING FullDllName;
    /* 0x0058 */ struct _UNICODE_STRING BaseDllName;
    union
    {
        /* 0x0068 */ unsigned char FlagGroup[4];
        /* 0x0068 */ unsigned long Flags;
        struct /* bitfield */
        {
            /* 0x0068 */ unsigned long PackagedBinary : 1; /* bit position: 0 */
            /* 0x0068 */ unsigned long MarkedForRemoval : 1; /* bit position: 1 */
            /* 0x0068 */ unsigned long ImageDll : 1; /* bit position: 2 */
            /* 0x0068 */ unsigned long LoadNotificationsSent : 1; /* bit position: 3 */
            /* 0x0068 */ unsigned long TelemetryEntryProcessed : 1; /* bit position: 4 */
            /* 0x0068 */ unsigned long ProcessStaticImport : 1; /* bit position: 5 */
            /* 0x0068 */ unsigned long InLegacyLists : 1; /* bit position: 6 */
            /* 0x0068 */ unsigned long InIndexes : 1; /* bit position: 7 */
            /* 0x0068 */ unsigned long ShimDll : 1; /* bit position: 8 */
            /* 0x0068 */ unsigned long InExceptionTable : 1; /* bit position: 9 */
            /* 0x0068 */ unsigned long ReservedFlags1 : 2; /* bit position: 10 */
            /* 0x0068 */ unsigned long LoadInProgress : 1; /* bit position: 12 */
            /* 0x0068 */ unsigned long LoadConfigProcessed : 1; /* bit position: 13 */
            /* 0x0068 */ unsigned long EntryProcessed : 1; /* bit position: 14 */
            /* 0x0068 */ unsigned long ProtectDelayLoad : 1; /* bit position: 15 */
            /* 0x0068 */ unsigned long ReservedFlags3 : 2; /* bit position: 16 */
            /* 0x0068 */ unsigned long DontCallForThreads : 1; /* bit position: 18 */
            /* 0x0068 */ unsigned long ProcessAttachCalled : 1; /* bit position: 19 */
            /* 0x0068 */ unsigned long ProcessAttachFailed : 1; /* bit position: 20 */
            /* 0x0068 */ unsigned long CorDeferredValidate : 1; /* bit position: 21 */
            /* 0x0068 */ unsigned long CorImage : 1; /* bit position: 22 */
            /* 0x0068 */ unsigned long DontRelocate : 1; /* bit position: 23 */
            /* 0x0068 */ unsigned long CorILOnly : 1; /* bit position: 24 */
            /* 0x0068 */ unsigned long ChpeImage : 1; /* bit position: 25 */
            /* 0x0068 */ unsigned long ReservedFlags5 : 2; /* bit position: 26 */
            /* 0x0068 */ unsigned long Redirected : 1; /* bit position: 28 */
            /* 0x0068 */ unsigned long ReservedFlags6 : 2; /* bit position: 29 */
            /* 0x0068 */ unsigned long CompatDatabaseProcessed : 1; /* bit position: 31 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x006c */ unsigned short ObsoleteLoadCount;
    /* 0x006e */ unsigned short TlsIndex;
    /* 0x0070 */ struct _LIST_ENTRY HashLinks;
    /* 0x0080 */ unsigned long TimeDateStamp;
    /* 0x0084 */ long Padding_2;
    /* 0x0088 */ struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    /* 0x0090 */ void* Lock;
    /* 0x0098 */ struct _LDR_DDAG_NODE* DdagNode;
    /* 0x00a0 */ struct _LIST_ENTRY NodeModuleLink;
    /* 0x00b0 */ struct _LDRP_LOAD_CONTEXT* LoadContext;
    /* 0x00b8 */ void* ParentDllBase;
    /* 0x00c0 */ void* SwitchBackContext;
    /* 0x00c8 */ struct _RTL_BALANCED_NODE BaseAddressIndexNode;
    /* 0x00e0 */ struct _RTL_BALANCED_NODE MappingInfoIndexNode;
    /* 0x00f8 */ unsigned __int64 OriginalBase;
    /* 0x0100 */ union _LARGE_INTEGER LoadTime;
    /* 0x0108 */ unsigned long BaseNameHashValue;
    /* 0x010c */ enum _LDR_DLL_LOAD_REASON LoadReason;
    /* 0x0110 */ unsigned long ImplicitPathOptions;
    /* 0x0114 */ unsigned long ReferenceCount;
    /* 0x0118 */ unsigned long DependentLoadFlags;
    /* 0x011c */ unsigned char SigningLevel;
    /* 0x011d */ char __PADDING__[3];
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY; /* size: 0x0120 */

// ----------------------------------------------------------------------------------------------------- // --

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
#define IMAGE_SIZEOF_SHORT_NAME              8
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16












typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern "C" PVOID FltGetRoutineAddress(PCSTR FltMgrRoutineName);
extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemInformationClassMin = 0,
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemNotImplemented1 = 4,
    SystemProcessInformation = 5,
    SystemProcessesAndThreadsInformation = 5,
    SystemCallCountInfoInformation = 6,
    SystemCallCounts = 6,
    SystemDeviceInformation = 7,
    SystemConfigurationInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemProcessorTimes = 8,
    SystemFlagsInformation = 9,
    SystemGlobalFlag = 9,
    SystemCallTimeInformation = 10,
    SystemNotImplemented2 = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemLockInformation = 12,
    SystemStackTraceInformation = 13,
    SystemNotImplemented3 = 13,
    SystemPagedPoolInformation = 14,
    SystemNotImplemented4 = 14,
    SystemNonPagedPoolInformation = 15,
    SystemNotImplemented5 = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemPagefileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemInstructionEmulationCounts = 19,
    SystemVdmBopInformation = 20,
    SystemInvalidInfoClass1 = 20,
    SystemFileCacheInformation = 21,
    SystemCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemProcessorStatistics = 23,
    SystemDpcBehaviourInformation = 24,
    SystemDpcInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemNotImplemented6 = 25,
    SystemLoadImage = 26,
    SystemUnloadImage = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemTimeAdjustment = 28,
    SystemSummaryMemoryInformation = 29,
    SystemNotImplemented7 = 29,
    SystemNextEventIdInformation = 30,
    SystemNotImplemented8 = 30,
    SystemEventIdsInformation = 31,
    SystemNotImplemented9 = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemLoadAndCallImage = 38,
    SystemPrioritySeparation = 39,
    SystemPlugPlayBusInformation = 40,
    SystemNotImplemented10 = 40,
    SystemDockInformation = 41,
    SystemNotImplemented11 = 41,
    SystemInvalidInfoClass2 = 42,
    SystemProcessorSpeedInformation = 43,
    SystemInvalidInfoClass3 = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemSetTimeSlipEvent = 46,
    SystemCreateSession = 47,
    SystemDeleteSession = 48,
    SystemInvalidInfoClass4 = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemAddVerifier = 52,
    SystemSessionProcessesInformation = 53,
    SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;





typedef struct _POOL_TRACKER_BIG_PAGES
{
    volatile ULONGLONG Va;                                                  //0x0
    ULONG Key;                                                              //0x8
    ULONG Pattern : 8;                                                        //0xc
    ULONG PoolType : 12;                                                      //0xc
    ULONG SlushSize : 12;                                                     //0xc
    ULONGLONG NumberOfBytes;                                                //0x10
}POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;



typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, * PPEB;

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
    );

typedef VOID KKERNEL_ROUTINE(
    _In_ PRKAPC Apc,
    _Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_opt_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

typedef struct
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    char WaitRegister;                                                      //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG UmsDirectedSwitchEnable : 1;                                //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG UmsPerformingSyscall : 1;                                   //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetShadowStack : 1;                                         //0x74
            ULONG Reserved : 11;                                              //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG BamQosLevel : 2;                                            //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG ThreadFlagsSpare : 1;                                       //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
            struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
        };
    };
    VOID* Spare21;                                                          //0x200
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    union
    {
        struct _GROUP_AFFINITY UserAffinity;                                //0x228
        struct
        {
            UCHAR UserAffinityFill[10];                                     //0x228
            CHAR PreviousMode;                                              //0x232
            CHAR BasePriority;                                              //0x233
            union
            {
                CHAR PriorityDecrement;                                     //0x234
                struct
                {
                    UCHAR ForegroundBoost : 4;                                //0x234
                    UCHAR UnusualBoost : 4;                                   //0x234
                };
            };
            UCHAR Preempted;                                                //0x235
            UCHAR AdjustReason;                                             //0x236
            CHAR AdjustIncrement;                                           //0x237
        };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
        struct _GROUP_AFFINITY Affinity;                                    //0x240
        struct
        {
            UCHAR AffinityFill[10];                                         //0x240
            UCHAR ApcStateIndex;                                            //0x24a
            UCHAR WaitBlockCount;                                           //0x24b
            ULONG IdealProcessor;                                           //0x24c
        };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill0[1];                                     //0x288
            UCHAR ResourceIndex;                                            //0x289
        };
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    char LockEntries[0x240];                                                //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x560
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x568
    UCHAR PriorityFloorCounts[16];                                          //0x570
    ULONG PriorityFloorSummary;                                             //0x580
    volatile LONG AbCompletedIoBoostCount;                                  //0x584
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x588
    volatile SHORT KeReferenceCount;                                        //0x58c
    UCHAR AbOrphanedEntrySummary;                                           //0x58e
    UCHAR AbOwnedEntryCount;                                                //0x58f
    ULONG ForegroundLossTime;                                               //0x590
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x598
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x598
            ULONGLONG InGlobalForegroundList;                               //0x5a0
        };
    };
    LONGLONG ReadOperationCount;                                            //0x5a8
    LONGLONG WriteOperationCount;                                           //0x5b0
    LONGLONG OtherOperationCount;                                           //0x5b8
    LONGLONG ReadTransferCount;                                             //0x5c0
    LONGLONG WriteTransferCount;                                            //0x5c8
    LONGLONG OtherTransferCount;                                            //0x5d0
    struct _KSCB* QueuedScb;                                                //0x5d8
    volatile ULONG ThreadTimerDelay;                                        //0x5e0
    union
    {
        volatile LONG ThreadFlags2;                                         //0x5e4
        struct
        {
            ULONG PpmPolicy : 2;                                              //0x5e4
            ULONG ThreadFlags2Reserved : 30;                                  //0x5e4
        };
    };
    VOID* SchedulerAssist;                                                  //0x5e8
} KThread;

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(_In_ PRKAPC Apc);

typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        PVOID Object;
        ULONG ObAttributes;
        ULONG_PTR Value;
    };
    union
    {
        ACCESS_MASK GrantedAccess;
        LONG NextFreeTableEntry;
    };
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE HANDLE_TABLE, * PHANDLE_TABLE;

typedef BOOLEAN(NTAPI* PEX_ENUM_HANDLE_CALLBACK)(
    __in PHANDLE_TABLE HandleTable,
    __inout PHANDLE_TABLE_ENTRY HandleTableEntry,
    __in HANDLE Handle,
    __in PVOID Context
    );

extern "C" BOOLEAN ExEnumHandleTable(
    IN PHANDLE_TABLE HandleTable,
    IN PEX_ENUM_HANDLE_CALLBACK EnumHandleProcedure,
    IN PVOID EnumParameter,
    OUT PHANDLE Handle
);

extern "C" NTSTATUS MmUnmapViewOfSection(PEPROCESS Process, PVOID BaseAddress);