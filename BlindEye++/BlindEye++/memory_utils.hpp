#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntddk.h>
#include <windef.h>
#include <cstdint>
#include <ntimage.h>
#include <cstdint>
#include <cstddef>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <handleapi.h>
#include <winioctl.h>

#include "nt_defines.hpp"




typedef unsigned long long QWORD;

static UINT64 _be_pre_ob_callback_cave = 0;
static POB_PRE_OPERATION_CALLBACK _be_original_ob_callback = 0;
static BOOLEAN LAST_Hooked_drv_called = false;
static INT call_counter = 0;
const WCHAR driver_name[] = L"iorate.sys";
const CHAR driver_name_c[] = "iorate.sys";
static QWORD be_module = NULL;
static QWORD orig_AddressMmGetSystemRoutineAddress = NULL;
static QWORD orig_MmGetSystemRoutineAddress = NULL;
static DWORD ExAllocatePool_Report_Counter = 1000;
static DWORD openfile_battleye_counter = 0;
static BOOLEAN Init_Completed = false;

#define DEBUGPRINT

#ifndef DEBUGPRINT
ULONG DbgPrintEx(_In_ ULONG ComponentId,_In_ ULONG Level,_In_z_ _Printf_format_string_ PCSTR Format,...)
{
    return 0;
}

ULONG DbgPrint(PCSTR Format,...)
{
    return 0;
}
#endif


//define credits: learn_more
#define INRANGE(x,a,b)  (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))



static QWORD find_pattern_nt(_In_ CONST CHAR* sig, _In_ QWORD start, _In_ QWORD size)
{
	QWORD match = 0;
	const char* pat = sig;

	for (QWORD cur = start; cur < (start + size); ++cur)
	{
        if (MmIsAddressValid((PVOID)cur)) // Check if address is valid to prevent BSODs
        {
            if (!*pat) return match;

            else if (*(BYTE*)pat == '\?' || *(BYTE*)cur == getByte(pat))
            {
                if (!match) match = cur;

                if (!pat[2]) return match;

                else if (*(WORD*)pat == '\?\?' || *(BYTE*)pat != '\?') pat += 3;
                else pat += 2;
            }

            else
            {
                pat = sig;
                match = 0;
            }
        }
	}

	return 0;
}

//Checks if operand is a return
static BOOLEAN is_retop(_In_ BYTE op)
{
	return op == 0xC2 ||   // RETN + POP
		op == 0xC3 ||      // RETN
		op == 0xCA ||      // RETF + POP
		op == 0xCB;        // RETF
}

/*
	Finds a suitable length code cave inside the .text section of the given module
	A valid code cave is a sequence of CC bytes prefixed by a return statement
*/
static QWORD find_codecave(_In_ VOID* module, _In_ INT length, _In_opt_ QWORD begin)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
	
	QWORD start = 0, size = 0;

	QWORD header_offset = (QWORD)IMAGE_FIRST_SECTION(nt_headers);

    //Iterate module by sections
	for (INT x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
	{
		IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

		if (strcmp((CHAR*)header->Name, ".text") == 0) //Check if current section is in .text
		{
			start = (QWORD)module + header->PointerToRawData; //get start address for the search
			size = header->SizeOfRawData; //get size for the search
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	QWORD match = 0;
	INT curlength = 0;
	BOOLEAN ret = FALSE;

    //We're looking for a codecave(CC bytes) after a return operand
	for (QWORD cur = (begin ? begin : start); cur < start + size; ++cur)
	{
		if (!ret && is_retop(*(BYTE*)cur)) 
            ret = TRUE;
		else if (ret && *(BYTE*)cur == 0xCC)
		{
			if (!match) match = cur;
			if (++curlength == length) return match;
		}

		else
		{
			match = curlength = 0;
			ret = FALSE;
		}
	}

	return 0;
}

/*
	Remaps the page where the target address is in with PAGE_EXECUTE_READWRITE protection and patches in the given bytes
	If this is the restore routine, then after patching in the bytes the protection is set back to PAGE_READONLY
*/
static BOOLEAN remap_page(_In_ VOID* address, _In_ BYTE* assembly, _In_ ULONG length, _In_ BOOLEAN restore)
{
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (!mdl)
	{
        DbgPrint("[-] Failed allocating MDL!\n"); 
		return FALSE;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (!map_address)
	{
        DbgPrint("[-] Failed mapping the page!\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status)
	{
        DbgPrint("[-] Failed MmProtectMdlSystemAddress with status: 0x%lX\n", status);
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	RtlCopyMemory(map_address, assembly, length);

	if (restore)
	{
		status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
		if (status)
		{
            DbgPrint("[-] Failed second MmProtectMdlSystemAddress with status: 0x%lX\n", status);
			MmUnmapLockedPages(map_address, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return FALSE;
		}
	}

	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

static BOOLEAN patch_codecave_detour(_In_ QWORD address, _In_ QWORD target)
{
    //Return pointer swap detour
	BYTE assembly[16] = {
		0x50,                                                        // push rax
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
		0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
		0xC3                                                         // retn
	};
	*(QWORD*)(assembly + 3) = target;

	return remap_page((VOID*)address, assembly, 16, FALSE);
}

static BOOLEAN restore_codecave_detour(_In_ QWORD address)
{
	BYTE assembly[16] = {
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
	};

	return remap_page((VOID*)address, assembly, 16, TRUE);
}

static VOID to_lower(_In_ CHAR* in, _Out_ CHAR* out)
{
	INT i = -1;
	while (in[++i] != '\x00') out[i] = (CHAR)tolower(in[i]);
}

static BOOLEAN is_pg_protected(_In_ CONST CHAR* image)
{
	
	static CONST CHAR* images[] = { "win32kbase.sys", "tm.sys", "clfs.sys", "msrpc.sys", "ndis.sys", "ntfs.sys", "tcpip.sys", "fltmgr.sys", "ksecdd.sys", "clipsp.sys", "cng.sys", "dxgkrnl.sys"};
	static INT count = 12;

	for (INT i = 0; i < count; ++i)
	{
		if (strstr(image, images[i]))
			return TRUE;
	}

	return FALSE;
}



#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define POOLTAG 'EB'

typedef unsigned long long QWORD;
#define ABSOLUTE(wait)			(wait)
#define RELATIVE(wait)			(-(wait))
#define NANOSECONDS(nanos)		(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)	(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)		(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)		(((signed __int64)(seconds)) * MILLISECONDS(1000L))

namespace Utils
{
    PVOID GetSystemRoutineAddress(LPCWSTR name)
    {
        UNICODE_STRING unicodeName;
        RtlInitUnicodeString(&unicodeName, name);
        return MmGetSystemRoutineAddress(&unicodeName);
    }

    PVOID GetSystemModuleBase(LPCWSTR name)
    {
        PLIST_ENTRY loadedModuleList = (PLIST_ENTRY)(GetSystemRoutineAddress(L"PsLoadedModuleList"));
        if (!loadedModuleList)
        {
            return NULL;
        }
        __try
        {
            for (PLIST_ENTRY link = loadedModuleList->Flink; link != loadedModuleList; link = link->Flink)
            {
                LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (_wcsicmp(name, entry->BaseDllName.Buffer) == 0)
                {
                    return entry->DllBase;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return NULL;
        }
        return NULL;
    }

    //Disables write protection by changing the cr0 mask
    void WriteProtectOff()
    {
        auto cr0 = __readcr0();
        cr0 &= 0xfffffffffffeffff;
        __writecr0(cr0);
        _disable();
    }

    //Enables write protection by changing the cr0 mask
    void WriteProtectOn()
    {
        auto cr0 = __readcr0();
        cr0 |= 0x10000;
        _enable();
        __writecr0(cr0);
    }

    

    //Finds drivers base address by its name
    PVOID GetDriverBase(LPCSTR module_name)
    {
        ULONG bytes{};
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);
        if (!bytes)
        {
            return NULL;
        }
        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOLTAG);
        if (modules)
        {
            status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(modules, POOLTAG);
                return NULL;
            }
            PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
            PVOID module_base{}, module_size{};
            for (ULONG i = 0; i < modules->NumberOfModules; i++)
            {
                if (strcmp(reinterpret_cast<char*>(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
                {
                    module_base = module[i].ImageBase;
                    module_size = (PVOID)module[i].ImageSize;
                    break;
                }
            }
            ExFreePoolWithTag(modules, POOLTAG);
            return module_base;
        }
        return NULL;
    }

    /*
        Swap pointer to an imported function in ImportAddressTable
    */
    PVOID IATHook(PVOID lpBaseAddress, CHAR* lpcStrImport, PVOID lpFuncAddress)
    {
        PIMAGE_DOS_HEADER dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(lpBaseAddress) + dosHeaders->e_lfanew);
        IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + (DWORD_PTR)lpBaseAddress);

        LPCSTR libraryName = NULL;
        PVOID result = NULL;
        PIMAGE_IMPORT_BY_NAME functionName = NULL;

        if (!importDescriptor)
        {
            DbgPrintEx(0, 0, "[-] Didn't find Import Descriptor\n");
            return NULL;
        }


        while (importDescriptor->Name != NULL)
        {
            libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)lpBaseAddress;
            if (GetDriverBase(libraryName))
            {
                PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
                originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + importDescriptor->OriginalFirstThunk);
                firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + importDescriptor->FirstThunk);
                while (originalFirstThunk->u1.AddressOfData != NULL)
                {
                    functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + originalFirstThunk->u1.AddressOfData);
                    if (strcmp(functionName->Name, lpcStrImport) == 0)
                    {
                        result = reinterpret_cast<PVOID>(firstThunk->u1.Function);
                        WriteProtectOff();
                        PVOID address = lpFuncAddress;
                        orig_MmGetSystemRoutineAddress = firstThunk->u1.Function; //save original pointer
                        firstThunk->u1.Function = reinterpret_cast<ULONG64>(address); //swap pointer to ours
                        WriteProtectOn();
                        return result; //returns original pointer
                    }
                    ++originalFirstThunk;
                    ++firstThunk;
                }
            }
            importDescriptor++;
        }
        return NULL;
    }

    const BYTE orig_cc[16] = { 0xCC,0xCC,0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC, 0xCC,0xCC };

    DWORD FindTextSection(char* module, DWORD* size)
    {
        PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
        {
            PIMAGE_SECTION_HEADER section = &sections[i];
            if (memcmp(section->Name, ".text", 5) == 0)
            {
                *size = section->Misc.VirtualSize;
                return section->VirtualAddress;
            }
        }
        return 0;
    }

    PRTL_PROCESS_MODULES GetModuleList()
    {
        ULONG length = 0;
        ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
        length += (10 * 1024);

        PRTL_PROCESS_MODULES module_list = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, length);
        ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length);

        if (!module_list)
        {
            DbgPrintEx(0, 0, "[-] Module List Is Empty\n");
            return 0;
        }
        return module_list;
    }

    VOID Sleep(LONGLONG milliseconds)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = RELATIVE(MILLISECONDS(milliseconds));
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    BOOLEAN WriteToReadOnlyMemory(IN VOID* destination, IN VOID* source, IN ULONG size)
    {
        PMDL mdl = IoAllocateMdl(destination, size, FALSE, FALSE, 0);
        if (!mdl)
            return FALSE;

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        PVOID map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
        if (!map_address)
        {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            MmUnmapLockedPages(map_address, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        RtlCopyMemory(map_address, source, size);

        MmUnmapLockedPages(map_address, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return TRUE;
    }

    NTSTATUS OpenPhysicalHandle(PHANDLE handle, PCWSTR diskName)
    {
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;
        UNICODE_STRING deviceName;
        NTSTATUS status;

        RtlInitUnicodeString(&deviceName, diskName);

        InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ZwCreateFile(
            handle,
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        return status;
    }
}


#define REPORT_WITHTAG 0x4CA793
#define REPORT 0x4C2C78

static OB_PREOP_CALLBACK_STATUS HookCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    auto result = _be_original_ob_callback(RegistrationContext, OperationInformation);
    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    return result;
}

static PVOID Hook_ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
{
    /*PVOID RetAdd = _ReturnAddress();
    if ((QWORD)RetAdd == report_exallocatepool_add)
    {
        DbgPrintEx(0, 0, "Failing ExAllocatePool in report routine: %p, at offset: %lx\n", (PVOID)report_exallocatepool_add, report_exallocatepool_add - (QWORD)be_module);
        last_exallocatepool_calladd = (QWORD)RetAdd;
        return 0;
    }
    if (last_exallocatepool_calladd != 0)
    {
        QWORD offset = (QWORD)RetAdd - last_exallocatepool_calladd;
        if (offset == 11)
        {
            DbgPrintEx(0, 0, "Failing suspect ExAllocatePool call!, distance to previous call: %lld\n", offset);
            if (!report_exallocatepool_add && offset == 11)
                report_exallocatepool_add = last_exallocatepool_calladd;
            last_exallocatepool_calladd = (QWORD)RetAdd;
            return 0;
        }
        if (offset < 1000)
            DbgPrintEx(0, 0, "ExAllocatePool called from: %p, distance to previous call: %lld\n", RetAdd, offset);
        last_exallocatepool_calladd = (QWORD)RetAdd;
    }
    else
        last_exallocatepool_calladd = (QWORD)RetAdd;*/
    //if (PoolType == 0x200 && (NumberOfBytes == 0x1000 || NumberOfBytes == 0x90 ))//|| NumberOfBytes == 0x91 || NumberOfBytes == 0x878
    //{
    //    return 0; //THIS WAS PATCHED BY BATTLEYE ON 09.03.2024
    //}
    if (((QWORD)_ReturnAddress() - (QWORD)be_module) == REPORT)
    {
        //ExAllocatePool_Report_Counter+=1;
        //DbgPrintEx(0, 0, "ExAllocatePool called in report routine!\n");

        DbgPrintEx(0, 0, "ExAllocatePool called in report routine! ");
        
        if (openfile_battleye_counter == 1 && !Init_Completed)
        {
            DbgPrintEx(0, 0, "Letting Vital info packets through\n");
            return ExAllocatePool(PoolType, NumberOfBytes);
        }
        else if (ExAllocatePool_Report_Counter < 2)
        {
            ExAllocatePool_Report_Counter += 1;
            DbgPrintEx(0, 0, "Letting HWID info packets pass\n");
            return ExAllocatePool(PoolType, NumberOfBytes);
        }
        /*else if (openfile_battleye_counter < 1 || Init_Completed)
        {
            DbgPrintEx(0, 0, "Failing ExAllocatePool\n");
            return 0;
        }*/
        else if (openfile_battleye_counter < 1)
        {
            DbgPrintEx(0, 0, "Failing ExAllocatePool %llx\n", NumberOfBytes);
            return 0;
        }
    }
    
    else if (LAST_Hooked_drv_called)
    {
        DbgPrintEx(0, 0, "Failing ExAllocatePool call on hooked driver!\n");
        return 0;
    }
    //DbgPrintEx(0, 0, "ExAllocatePool called\n");
    return ExAllocatePool(PoolType, NumberOfBytes);
}

static PVOID Hook_ExAllocatePoolWithTag(QWORD PoolType, QWORD NumberOfBytes, QWORD Tag)
{
    /*PVOID RetAdd = _ReturnAddress();
    if ((QWORD)RetAdd == report_exallocatepoolwithtag_add)
    {
        DbgPrintEx(0, 0, "Failing ExAllocatePoolWithTag in report routine: %p, at offset: %lx\n", (PVOID)report_exallocatepoolwithtag_add, report_exallocatepoolwithtag_add - (QWORD)be_module);
        last_exallocatepoolwithtag_calladd = (QWORD)RetAdd;
        return 0;
    }
    if (last_exallocatepoolwithtag_calladd != 0)
    {
        QWORD offset = (QWORD)RetAdd - last_exallocatepoolwithtag_calladd;
        if (offset == 11)
        {
            DbgPrintEx(0, 0, "Failing suspect ExAllocatePoolWithTag call!, distance to previous call: %lld\n", offset);
            if (!report_exallocatepoolwithtag_add)
                report_exallocatepoolwithtag_add = last_exallocatepoolwithtag_calladd;
            last_exallocatepoolwithtag_calladd = (QWORD)RetAdd;
            return 0;
        }
        if (offset < 1000)
            DbgPrintEx(0, 0, "ExAllocatePoolWithTag called from: %p, distance to previous call: %lld\n", RetAdd, offset);
        last_exallocatepoolwithtag_calladd = (QWORD)RetAdd;
    }
    else
        last_exallocatepoolwithtag_calladd = (QWORD)RetAdd;*/

    if (((QWORD)_ReturnAddress() - (QWORD)be_module) == REPORT_WITHTAG)
    {
        DbgPrintEx(0, 0, "ExAllocatePoolWithTag called in report routine! Failing ExAllocatePoolWithTag %llx\n", NumberOfBytes);
        return 0;
    }
    if (LAST_Hooked_drv_called)
    {
        DbgPrintEx(0, 0, "Failing ExAllocatePoolWithTag call on hooked driver!\n");
        return 0;
    }

    //DbgPrintEx(0, 0, "ExAllocatePoolWithTag called\n");

    return ExAllocatePoolWithTag((POOL_TYPE)PoolType, NumberOfBytes, Tag);
}

static NTSTATUS Hook_ObRegisterCallbacks(POB_CALLBACK_REGISTRATION callback_registration, PVOID* registration_handle)
{
    DbgPrintEx(0, 0, "[+] BE Called ObRegisterCallbacks\n");

    _be_original_ob_callback = callback_registration->OperationRegistration->PreOperation;

    if (_be_pre_ob_callback_cave != 0)
    {
        if (!patch_codecave_detour(_be_pre_ob_callback_cave, (uint64_t)&HookCallback))
        {
            DbgPrintEx(0, 0, "[!] Failed To Patch Code Cave\n");
            return STATUS_UNSUCCESSFUL;
        }
        callback_registration->OperationRegistration->PreOperation = (POB_PRE_OPERATION_CALLBACK)_be_pre_ob_callback_cave;
        DbgPrintEx(0, 0, "[+] Patched ObRegisterCallbacks\n");
    }

    return ObRegisterCallbacks(callback_registration, registration_handle);
}

static BOOLEAN Hook_ExEnumHandleTable(__in PHANDLE_TABLE 	HandleTable,
    __in PEX_ENUM_HANDLE_CALLBACK 	EnumHandleProcedure,
    __inout PVOID 	Context,
    __out_opt PHANDLE 	Handle
)
{
    return ExEnumHandleTable(
        HandleTable,
        EnumHandleProcedure,
        (PVOID)1,
        Handle);
}

static NTSTATUS Hook_ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{

    if (wcsstr((wchar_t*)ObjectAttributes->ObjectName->Buffer, (wchar_t*)driver_name))
    {
        DbgPrintEx(0, 0, "(!) BE Called ZwOpenFile on: %S\n", (WCHAR*)driver_name);

        /*FileHandle = NULL;
        IoStatusBlock = NULL;
        return 0xC000000D;*/
        LAST_Hooked_drv_called = TRUE;
    }
    else
        LAST_Hooked_drv_called = FALSE;

    if (wcsstr((wchar_t*)ObjectAttributes->ObjectName->Buffer, L"Harddisk0\\DR0"))
    {
        DbgPrintEx(0, 0, "(!) BE Called ZwOpenFile on: Harddisk0\\DR0\n");

        if (!Init_Completed) Init_Completed = true;
        wchar_t diskName[] = L"\\??\\C:\\spoof\\newhwid.bin";
        NTSTATUS status;

        status = Utils::OpenPhysicalHandle(FileHandle, (wchar_t*)diskName);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(0, 0, "Failed to open disk handle: 0x%X\n", status);
            return status;
        }
        else
            DbgPrintEx(0, 0, "Successfully redirected BE\n");

        ExAllocatePool_Report_Counter = 0;

        //return ZwOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        return status;
    }
    else if (wcsstr((wchar_t*)ObjectAttributes->ObjectName->Buffer, L"BattlEye"))
    {
        DbgPrintEx(0, 0, "BE Called ZwOpenFile on: %S\n", (wchar_t*)ObjectAttributes->ObjectName->Buffer);
        openfile_battleye_counter += 1;
        if (openfile_battleye_counter == 2)
            Init_Completed = true;
    }


    //DbgPrintEx(0, 0, "BE Called ZwOpenFile on: %S\n", (wchar_t*)ObjectAttributes->ObjectName->Buffer);
    return ZwOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

//NTSTATUS Hook_ZwDeviceIoControlFile(
//	__in            HANDLE           FileHandle,
//	__in_opt		HANDLE           Event,
//	__in_opt		PIO_APC_ROUTINE  ApcRoutine,
//	__in_opt		PVOID            ApcContext,
//	__out			PIO_STATUS_BLOCK IoStatusBlock,
//	__in            ULONG            IoControlCode,
//	__in_opt		PVOID            InputBuffer,
//	__in            ULONG            InputBufferLength,
//	__out_opt		PVOID            OutputBuffer,
//	__in            ULONG            OutputBufferLength
//)
//{
//	DbgPrintEx(0, 0, "BE called ZwDeviceIoControlFile with IOCTL code : % ld\n", IoControlCode);
//	return ZwDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
//}

static BOOLEAN Hook_MmIsAddressValid(
    __in PVOID VirtualAddress
)
{
    DbgPrintEx(0, 0, "Failing MmIsAddressValid\n");
    return FALSE;

    //return MmIsAddressValid(VirtualAddress);
}

/*
    BEDaisy gets its imports with MmGetSystemRoutineAddress
    By hooking it we can return pointers to our functions instead of the real ones
    Be aware BEDaisy checks whether the pointer to an imported function resides inside of ntoskrnl.exe, after its Init function completes and reports it
    So you need to disable or spoof this check, or disable BEDaisy violation reports altogether
    Known method to disable its violation reports is by filtering its calls to ExAllocatePool and ExAllocatePoolWithTag
    This can be done by checking from where in memory they are being called (_ReturnAddress()) with having previously checked that is the violation report function
    You can check this by looking up the distance between calls to ExAllocatePool/ExAllocatePoolWithTag and their size parameter
    In the driver's decompiled reports functions you can see that the calls happen very close one after another and the first size is much smaller than the second
    Knowing that, calls that report violations can be filtered out and their offset from base saved(it is constant for the same compilation)
    Having done that, all that is left is to fail either one of the 2 calls in the report function, resulting in disabling the violation reporting functionality
*/
static PVOID Hook_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
    DbgPrintEx(0, 0, "BE imported: %S\n", (wchar_t*)SystemRoutineName->Buffer);
    if (!wcscmp(SystemRoutineName->Buffer, L"ObGetObjectType"))
    {
    Utils::IATHook((PVOID)be_module, "MmGetSystemRoutineAddress", (PVOID)orig_MmGetSystemRoutineAddress);
    }
    else if (!wcscmp(SystemRoutineName->Buffer, L"ObRegisterCallbacks"))
    {
        return &Hook_ObRegisterCallbacks;
    }
    else if (!wcscmp(SystemRoutineName->Buffer, L"ExAllocatePool"))
    {
        return &Hook_ExAllocatePool;
    }
    else if (!wcscmp(SystemRoutineName->Buffer, L"ExAllocatePoolWithTag"))
    {
        return &Hook_ExAllocatePoolWithTag;
    }
    else if (!wcscmp(SystemRoutineName->Buffer, L"ExEnumHandleTable"))
    {
        return &Hook_ExEnumHandleTable;
    }
    else if (!wcscmp(SystemRoutineName->Buffer, L"ZwOpenFile"))
    {
        return &Hook_ZwOpenFile;
    }
    else if (!wcscmp(SystemRoutineName->Buffer, L"MmIsAddressValid"))
    {
        return &Hook_MmIsAddressValid;
    }
    

    return MmGetSystemRoutineAddress(SystemRoutineName);
}