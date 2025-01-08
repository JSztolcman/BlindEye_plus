#include "memory_utils.hpp"

#define SystemModuleInformation 0x0B
extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

typedef LDR_DATA_TABLE_ENTRY*(*MiLookupDataTableEntry_fn)(IN VOID* Address, IN BOOLEAN);
MiLookupDataTableEntry_fn MiLookupDataTableEntry;

QWORD g_callback_address = 0, g_thread_address = 0;





/*
	The (detoured) callback will enter here
	Note that the accompanying shellcode cannot be removed, as it still gets called regularly
*/
VOID callback(UNICODE_STRING* image_name, HANDLE process_id, IMAGE_INFO* image_info)
{
	//processId is 4 for drivers
	if ((process_id == NULL || process_id == (HANDLE)4) && image_name != NULL && wcsstr(image_name->Buffer, L"BEDaisy.sys")) 
	{
		// hook import
		be_module = (QWORD)Utils::GetSystemModuleBase(L"BEDaisy.sys");
		Init_Completed = false;
		Utils::IATHook((PVOID)be_module, "MmGetSystemRoutineAddress", &Hook_MmGetSystemRoutineAddress);
	}
	DbgPrintEx(0, 0, "[+] Driver Loaded: %S\n", (WCHAR*)image_name->Buffer); //Driver Load notification
}

/*
	The (detoured) main thread will enter here, this can be looped infinitely without worry
	As soon as the thread gets created the shellcode and the page protection are restored to hide any traces
	In this case I only use this to register my callback
*/
VOID main_thread()
{
	DbgPrintEx(0, 0, "[+] Inside main thread\n");
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING dev, dos;

	//restore codecave bytes
	if (!restore_codecave_detour(g_thread_address))
	{
		DbgPrintEx(0, 0, "[-] Failed restoring thread code cave!\n");
}
	else
	{
		DbgPrintEx(0, 0, "[+] Restored thread code cave\n");
	}

	//Create callback
	NTSTATUS status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)g_callback_address);
	if (status)
	{
		DbgPrintEx(0, 0, "[-] Failed PsSetCreateProcessNotifyRoutineEx with status: 0x%lX\n", status);
	}
	else
	{
		DbgPrintEx(0, 0, "[+] Registered LoadImage notify routine\n");
	}

}

VOID* get_module_list()
{
	ULONG length = 0;
	ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length); // Call ZwQuerySystemInformation to get size of the structure
	length += (10 * 1024); // Add some size for safety

	VOID* module_list = ExAllocatePool2(POOL_FLAG_PAGED | POOL_COLD_ALLOCATION, length, 55); //Create a pool for the module list
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length); // Call ZwQuerySystemInformation to get module list

	if (status)
	{
		DbgPrintEx(0, 0, "[-] Failed ZwQuerySystemInformation with 0x%lX\n", status);
		if (module_list) ExFreePool(module_list);
		return 0;
	}

	if (!module_list)
	{
		DbgPrintEx(0, 0, "[-] Module list is empty\n");
		return 0;
	}

	return module_list;
}

BOOLEAN apply_codecaves()
{
	VOID* module_list = get_module_list();
	if (!module_list) return FALSE;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;
	
	/*
		We need to find 2, 16 byte codecaves, preferably in the same module:
		g_callback_address will be the detour to the CreateProcess callback
		g_thread_address will be the detour for our main thread
	*/
	for (ULONG i = 1; i < modules->NumberOfModules; ++i) //iterate from 1 to skip ntoskrnl.exe
	{
		RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];

		CHAR driver_name[0x0100] = { 0 };
		to_lower(module->FullPathName, driver_name);

		/*
			Either look for any driver that isn't PageGuard protected
			Or look for a driver that you know works (iorate.sys here)
		*/

		/*if (!strstr(driver_name, ".sys") || is_pg_protected(driver_name)) 
			continue;*/

		if (!strstr(driver_name, "iorate.sys"))
			continue;

		//Check if you've already hooked the chosen driver
		if (find_pattern_nt("50 48 B8 ? ? ? ? ? ? ? ? 48 87 04 24 C3", (QWORD)module->ImageBase, module->ImageSize))
		{
			DbgPrintEx(0, 0, "[-] Already hooked\n");
			return FALSE;
		}
		
		//Look for codecaves
		g_callback_address = find_codecave(module->ImageBase, 16, 0);
		if (!g_callback_address) continue;

		g_thread_address = find_codecave(module->ImageBase, 16, g_callback_address + 16);
		_be_pre_ob_callback_cave = g_thread_address;
		if (!g_thread_address)
		{
			g_callback_address = 0;
			continue;
		}

		LDR_DATA_TABLE_ENTRY* ldr = MiLookupDataTableEntry((VOID*)g_callback_address, FALSE);
		if (!ldr)
		{
			g_callback_address = g_thread_address = 0;
			continue;
		}

		// Setting the 0x20 data table entry flag makes MmVerifyCallbackFunction pass
		ldr->Flags |= 0x20;
		DbgPrintEx(0, 0, "[+] Found places for both code caves in module %s\n", driver_name + module->OffsetToFileName);

		break;
	}

	ExFreePool(module_list);

	/*
		Instead of just stopping we could loosen our restrictions and search for 2 code caves in separate modules
		But in practice, 16 byte code caves are quite common, so this shouldn't really happen
	*/
	if (!g_callback_address || !g_thread_address)
	{
		DbgPrintEx(0, 0, "[-] Failed to find all required code caves in any driver module!\n");
		return FALSE;
	}


	if (!patch_codecave_detour(g_callback_address, (QWORD)&callback))
	{
		DbgPrintEx(0, 0, "[-] Failed patching in create_process_callback redirection code cave!\n");
		return FALSE;
	}

	if (!patch_codecave_detour(g_thread_address, (QWORD)&main_thread))
	{
		DbgPrintEx(0, 0, "[-] Failed patching in main_thread redirection code cave!\n");
		return FALSE;
	}

	DbgPrintEx(0, 0, "[+] Patched in both code caves succesfully\n");

	HANDLE thread;
	NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, 0, 0, 0, (KSTART_ROUTINE*)g_thread_address, 0);
	if (status)
	{
		DbgPrintEx(0, 0, "[-] PsCreateSystemThread failed, status = 0x%08X\n", status);
	}
	else
	{
		DbgPrintEx(0, 0, "[+] Created a system thread in target space\n");
	}

	return TRUE;
}

// Custom entry point, don't create a driver object here because that would just add another detection vector
NTSTATUS DriverEntry(DRIVER_OBJECT* driver_object, UNICODE_STRING* registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);
	DbgPrintEx(0, 0, "Start\n");
	void* module_list = get_module_list();
	if (!module_list) return STATUS_UNSUCCESSFUL;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;

	// First module is always ntoskrnl.exe
	RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[0];

	//Sigscan for MiLookupDataTableEntry in ntoskrnl.exe
	QWORD address = find_pattern_nt("48 8B C4 48 89 58 08 48 89 70 18 57 48 83 EC 20 33 F6", (QWORD)module->ImageBase, module->ImageSize); //Win10
	if (!address) 
	{
		address = find_pattern_nt("48 89 5C 24 08 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 33 ED", (QWORD)module->ImageBase, module->ImageSize); //Win11
		if (!address)
		{
			DbgPrintEx(0, 0, "[-] Could not find MiLookupDataTableEntry\n");
			return STATUS_UNSUCCESSFUL;
		}
	}
	DbgPrintEx(0, 0, "[+] Found MiLookupDataTableEntry at 0x%p\n", (VOID*)address);
	MiLookupDataTableEntry = (MiLookupDataTableEntry_fn)address; // Save pointer to global var

	ExFreePool(module_list);
	if (!apply_codecaves()) 
		DbgPrintEx(0,0,"[-] Failed applying code caves\n");

	return STATUS_UNSUCCESSFUL;
}