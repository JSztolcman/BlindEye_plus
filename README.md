# BlindEye_plus

Project based on https://github.com/zouxianyu/BlindEye and https://github.com/rogerxiii/kernel-codecave-poc

This project adds a callback registered by a legit module by exploiting its codecaves to the original BlindEye

## Overview

1. We get MiLookupDataTableEntry by sigscanning ntoskrnl.exe

2. We look for two 16 byte codecaves inside of any legit driver that isn't PageGuard protected

3. We place detours in the codecaves, one detour to the callback code and one for the thread that will register it

4. We use MiLookupDataTableEntry to change ldr flags to make MmVerifyCallbackFunction pass

5. LoadImage callback IAT hooks BEDaisy.sys MmGetSystemRoutineAddress every time it is loaded

## ExAllocatePool & ExAllocatePoolWithTag filtering

The original method of failing every call with 'NonPagedPool' and size 24 is no longer possible. But with some creativity it can still be achieved.
