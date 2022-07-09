/*
	Author: Dreg aka David Reguera García 
			Dreg@fr33project.org - http://blog.48bits.com
	-
	License: MIT
	-
	Description: Callgate injector based in rootkit arsenal: fixed.
    -
	Geetz: GriYo, Slay, Tomac, Alon & Pluf.
*/

#ifndef _CALL_GATES_H__
#define _CALL_GATES_H__

#include <ntddk.h>
#include <windef.h> 

#define KGDT_R0_CODE 0x8 

#pragma pack(1)
typedef struct _GDTR
{
	WORD  nBytes;
	DWORD baseAddress;
} GDTR;
#pragma pack()

#pragma pack(1)
typedef struct _SELECTOR
{
	WORD rpl:2;
	WORD ti:1;
	WORD index:13;
} SELECTOR;
#pragma pack()

#pragma pack(1)
typedef struct _SEG_DESCRIPTOR
{
	WORD size_00_15; 
	WORD baseAddress_00_15; 
	WORD baseAddress_16_23:8;
	WORD type:4;
	WORD sFlag:1;
	WORD dpl:2;
	WORD pFlag:1;
	WORD size_16_19:4;
	WORD notUsed:1;
	WORD lFlag:1;
	WORD DB:1;
	WORD gFlag:1;
	WORD baseAddress_24_31:8;
} SEG_DESCRIPTOR, *PSEG_DESCRIPTOR;
#pragma pack()

#pragma pack(1)
typedef struct _CALL_GATE_DESCRIPTOR
{
	WORD offset_00_15;
	WORD selector;
	WORD argCount:5;
	WORD zeroes:3;
	WORD type:4;
	WORD sFlag:1;
	WORD dpl:2;
	WORD pFlag:1; 
	WORD offset_16_31;
} CALL_GATE_DESCRIPTOR, *PCALL_GATE_DESCRIPTOR;
#pragma pack()

typedef enum _SYSTEM_INFORMATION_CLASS { 
	SystemBasicInformation, 				// 0 
	SystemProcessorInformation, 			// 1 
	SystemPerformanceInformation, 			// 2
	SystemTimeOfDayInformation, 			// 3
	SystemNotImplemented1, 				// 4
	SystemProcessesAndThreadsInformation, 		// 5
	SystemCallCounts, 					// 6
	SystemConfigurationInformation, 			// 7
	SystemProcessorTimes, 				// 8
	SystemGlobalFlag, 					// 9
	SystemNotImplemented2, 				// 10
	SystemModuleInformation, 				// 11
	SystemLockInformation, 				// 12
	SystemNotImplemented3, 				// 13
	SystemNotImplemented4, 				// 14
	SystemNotImplemented5, 				// 15
	SystemHandleInformation, 				// 16
	SystemObjectInformation, 				// 17
	SystemPagefileInformation, 				// 18
	SystemInstructionEmulationCounts, 			// 19
	SystemInvalidInfoClass1, 				// 20
	SystemCacheInformation, 				// 21
	SystemPoolTagInformation, 				// 22
	SystemProcessorStatistics, 				// 23
	SystemDpcInformation, 				// 24
	SystemNotImplemented6, 				// 25
	SystemLoadImage, 					// 26
	SystemUnloadImage, 				// 27
	SystemTimeAdjustment, 				// 28
	SystemNotImplemented7, 				// 29
	SystemNotImplemented8, 				// 30
	SystemNotImplemented9, 				// 31
	SystemCrashDumpInformation, 			// 32
	SystemExceptionInformation, 			// 33
	SystemCrashDumpStateInformation, 			// 34
	SystemKernelDebuggerInformation, 			// 35
	SystemContextSwitchInformation, 			// 36
	SystemRegistryQuotaInformation, 			// 37
	SystemLoadAndCallImage, 				// 38
	SystemPrioritySeparation, 				// 39
	SystemNotImplemented10, 				// 40
	SystemNotImplemented11, 				// 41
	SystemInvalidInfoClass2, 				// 42
	SystemInvalidInfoClass3, 				// 43
	SystemTimeZoneInformation, 				// 44
	SystemLookasideInformation, 			// 45
	SystemSetTimeSlipEvent, 				// 46
	SystemCreateSession, 				// 47
	SystemDeleteSession, 				// 48
	SystemInvalidInfoClass4, 				// 49
	SystemRangeStartInformation, 			// 50
	SystemVerifierInformation, 				// 51
	SystemAddVerifier, 				// 52
	SystemSessionProcessesInformation 			// 53
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
    BYTE Reserved1[24];
    PVOID Reserved2[4];
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

#endif /* _CALL_GATES_H__ */
