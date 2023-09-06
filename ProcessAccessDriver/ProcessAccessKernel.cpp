#include <ntddk.h>
#include "Header.h"


// Initializing the dispatch routines and unload.
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH CreateCloseRoutine;
DRIVER_DISPATCH DeviceControl;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	DbgPrint("Entering %s", __FUNCTION__);
	
	NTSTATUS status;
	UNICODE_STRING DeviceName, SymbolicLink;
	PDEVICE_OBJECT DeviceObject;

	RtlInitUnicodeString(&DeviceName, L"\\Device\\ProcessAccessOmarDev");

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error, Creating the device object.\n");
		return status;
	}

	RtlInitUnicodeString(&SymbolicLink, L"\\??\\PorcessAccessOmarSym");
	IoCreateSymbolicLink(&SymbolicLink, &DeviceName);

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseRoutine;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	
	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("Entering %s", __FUNCTION__);

	UNICODE_STRING SymbolicLink;
	RtlInitUnicodeString(&SymbolicLink, L"\\??\\PorcessAccessOmarSym");


	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&SymbolicLink);

}

NTSTATUS CreateCloseRoutine(PDEVICE_OBJECT , PIRP Irp)
{
	DbgPrint("Entering %s", __FUNCTION__);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT , PIRP Irp)
{

	DbgPrint("Entering %s", __FUNCTION__);
	HANDLE hSystemProcess; /*holds the system process handle*/
	OBJECT_ATTRIBUTES objAttr; 
	CLIENT_ID clientID{};
	int PID, sizeofOutbuffer; /*the PID came from user*/
	NTSTATUS status = STATUS_SUCCESS;

	auto stackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (stackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PROC_ACCESS:
		
		// CHECK FIRST FOR SOME SECURITY THINGS:
		if (stackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(int) ||
			stackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HANDLE) ||
			Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			DbgPrint("error in input or output size or no parameter passed in the call of IoDeviceControl.\n");
			return STATUS_INVALID_PARAMETER;
		}

		// do the actuall work:

		PID = *(int*)Irp->AssociatedIrp.SystemBuffer; // get the Pid from user

		clientID.UniqueProcess = ULongToHandle(PID); // convert to handle and set the process id


		// init the object attribute for the handle that will be passed
		InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr); 


		status = ZwOpenProcess(&hSystemProcess, PROCESS_ALL_ACCESS, &objAttr, &clientID);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("ERROR: while openning the process.\n");
			return status;
		}

		// GIVE IT TO THE USER FINALLY:
		memcpy(Irp->AssociatedIrp.SystemBuffer, &hSystemProcess, sizeof(hSystemProcess));
		 
		// but don't forget to tell set the size of that handle passed to the Irp.
		sizeofOutbuffer = sizeof(HANDLE);

		break;

	default:
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	// set the size of the output buffer passed and complete the request.
	Irp->IoStatus.Information = sizeofOutbuffer;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, 0);

	return STATUS_SUCCESS;
}