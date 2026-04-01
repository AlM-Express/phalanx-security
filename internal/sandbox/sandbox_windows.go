//go:build windows
// +build windows

package sandbox

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func executeSandboxed(command []string) error {
	// MVP Job Object approach to constrain processes spawned by the script.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create job object: %w", err)
	}
	defer windows.CloseHandle(job)

	// Format command line
	var cmdLine string
	for _, arg := range command {
		cmdLine += " " + syscall.EscapeArg(arg)
	}

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	cwd, _ := syscall.UTF16PtrFromString(".")
	cmdPtr, _ := syscall.UTF16PtrFromString(cmdLine[1:])

	// Create process suspended using windows package constant
	err = syscall.CreateProcess(nil, cmdPtr, nil, nil, false,
		windows.CREATE_SUSPENDED|syscall.CREATE_NEW_PROCESS_GROUP,
		nil, cwd, &si, &pi)

	if err != nil {
		return fmt.Errorf("CreateProcess failed: %w", err)
	}

	// Assign the suspended process to the Job Object
	handle := windows.Handle(pi.Process)
	err = windows.AssignProcessToJobObject(job, handle)
	if err != nil {
		syscall.TerminateProcess(pi.Process, 1)
		syscall.CloseHandle(pi.Thread)
		syscall.CloseHandle(pi.Process)
		return fmt.Errorf("failed to assign to job: %w", err)
	}

	// Resume the thread using windows package
	_, err = windows.ResumeThread(windows.Handle(pi.Thread))
	if err != nil {
		syscall.TerminateProcess(pi.Process, 1)
	}

	// Wait for completion
	event, _ := syscall.WaitForSingleObject(pi.Process, syscall.INFINITE)
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)

	if event != syscall.WAIT_OBJECT_0 {
		return fmt.Errorf("child process terminated abnormally")
	}

	fmt.Println("[SANDBOX] Execution finished cleanly within Windows Job Object.")
	return nil
}
