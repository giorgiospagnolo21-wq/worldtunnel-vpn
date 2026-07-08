//go:build windows

package main

import (
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func showErrorDialog(title, message string) {
	msgPtr, _ := syscall.UTF16PtrFromString(message)
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")
	
	// MB_OK | MB_ICONERROR = 0x00000000 | 0x00000010
	messageBox.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x00000010)
}

func checkAndElevate() {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return // Già amministratore, continua
	}

	verb := "runas"
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("Impossibile ottenere percorso eseguibile: %v", err)
	}

	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	// Avvia una nuova istanza con privilegi elevati (UAC Prompt)
	err = windows.ShellExecute(0, verbPtr, exePtr, argPtr, nil, 1)
	if err != nil {
		// Se l'utente nega l'autorizzazione UAC
		showErrorDialog("WorldTunnel - Privilegi Amministratore Richiesti", 
			"L'applicazione richiede i privilegi di Amministratore per creare la scheda di rete virtuale (TUN).\n\n"+
			"Avvia il programma consentendo l'elevazione dei privilegi per procedere.")
		os.Exit(1)
	}
	
	// Esci dal processo non amministratore corrente
	os.Exit(0)
}
