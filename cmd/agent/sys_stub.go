//go:build !windows

package main

import "log"

func showErrorDialog(title, message string) {
	log.Printf("[%s] %s", title, message)
}

func checkAndElevate() {
	// Nessuna operazione di elevazione automatica necessaria/supportata su altre piattaforme in questo stub
}
