//go:build windows

package tun

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type WindowsDevice struct {
	dev tun.Device
	cfg Config
	mu  sync.Mutex
}

func ensureWintunDLL() error {
	dllPath := "wintun.dll"
	if _, err := os.Stat(dllPath); err == nil {
		return nil // Esiste già
	}

	log.Println("wintun.dll non trovato. Download in corso da wintun.net...")
	resp, err := http.Get("https://www.wintun.net/builds/wintun-0.14.1.zip")
	if err != nil {
		return fmt.Errorf("impossibile scaricare wintun.zip: %v", err)
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "wintun-*.zip")
	if err != nil {
		return fmt.Errorf("impossibile creare file temporaneo: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return fmt.Errorf("impossibile scrivere zip temporaneo: %v", err)
	}

	// Apri lo zip
	zipReader, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("impossibile leggere zip: %v", err)
	}
	defer zipReader.Close()

	// Determina il percorso del DLL corretto nello zip a seconda dell'architettura
	var archDir string
	switch runtime.GOARCH {
	case "amd64":
		archDir = "wintun/bin/amd64/wintun.dll"
	case "386":
		archDir = "wintun/bin/x86/wintun.dll"
	case "arm64":
		archDir = "wintun/bin/arm64/wintun.dll"
	default:
		return fmt.Errorf("architettura non supportata per wintun: %s", runtime.GOARCH)
	}

	var found bool
	for _, f := range zipReader.File {
		if f.Name == archDir {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("errore apertura file nello zip: %v", err)
			}
			defer rc.Close()

			outDLL, err := os.Create(dllPath)
			if err != nil {
				return fmt.Errorf("impossibile creare wintun.dll in locale: %v", err)
			}
			defer outDLL.Close()

			_, err = io.Copy(outDLL, rc)
			if err != nil {
				return fmt.Errorf("errore scrittura wintun.dll: %v", err)
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("wintun.dll non trovato nello zip per l'architettura %s", runtime.GOARCH)
	}

	log.Println("wintun.dll scaricato ed estratto con successo!")
	return nil
}

func CreateDevice(cfg Config) (Tuner, error) {
	// Assicuriamoci che ci sia il driver wintun.dll prima di creare l'interfaccia
	if err := ensureWintunDLL(); err != nil {
		return nil, fmt.Errorf("driver wintun.dll mancante o non scaricabile: %w", err)
	}

	if cfg.MTU <= 0 {
		cfg.MTU = 1420
	}

	log.Printf("Creazione interfaccia TUN '%s'...", cfg.Name)
	dev, err := tun.CreateTUN(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("errore creazione TUN: %w", err)
	}

	wd := &WindowsDevice{
		dev: dev,
		cfg: cfg,
	}

	// Diamo tempo al sistema operativo di registrare l'interfaccia
	time.Sleep(1 * time.Second)

	// Configurazione dell'indirizzo IP
	log.Printf("Configurazione IP %s su interfaccia %s...", cfg.IP, cfg.Name)
	if err := wd.configureIP(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("errore configurazione IP: %w", err)
	}

	log.Printf("Interfaccia TUN %s configurata con successo con IP %s", cfg.Name, cfg.IP)
	return wd, nil
}

func (d *WindowsDevice) configureIP() error {
	// Usiamo netsh per configurare l'indirizzo IP
	// netsh interface ip set address name="NOME" static IP MASK
	cmd := exec.Command("netsh", "interface", "ip", "set", "address", "name="+d.cfg.Name, "static", d.cfg.IP, "255.255.255.0", "store=active")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// A volte Windows usa il nome dell'interfaccia in modo diverso o ha bisogno di qualche secondo in più. Prova un fallback usando powershell
		log.Printf("Netsh fallito (%v): %s. Provo con PowerShell...", err, string(output))
		psCmd := fmt.Sprintf("New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength 24 -SkipAsSource $false", d.cfg.Name, d.cfg.IP)
		cmd = exec.Command("powershell", "-Command", psCmd)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("fallito anche con PowerShell: %v, output: %s", err, string(output))
		}
	}

	// Configura il firewall di Windows per consentire tutto il traffico su questa interfaccia
	log.Printf("Configurazione regole Firewall per l'interfaccia %s...", d.cfg.Name)
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=WorldTunnel-"+d.cfg.Name).Run()
	fwCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", 
		"name=WorldTunnel-"+d.cfg.Name, 
		"dir=in", 
		"action=allow", 
		"interface="+d.cfg.Name, 
		"enable=yes",
	)
	if fwOut, fwErr := fwCmd.CombinedOutput(); fwErr != nil {
		log.Printf("Avviso: Impossibile creare regola firewall automatica (%v): %s", fwErr, string(fwOut))
	} else {
		log.Printf("Firewall configurato: consentito tutto il traffico in ingresso sulla scheda %s", d.cfg.Name)
	}

	return nil
}

func (d *WindowsDevice) ReadPacket() ([]byte, error) {
	// Alloca un buffer abbastanza capiente per contenere un pacchetto IP e un margine di sicurezza
	buf := make([]byte, d.cfg.MTU+200)
	bufs := [][]byte{buf}
	sizes := []int{0}

	n, err := d.dev.Read(bufs, sizes, 0)
	if err != nil {
		return nil, err
	}

	if n == 0 || sizes[0] == 0 {
		return nil, fmt.Errorf("nessun pacchetto letto")
	}

	packetSize := sizes[0]
	packet := make([]byte, packetSize)
	copy(packet, buf[:packetSize])
	return packet, nil
}

func (d *WindowsDevice) WritePacket(packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bufs := [][]byte{packet}
	_, err := d.dev.Write(bufs, 0)
	return err
}

func (d *WindowsDevice) Close() error {
	return d.dev.Close()
}

func (d *WindowsDevice) IP() string {
	return d.cfg.IP
}
