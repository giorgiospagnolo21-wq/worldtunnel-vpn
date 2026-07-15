package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"worldtunnel/pkg/tun"
	"worldtunnel/pkg/webrtc"

	"github.com/gogpu/systray"
	"github.com/gorilla/websocket"
	webview2 "github.com/jchv/go-webview2"
)

type LogBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

var globalLogBuffer = &LogBuffer{
	max: 100,
}

func (lb *LogBuffer) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	line := string(p)
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")

	lb.lines = append(lb.lines, line)
	if len(lb.lines) > lb.max {
		lb.lines = lb.lines[1:]
	}

	return os.Stdout.Write(p)
}

func (lb *LogBuffer) GetLines() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	copied := make([]string, len(lb.lines))
	copy(copied, lb.lines)
	return copied
}

//go:embed ui/*
var uiFS embed.FS

//go:embed ui/icon_tray.png
var iconBytes []byte

type Agent struct {
	mu            sync.RWMutex
	localID       string
	localIP       string
	serverURL     string
	ifaceName     string
	networkKey    string
	requestedIP   string
	authenticated bool
	authError     string
	wsConn        *websocket.Conn
	tunDev        tun.Tuner
	webrtcMgr     *webrtc.Manager
	wsMutex       sync.Mutex
	done          chan struct{}
	peersStatus   []webrtc.PeerStatus
}

func NewAgent(localID, serverURL, ifaceName, networkKey, requestedIP string) *Agent {
	return &Agent{
		localID:       localID,
		serverURL:     serverURL,
		ifaceName:     ifaceName,
		networkKey:    networkKey,
		requestedIP:   requestedIP,
		authenticated: false,
		done:          make(chan struct{}),
	}
}

func (a *Agent) connectSignaling() error {
	u, err := url.Parse(a.serverURL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("id", a.localID)
	q.Set("key", a.networkKey)
	if a.requestedIP != "" {
		q.Set("ip", a.requestedIP)
	}
	u.RawQuery = q.Encode()

	log.Printf("Connessione al server di coordinamento: %s...", u.String())
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	a.wsConn = conn
	return nil
}

func (a *Agent) sendSignal(target string, signalType string, data []byte) {
	a.wsMutex.Lock()
	defer a.wsMutex.Unlock()

	if a.wsConn == nil {
		return
	}

	// Aggiunge il tipo specifico di segnale nel wrapper per essere decodificato correttamente
	wrapper := map[string]interface{}{
		"type":   "signal",
		"target": target,
		"data": map[string]interface{}{
			"type": signalType,
			"data": string(data),
		},
	}

	err := a.wsConn.WriteJSON(wrapper)
	if err != nil {
		log.Printf("Errore invio segnale a %s: %v", target, err)
	}
}

func (a *Agent) run() {
	for {
		select {
		case <-a.done:
			return
		default:
			err := a.connectSignaling()
			if err != nil {
				log.Printf("Errore connessione server (%v). Riprovo tra 5 secondi...", err)
				time.Sleep(5 * time.Second)
				continue
			}

			a.handleSignalingLoop()
			
			// Attendi 5 secondi dopo la chiusura prima di ricollegarti (evita loop stretto)
			time.Sleep(5 * time.Second)
		}
	}
}

// Struttura per decodificare il segnale nidificato
type SignalDataWrapper struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

func (a *Agent) handleSignalingLoop() {
	defer func() {
		if a.wsConn != nil {
			a.wsConn.Close()
		}
	}()

	for {
		_, payload, err := a.wsConn.ReadMessage()
		if err != nil {
			log.Printf("Errore di lettura dal server WebSocket: %v", err)
			return
		}

		var rawMsg map[string]json.RawMessage
		if err := json.Unmarshal(payload, &rawMsg); err != nil {
			log.Printf("Errore decodifica messaggio raw: %v", err)
			continue
		}

		var msgType string
		if err := json.Unmarshal(rawMsg["type"], &msgType); err != nil {
			continue
		}

		switch msgType {
		case "register":
			var errStr string
			if rawMsg["error"] != nil {
				json.Unmarshal(rawMsg["error"], &errStr)
			}
			if errStr != "" {
				a.mu.Lock()
				a.authenticated = false
				if errStr == "device_not_authenticated" {
					a.authError = "device_not_authenticated"
				} else {
					a.authError = errStr
				}
				a.mu.Unlock()
				log.Printf("Registrazione rifiuta dal server: %s", errStr)
				// Interrompiamo la connessione corrente per riprovare
				return
			}

			var ip string
			if err := json.Unmarshal(rawMsg["ip"], &ip); err != nil {
				log.Printf("Errore decodifica IP virtuale: %v", err)
				continue
			}
			a.handleRegistration(ip)

		case "peers":
			var peers []struct {
				ID        string `json:"id"`
				VirtualIP string `json:"virtual_ip"`
			}
			if err := json.Unmarshal(rawMsg["peers"], &peers); err != nil {
				log.Printf("Errore decodifica lista peer: %v", err)
				continue
			}
			a.handlePeersUpdate(peers)

		case "signal":
			var sender string
			if err := json.Unmarshal(rawMsg["sender"], &sender); err != nil {
				continue
			}
			
			// Decodifica il wrapper del segnale
			var wrappedSignal SignalDataWrapper
			if err := json.Unmarshal(rawMsg["data"], &wrappedSignal); err != nil {
				log.Printf("Errore decodifica wrapped signal: %v", err)
				continue
			}

			a.mu.RLock()
			mgr := a.webrtcMgr
			a.mu.RUnlock()

			if mgr != nil {
				err := mgr.HandleSignal(sender, wrappedSignal.Type, []byte(wrappedSignal.Data))
				if err != nil {
					log.Printf("Errore gestione segnale da %s: %v", sender, err)
				}
			}
		}
	}
}

func (a *Agent) handleRegistration(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.authenticated = true
	a.authError = ""

	log.Printf("Registrazione confermata dal server! IP Virtuale: %s", ip)

	if a.localIP == ip {
		return // IP già configurato
	}

	a.localIP = ip

	// Se esiste un vecchio device, chiudilo
	if a.tunDev != nil {
		a.tunDev.Close()
	}

	// Chiudi tutte le connessioni WebRTC del vecchio manager prima di ricrearlo
	if a.webrtcMgr != nil {
		a.webrtcMgr.Close()
	}

	// Crea l'interfaccia di rete virtuale TUN
	tunCfg := tun.Config{
		Name: a.ifaceName,
		IP:   ip,
		MTU:  1420,
	}
	dev, err := tun.CreateDevice(tunCfg)
	if err != nil {
		showErrorDialog("Errore Inizializzazione Rete", 
			fmt.Sprintf("Impossibile creare la scheda di rete virtuale '%s'.\n\n"+
			"Dettagli Errore: %v\n\n"+
			"Verifica di disporre dei privilegi di Amministratore.", a.ifaceName, err))
		log.Fatalf("IMPOSSIBILE creare l'interfaccia TUN: %v", err)
	}
	a.tunDev = dev

	// Callback per i pacchetti ricevuti via WebRTC -> scrivi su TUN
	onPacketReceived := func(packet []byte) {
		err := dev.WritePacket(packet)
		if err != nil {
			// Evitiamo log eccessivi per errori di scrittura ricorrenti
		}
	}

	// Callback per la segnalazione WebRTC -> invia al server di coordinamento
	onSignalingMsg := func(target string, msgType string, data []byte) {
		a.sendSignal(target, msgType, data)
	}

	// Inizializza il gestore WebRTC
	mgr, err := webrtc.NewManager(a.localID, ip, onSignalingMsg, onPacketReceived)
	if err != nil {
		log.Fatalf("Errore inizializzazione WebRTC Manager: %v", err)
	}
	a.webrtcMgr = mgr

	// Avvia il loop di lettura pacchetti da TUN -> invia a WebRTC
	go a.startTUNReadLoop()
}

func getDstIP(packet []byte) (string, error) {
	if len(packet) < 20 {
		return "", fmt.Errorf("pacchetto troppo corto (%d bytes)", len(packet))
	}
	version := packet[0] >> 4
	if version != 4 {
		return "", fmt.Errorf("solo IPv4 supportato (versione: %d)", version)
	}
	return fmt.Sprintf("%d.%d.%d.%d", packet[16], packet[17], packet[18], packet[19]), nil
}

func (a *Agent) startTUNReadLoop() {
	log.Println("Loop lettura pacchetti TUN avviato...")
	for {
		packet, err := a.tunDev.ReadPacket()
		if err != nil {
			log.Printf("Ciclo TUN interrotto o errore di lettura: %v", err)
			return
		}

		dstIP, err := getDstIP(packet)
		if err != nil {
			continue // Ignora pacchetti non validi o non IPv4
		}

		a.mu.RLock()
		mgr := a.webrtcMgr
		localIP := a.localIP
		a.mu.RUnlock()

		if dstIP == localIP {
			continue // Evita auto-loopback locale
		}

		if mgr != nil {
			// Invia il pacchetto tramite WebRTC al peer assegnato a questo IP virtuale
			mgr.SendPacket(dstIP, packet)
		}
	}
}

func (a *Agent) handlePeersUpdate(peers []struct {
	ID        string `json:"id"`
	VirtualIP string `json:"virtual_ip"`
}) {
	a.mu.Lock()
	mgr := a.webrtcMgr
	localID := a.localID
	a.mu.Unlock()

	if mgr == nil {
		return
	}

	// Tieni traccia dei peer attuali per la UI
	peersMap := make(map[string]bool)

	for _, p := range peers {
		if p.ID == localID {
			continue // Salta se stesso
		}
		peersMap[p.ID] = true

		// Aggiunge il peer al gestore WebRTC
		mgr.AddPeer(p.ID, p.VirtualIP)

		// Se il nostro ID locale è alfabeticamente minore del peer, iniziamo noi la connessione WebRTC.
		// Questo risolve i conflitti di chiamata simultanea
		if localID < p.ID {
			// Avvia una goroutine per non bloccare il ciclo principale
			go func(id string) {
				time.Sleep(500 * time.Millisecond) // Attendi stabilità
				log.Printf("Inizio connessione WebRTC verso peer: %s", id)
				if err := mgr.InitiateConnection(id); err != nil {
					log.Printf("Errore inizializzazione chiamata a %s: %v", id, err)
				}
			}(p.ID)
		}
	}

	// Rimuovi eventuali peer disconnessi che non sono più nell'elenco del server
	currentPeers := mgr.GetPeersStatus()
	for _, p := range currentPeers {
		if !peersMap[p.ID] {
			mgr.RemovePeer(p.ID)
		}
	}
}

func (a *Agent) GetStatus() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	peers := []webrtc.PeerStatus{}
	if a.webrtcMgr != nil {
		peers = a.webrtcMgr.GetPeersStatus()
	}

	return map[string]interface{}{
		"id":            a.localID,
		"virtual_ip":    a.localIP,
		"requested_ip":  a.requestedIP,
		"server":        a.serverURL,
		"network_key":   a.networkKey,
		"online":        a.wsConn != nil,
		"authenticated": a.authenticated,
		"auth_error":    a.authError,
		"peers":         peers,
	}
}

func (a *Agent) Close() {
	close(a.done)
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tunDev != nil {
		a.tunDev.Close()
	}
	if a.wsConn != nil {
		a.wsConn.Close()
	}
}

var webviewActive bool
var webviewMutex sync.Mutex

func openWebView(port string) {
	webviewMutex.Lock()
	if webviewActive {
		webviewMutex.Unlock()
		return
	}
	webviewActive = true
	webviewMutex.Unlock()

	go func() {
		defer func() {
			webviewMutex.Lock()
			webviewActive = false
			webviewMutex.Unlock()
		}()

		runtime.LockOSThread()
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  "WorldTunnel Control Panel",
				Width:  1024,
				Height: 720,
				Center: true,
			},
		})
		if w != nil {
			defer w.Destroy()
			w.Navigate("http://localhost:" + port)
			w.Run()
		}
	}()
}

func main() {
	// Reindirizza l'output del log al nostro buffer in memoria per la UI
	log.SetOutput(globalLogBuffer)

	// Eseguiamo il controllo di elevazione UAC prima di tutto
	checkAndElevate()

	serverFlag := flag.String("server", "wss://worldtunnel-vpn.onrender.com/ws", "URL del server di coordinamento")
	idFlag := flag.String("id", "", "ID univoco per questo PC (lascia vuoto per usare il nome del PC)")
	portFlag := flag.String("port", "8000", "Porta locale per l'interfaccia web di controllo")
	ifaceFlag := flag.String("iface", "worldtunnel", "Nome dell'interfaccia di rete virtuale")
	keyFlag := flag.String("key", "default_network", "Chiave di rete (account)")
	ipFlag := flag.String("ip", "", "Indirizzo IP virtuale statico richiesto (es. 10.0.0.5)")

	flag.Parse()

	if *idFlag == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "pc-" + fmt.Sprintf("%d", time.Now().Unix()%10000)
		}
		*idFlag = hostname
	}

	agent := NewAgent(*idFlag, *serverFlag, *ifaceFlag, *keyFlag, *ipFlag)
	go agent.run()

	// Gestione dei file statici della UI incorporati (embed)
	subFS, err := fs.Sub(uiFS, "ui")
	if err != nil {
		log.Fatalf("Errore filesystem UI incorporato: %v", err)
	}

	// Endpoints API per la UI
	http.Handle("/", http.FileServer(http.FS(subFS)))
	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(agent.GetStatus())
	})
	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(globalLogBuffer.GetLines())
	})
	http.HandleFunc("/api/configure", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		newKey := r.URL.Query().Get("key")
		newServer := r.URL.Query().Get("server")
		newIP := r.URL.Query().Get("ip")

		agent.mu.Lock()
		if newKey != "" {
			agent.networkKey = newKey
		}
		if newServer != "" {
			agent.serverURL = newServer
		}
		agent.requestedIP = newIP // Se vuoto, ritorna a dynamic allocation
		agent.mu.Unlock()

		log.Printf("Configurazione aggiornata -> Server: '%s', Account: '%s', IP Richiesto: '%s'. Riconnessione in corso...", agent.serverURL, agent.networkKey, agent.requestedIP)

		// Disconnettiamo per forzare la riconnessione automatica con i nuovi dati
		agent.wsMutex.Lock()
		if agent.wsConn != nil {
			agent.wsConn.Close()
		}
		agent.wsMutex.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Server web locale
	go func() {
		log.Printf("Dashboard Web locale avviata su http://localhost:%s", *portFlag)
		if err := http.ListenAndServe(":"+*portFlag, nil); err != nil {
			log.Printf("Errore avvio server Web UI: %v", err)
		}
	}()

	// Inizializzazione e avvio del System Tray
	tray := systray.New().SetIcon(iconBytes).SetTooltip("WorldTunnel Client")
	
	// Registriamo i gestori per il click e il doppio click sull'icona del tray
	tray.OnClick(func() {
		openWebView(*portFlag)
	})
	tray.OnDoubleClick(func() {
		openWebView(*portFlag)
	})

	menu := systray.NewMenu()
	menu.Add("Apri Pannello di Controllo", func() {
		openWebView(*portFlag)
	})

	menu.Add("Esci", func() {
		log.Println("Spegnimento dell'agente e ripristino schede di rete...")
		agent.Close()
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	})

	tray.SetMenu(menu)
	tray.Show()

	// Apriamo automaticamente la dashboard integrata all'avvio
	openWebView(*portFlag)

	// Eseguiamo il ciclo dei messaggi di Windows (blocca fino a quando non usciamo)
	if err := tray.Run(); err != nil {
		log.Printf("Errore nell'esecuzione del System Tray: %v", err)
	}
}
