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

type ClientConfig struct {
	Server      string `json:"server"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	RequestedIP string `json:"requested_ip"`
}

func loadConfig() ClientConfig {
	var cfg ClientConfig
	file, err := os.Open("config.json")
	if err != nil {
		return ClientConfig{
			Server:      "wss://worldtunnel-vpn.onrender.com/ws",
			RequestedIP: "",
		}
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		log.Printf("Impossibile caricare config.json: %v. Uso impostazioni predefinite.", err)
		return ClientConfig{
			Server:      "wss://worldtunnel-vpn.onrender.com/ws",
			RequestedIP: "",
		}
	}
	if cfg.Server == "" {
		cfg.Server = "wss://worldtunnel-vpn.onrender.com/ws"
	}
	return cfg
}

func saveConfig(cfg ClientConfig) {
	file, err := os.Create("config.json")
	if err != nil {
		log.Printf("Errore durante il salvataggio di config.json: %v", err)
		return
	}
	defer file.Close()

	json.NewEncoder(file).Encode(cfg)
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
	email         string
	password      string
	authenticated bool
	authError     string
	wsConn        *websocket.Conn
	tunDev        tun.Tuner
	webrtcMgr     *webrtc.Manager
	wsMutex       sync.Mutex
	done          chan struct{}
	peersStatus   []webrtc.PeerStatus
}

func (a *Agent) saveLocalConfig() {
	a.mu.Lock()
	defer a.mu.Unlock()

	cfg := ClientConfig{
		Server:      a.serverURL,
		Email:       a.email,
		Password:    a.password,
		RequestedIP: a.requestedIP,
	}
	saveConfig(cfg)
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
	a.mu.Lock()
	serverURL := a.serverURL
	localID := a.localID
	email := a.email
	password := a.password
	requestedIP := a.requestedIP
	a.mu.Unlock()

	// Se abbiamo email e password locali, tentiamo un login diretto http preventivo
	if email != "" && password != "" {
		loginURL := strings.Replace(serverURL, "wss://", "https://", 1)
		loginURL = strings.Replace(loginURL, "ws://", "http://", 1)
		loginURL = strings.TrimSuffix(loginURL, "/ws") + "/auth/login-direct"

		log.Printf("Autenticazione automatica sul server per account %s...", email)

		reqBody, _ := json.Marshal(map[string]string{
			"device_id": localID,
			"email":     email,
			"password":  password,
		})

		resp, err := http.Post(loginURL, "application/json", strings.NewReader(string(reqBody)))
		if err != nil {
			log.Printf("Errore chiamata login automatico: %v. Procedo con WebSocket...", err)
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				log.Printf("Autenticazione automatica riuscita!")
			} else {
				log.Printf("Autenticazione automatica non riuscita (Stato: %d). Potrebbe essere richiesta la riautenticazione.", resp.StatusCode)
			}
		}
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("id", localID)
	q.Set("key", email)
	if requestedIP != "" {
		q.Set("ip", requestedIP)
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
			if strings.Contains(err.Error(), "use of closed network connection") {
				log.Println("Connessione chiusa per aggiornamento configurazione.")
			} else {
				log.Printf("Errore di lettura dal server WebSocket: %v", err)
			}
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

	localCfg := loadConfig()

	serverFlag := flag.String("server", localCfg.Server, "URL del server di coordinamento")
	idFlag := flag.String("id", "", "ID univoco per questo PC (lascia vuoto per usare il nome del PC)")
	portFlag := flag.String("port", "8000", "Porta locale per l'interfaccia web di controllo")
	ifaceFlag := flag.String("iface", "worldtunnel", "Nome dell'interfaccia di rete virtuale")
	keyFlag := flag.String("key", "default_network", "Chiave di rete (account)")
	ipFlag := flag.String("ip", localCfg.RequestedIP, "Indirizzo IP virtuale statico richiesto (es. 10.0.0.5)")

	flag.Parse()

	if *idFlag == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "pc-" + fmt.Sprintf("%d", time.Now().Unix()%10000)
		}
		*idFlag = hostname
	}

	agent := NewAgent(*idFlag, *serverFlag, *ifaceFlag, *keyFlag, *ipFlag)
	agent.email = localCfg.Email
	agent.password = localCfg.Password
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
	http.HandleFunc("/api/login-submit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		email := r.URL.Query().Get("email")
		password := r.URL.Query().Get("password")

		if email == "" || password == "" {
			w.Write([]byte(`{"status":"error","error":"Email e Password sono obbligatori"}`))
			return
		}

		agent.mu.Lock()
		serverURL := agent.serverURL
		localID := agent.localID
		agent.mu.Unlock()

		loginURL := strings.Replace(serverURL, "wss://", "https://", 1)
		loginURL = strings.Replace(loginURL, "ws://", "http://", 1)
		loginURL = strings.TrimSuffix(loginURL, "/ws") + "/auth/login-direct"

		reqBody, _ := json.Marshal(map[string]string{
			"device_id": localID,
			"email":     email,
			"password":  password,
		})

		resp, err := http.Post(loginURL, "application/json", strings.NewReader(string(reqBody)))
		if err != nil {
			w.Write([]byte(fmt.Sprintf(`{"status":"error","error":"Server non raggiungibile: %v"}`, err)))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errData struct {
				Error string `json:"error"`
			}
			json.NewDecoder(resp.Body).Decode(&errData)
			if errData.Error == "" {
				errData.Error = fmt.Sprintf("Codice stato: %d", resp.StatusCode)
			}
			w.Write([]byte(fmt.Sprintf(`{"status":"error","error":"%s"}`, errData.Error)))
			return
		}

		agent.mu.Lock()
		agent.email = email
		agent.password = password
		agent.mu.Unlock()

		agent.saveLocalConfig()

		agent.wsMutex.Lock()
		if agent.wsConn != nil {
			agent.wsConn.Close()
		}
		agent.wsMutex.Unlock()

		w.Write([]byte(`{"status":"ok"}`))
	})
	http.HandleFunc("/api/register-submit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		email := r.URL.Query().Get("email")
		password := r.URL.Query().Get("password")

		if email == "" || password == "" {
			w.Write([]byte(`{"status":"error","error":"Email e Password sono obbligatori"}`))
			return
		}

		agent.mu.Lock()
		serverURL := agent.serverURL
		localID := agent.localID
		agent.mu.Unlock()

		registerURL := strings.Replace(serverURL, "wss://", "https://", 1)
		registerURL = strings.Replace(registerURL, "ws://", "http://", 1)
		registerURL = strings.TrimSuffix(registerURL, "/ws") + "/auth/register-direct"

		reqBody, _ := json.Marshal(map[string]string{
			"device_id": localID,
			"email":     email,
			"password":  password,
		})

		resp, err := http.Post(registerURL, "application/json", strings.NewReader(string(reqBody)))
		if err != nil {
			w.Write([]byte(fmt.Sprintf(`{"status":"error","error":"Server non raggiungibile: %v"}`, err)))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errData struct {
				Error string `json:"error"`
			}
			json.NewDecoder(resp.Body).Decode(&errData)
			if errData.Error == "" {
				errData.Error = fmt.Sprintf("Codice stato: %d", resp.StatusCode)
			}
			w.Write([]byte(fmt.Sprintf(`{"status":"error","error":"%s"}`, errData.Error)))
			return
		}

		agent.mu.Lock()
		agent.email = email
		agent.password = password
		agent.mu.Unlock()

		agent.saveLocalConfig()

		agent.wsMutex.Lock()
		if agent.wsConn != nil {
			agent.wsConn.Close()
		}
		agent.wsMutex.Unlock()

		w.Write([]byte(`{"status":"ok"}`))
	})
	http.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		agent.mu.Lock()
		serverURL := agent.serverURL
		localID := agent.localID
		agent.mu.Unlock()

		// Notifica il server per disassociare la sessione del dispositivo
		logoutURL := strings.Replace(serverURL, "wss://", "https://", 1)
		logoutURL = strings.Replace(logoutURL, "ws://", "http://", 1)
		logoutURL = strings.TrimSuffix(logoutURL, "/ws") + "/auth/logout-direct"

		reqBody, _ := json.Marshal(map[string]string{
			"device_id": localID,
		})

		resp, err := http.Post(logoutURL, "application/json", strings.NewReader(string(reqBody)))
		if err != nil {
			log.Printf("Errore invio richiesta logout al server: %v", err)
		} else {
			resp.Body.Close()
		}

		agent.mu.Lock()
		agent.email = ""
		agent.password = ""
		agent.authenticated = false
		agent.localIP = ""
		agent.mu.Unlock()

		agent.saveLocalConfig()

		agent.mu.Lock()
		if agent.tunDev != nil {
			agent.tunDev.Close()
			agent.tunDev = nil
		}
		if agent.webrtcMgr != nil {
			agent.webrtcMgr.Close()
			agent.webrtcMgr = nil
		}
		agent.mu.Unlock()

		agent.wsMutex.Lock()
		if agent.wsConn != nil {
			agent.wsConn.Close()
		}
		agent.wsMutex.Unlock()

		w.Write([]byte(`{"status":"ok"}`))
	})
	http.HandleFunc("/api/reconnect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		agent.wsMutex.Lock()
		if agent.wsConn != nil {
			agent.wsConn.Close()
			log.Println("Riconnessione manuale del WebSocket avviata...")
		} else {
			log.Println("WebSocket non attivo, avvio tentativo di connessione immediato...")
		}
		agent.wsMutex.Unlock()

		w.Write([]byte(`{"status":"ok"}`))
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

		agent.saveLocalConfig()

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
