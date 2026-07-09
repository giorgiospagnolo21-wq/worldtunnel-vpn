package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	ID        string          `json:"id"`
	VirtualIP string          `json:"virtual_ip"`
	Key       string          `json:"key"` // Sarà l'email dell'account Google
	Conn      *websocket.Conn `json:"-"`
}

type Message struct {
	Type   string          `json:"type"`             // "register", "peers", "signal"
	Sender string          `json:"sender,omitempty"` // Mittente
	Target string          `json:"target,omitempty"` // Destinatario (solo per "signal")
	Data   json.RawMessage `json:"data,omitempty"`   // Dati SDP o ICE
	Peers  []Client        `json:"peers,omitempty"`  // Peers nello stesso account
	IP     string          `json:"ip,omitempty"`     // IP assegnato
	Error  string          `json:"error,omitempty"`  // Eventuale messaggio di errore (es: non autenticato)
}

type Server struct {
	mu            sync.Mutex
	clients       map[string]map[string]*Client // email -> clientID -> Client
	assignedIP    map[string]map[string]string   // email -> clientID -> VirtualIP
	ipPools       map[string][]string            // email -> []IPs
	deviceToEmail map[string]string              // deviceID -> email (Sessioni attive)
	googleClientID     string
	googleClientSecret string
	publicURL          string
}

func NewServer() *Server {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	
	// Ricava l'URL pubblico di Render o usa il default
	publicURL := os.Getenv("RENDER_EXTERNAL_URL")
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	publicURL = strings.TrimSuffix(publicURL, "/")

	return &Server{
		clients:            make(map[string]map[string]*Client),
		assignedIP:         make(map[string]map[string]string),
		ipPools:            make(map[string][]string),
		deviceToEmail:      make(map[string]string),
		googleClientID:     clientID,
		googleClientSecret: clientSecret,
		publicURL:          publicURL,
	}
}

func (s *Server) getOrAssignIP(key, clientID, requestedIP string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.assignedIP[key]; !ok {
		s.assignedIP[key] = make(map[string]string)
	}
	if _, ok := s.ipPools[key]; !ok {
		pool := make([]string, 0, 253)
		for i := 2; i <= 254; i++ {
			pool = append(pool, fmt.Sprintf("10.0.0.%d", i))
		}
		s.ipPools[key] = pool
	}

	if ip, ok := s.assignedIP[key][clientID]; ok {
		if requestedIP == "" || requestedIP == ip {
			return ip, nil
		}
	}

	if requestedIP != "" {
		for id, ip := range s.assignedIP[key] {
			if ip == requestedIP && id != clientID {
				return "", fmt.Errorf("l'IP virtuale %s è già occupato", requestedIP)
			}
		}

		pool := s.ipPools[key]
		for i, ip := range pool {
			if ip == requestedIP {
				s.ipPools[key] = append(pool[:i], pool[i+1:]...)
				break
			}
		}

		s.assignedIP[key][clientID] = requestedIP
		return requestedIP, nil
	}

	pool := s.ipPools[key]
	if len(pool) == 0 {
		return "", fmt.Errorf("nessun IP virtuale disponibile")
	}

	ip := pool[0]
	s.ipPools[key] = pool[1:]
	s.assignedIP[key][clientID] = ip
	return ip, nil
}

func (s *Server) broadcastPeers(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	groupClients, ok := s.clients[key]
	if !ok || len(groupClients) == 0 {
		return
	}

	peersList := make([]Client, 0, len(groupClients))
	for _, client := range groupClients {
		peersList = append(peersList, Client{
			ID:        client.ID,
			VirtualIP: client.VirtualIP,
			Key:       client.Key,
		})
	}

	msg := Message{
		Type:  "peers",
		Peers: peersList,
	}

	rawMsg, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, client := range groupClients {
		client.Conn.WriteMessage(websocket.TextMessage, rawMsg)
	}
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Errore upgrade WebSocket: %v", err)
		return
	}
	defer conn.Close()

	clientID := r.URL.Query().Get("id")
	requestedIP := r.URL.Query().Get("ip")

	if clientID == "" {
		log.Println("Connessione rifiutata: client ID mancante")
		return
	}

	// Verifica se il dispositivo è associato a un account (autenticato)
	s.mu.Lock()
	email, authenticated := s.deviceToEmail[clientID]
	s.mu.Unlock()

	if !authenticated {
		log.Printf("Connessione rifiutata: dispositivo %s non autenticato", clientID)
		errMsg, _ := json.Marshal(Message{
			Type:  "register",
			Error: "device_not_authenticated",
		})
		conn.WriteMessage(websocket.TextMessage, errMsg)
		return
	}

	virtualIP, err := s.getOrAssignIP(email, clientID, requestedIP)
	if err != nil {
		log.Printf("Connessione rifiutata per %s (account %s): %v", clientID, email, err)
		errMsg, _ := json.Marshal(Message{Type: "register", Error: err.Error()})
		conn.WriteMessage(websocket.TextMessage, errMsg)
		return
	}

	client := &Client{
		ID:        clientID,
		VirtualIP: virtualIP,
		Key:       email,
		Conn:      conn,
	}

	s.mu.Lock()
	if _, ok := s.clients[email]; !ok {
		s.clients[email] = make(map[string]*Client)
	}
	if oldClient, ok := s.clients[email][clientID]; ok {
		oldClient.Conn.Close()
	}
	s.clients[email][clientID] = client
	s.mu.Unlock()

	log.Printf("Agent Connesso: %s | Account: '%s' | IP Virtuale: %s", clientID, email, virtualIP)

	regMsg := Message{
		Type: "register",
		IP:   virtualIP,
	}
	if err := conn.WriteJSON(regMsg); err != nil {
		s.removeClient(email, clientID)
		return
	}

	s.broadcastPeers(email)

	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Agent disconnesso %s (%s): %v", clientID, email, err)
			break
		}

		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "signal":
			s.routeSignal(email, clientID, msg)
		}
	}

	s.removeClient(email, clientID)
}

func (s *Server) removeClient(key, clientID string) {
	s.mu.Lock()
	group, ok := s.clients[key]
	exists := false
	if ok {
		if _, ok2 := group[clientID]; ok2 {
			delete(group, clientID)
			exists = true
			log.Printf("Agent Rimosso: %s dell'account '%s'", clientID, key)
		}
		if len(group) == 0 {
			delete(s.clients, key)
		}
	}
	s.mu.Unlock()

	if exists {
		s.broadcastPeers(key)
	}
}

func (s *Server) routeSignal(key, senderID string, msg Message) {
	s.mu.Lock()
	group, ok := s.clients[key]
	var targetClient *Client
	if ok {
		targetClient = group[msg.Target]
	}
	s.mu.Unlock()

	if targetClient == nil {
		return
	}

	msg.Sender = senderID
	rawMsg, err := json.Marshal(msg)
	if err != nil {
		return
	}

	targetClient.Conn.WriteMessage(websocket.TextMessage, rawMsg)
}

// --- GESTIONE AUTHENTICATION / LOGIN ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("id")
	if deviceID == "" {
		http.Error(w, "Parametro 'id' (ID Dispositivo) mancante nell'URL", http.StatusBadRequest)
		return
	}

	// Se le credenziali Google non sono configurate nell'ambiente, usa la simulazione
	if s.googleClientID == "" || s.googleClientSecret == "" {
		s.serveMockLoginPage(w, deviceID)
		return
	}

	// Altrimenti procedi con il vero Google OAuth
	redirectURI := fmt.Sprintf("%s/auth/callback", s.publicURL)
	googleURL := fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20email&state=%s",
		s.googleClientID, url.QueryEscape(redirectURI), deviceID)

	http.Redirect(w, r, googleURL, http.StatusTemporaryRedirect)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	deviceID := r.FormValue("state") // Contiene l'ID del dispositivo passato nello state

	if code == "" || deviceID == "" {
		http.Error(w, "Dati di autenticazione non validi", http.StatusBadRequest)
		return
	}

	redirectURI := fmt.Sprintf("%s/auth/callback", s.publicURL)

	// Scambia il codice per il token di accesso
	tokenRes, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {s.googleClientID},
		"client_secret": {s.googleClientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		http.Error(w, "Errore scambio token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer tokenRes.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenRes.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Errore decodifica token", http.StatusInternalServerError)
		return
	}

	// Usa il token per recuperare l'email dell'utente da Google
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Errore recupero info utente", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Errore decodifica info utente", http.StatusInternalServerError)
		return
	}

	if userInfo.Email == "" {
		http.Error(w, "Impossibile recuperare l'indirizzo email dell'account", http.StatusBadRequest)
		return
	}

	// Associa il dispositivo a questa email
	s.mu.Lock()
	s.deviceToEmail[deviceID] = userInfo.Email
	s.mu.Unlock()

	log.Printf("Autenticazione Riuscita! Dispositivo %s associato a %s", deviceID, userInfo.Email)

	s.serveSuccessPage(w, userInfo.Email)
}

func (s *Server) serveMockLoginPage(w http.ResponseWriter, deviceID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>WorldTunnel - Login di Test</title>
		<style>
			body { font-family: sans-serif; background-color: #0b0f19; color: #fff; text-align: center; padding-top: 5rem; }
			.card { background: #131a2b; display: inline-block; padding: 2.5rem; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.08); max-width: 400px; }
			h1 { color: #06b6d4; font-size: 1.5rem; margin-bottom: 1rem; }
			input { width: 100%%; padding: 0.75rem; margin: 1rem 0; border-radius: 0.5rem; border: 1px solid #333; background: #0b0f19; color: #fff; box-sizing: border-box; }
			button { background: linear-gradient(135deg, #06b6d4, #10b981); border: none; padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-weight: bold; cursor: pointer; width: 100%%; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1>WorldTunnel Simulator</h1>
			<p>Credenziali Google OAuth non impostate sul server. Esegui l'accesso simulato inserendo un'email fittizia:</p>
			<form action="/auth/mock" method="POST">
				<input type="hidden" name="device_id" value="%s">
				<input type="email" name="email" placeholder="latuaemail@gmail.com" required value="utente@gmail.com">
				<button type="submit">Accedi (Simulato)</button>
			</form>
		</div>
	</body>
	</html>
	`, deviceID)
}

func (s *Server) handleMockLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.FormValue("device_id")
	email := r.FormValue("email")

	if deviceID == "" || email == "" {
		http.Error(w, "Parametri mancanti", http.StatusBadRequest)
		return
	}

	// Associa il dispositivo a questa email di test
	s.mu.Lock()
	s.deviceToEmail[deviceID] = email
	s.mu.Unlock()

	log.Printf("Autenticazione Simulata! Dispositivo %s associato a %s", deviceID, email)

	s.serveSuccessPage(w, email)
}

func (s *Server) serveSuccessPage(w http.ResponseWriter, email string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>WorldTunnel - Accesso Eseguito</title>
		<style>
			body { font-family: sans-serif; background-color: #0b0f19; color: #fff; text-align: center; padding-top: 6rem; }
			.card { background: #131a2b; display: inline-block; padding: 3rem; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.08); }
			h1 { color: #10b981; margin-bottom: 1rem; }
			p { color: #94a3b8; }
			.email { font-weight: bold; color: #06b6d4; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1>Accesso Eseguito con Successo!</h1>
			<p>Il tuo dispositivo è ora associato all'account: <span class="email">%s</span></p>
			<p>Puoi chiudere questa scheda. Il client si connetterà automaticamente.</p>
		</div>
	</body>
	</html>
	`, email)
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Esporta solo dati non sensibili per diagnostica
	status := map[string]interface{}{
		"authenticated_devices": len(s.deviceToEmail),
		"active_networks":       len(s.clients),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func main() {
	server := NewServer()

	http.HandleFunc("/ws", server.handleConnection)
	http.HandleFunc("/login", server.handleLogin)
	http.HandleFunc("/auth/callback", server.handleAuthCallback)
	http.HandleFunc("/auth/mock", server.handleMockLoginSubmit)
	
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/status", server.handleGetStatus)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server di coordinamento WorldTunnel (con Google OAuth / Mock) avviato sulla porta %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Errore all'avvio del server: %v", err)
	}
}
