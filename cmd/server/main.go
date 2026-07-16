package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	Key       string          `json:"key"` // Email dell'account
	Conn      *websocket.Conn `json:"-"`
}

type Message struct {
	Type   string          `json:"type"`             // "register", "peers", "signal"
	Sender string          `json:"sender,omitempty"` // Mittente
	Target string          `json:"target,omitempty"` // Destinatario (solo per "signal")
	Data   json.RawMessage `json:"data,omitempty"`   // Dati SDP o ICE
	Peers  []Client        `json:"peers,omitempty"`  // Peers nello stesso account
	IP     string          `json:"ip,omitempty"`     // IP assegnato
	Error  string          `json:"error,omitempty"`  // Eventuale messaggio di errore
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"` // Password cifrata
}

type Server struct {
	mu                 sync.Mutex
	clients            map[string]map[string]*Client // email -> clientID -> Client
	assignedIP         map[string]map[string]string   // email -> clientID -> VirtualIP
	ipPools            map[string][]string            // email -> []IPs
	deviceToEmail      map[string]string              // deviceID -> email (Sessioni attive)
	users              map[string]User                // email -> User
	usersFile          string
	publicURL          string
}

func NewServer() *Server {
	publicURL := os.Getenv("RENDER_EXTERNAL_URL")
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	publicURL = strings.TrimSuffix(publicURL, "/")

	s := &Server{
		clients:            make(map[string]map[string]*Client),
		assignedIP:         make(map[string]map[string]string),
		ipPools:            make(map[string][]string),
		deviceToEmail:      make(map[string]string),
		users:              make(map[string]User),
		usersFile:          "users.json",
		publicURL:          publicURL,
	}

	s.loadUsers()
	s.loadSessions()
	return s
}

func hashPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + "worldtunnel_secret_salt"))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (s *Server) loadSessions() {
	file, err := os.Open("sessions.json")
	if err != nil {
		return
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&s.deviceToEmail); err != nil {
		log.Printf("Errore decodifica sessioni: %v", err)
		s.deviceToEmail = make(map[string]string)
	} else {
		log.Printf("Caricate %d sessioni attive da sessions.json", len(s.deviceToEmail))
	}
}

func (s *Server) saveSessions() {
	file, err := os.Create("sessions.json")
	if err != nil {
		log.Printf("Errore creazione file sessioni: %v", err)
		return
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(s.deviceToEmail); err != nil {
		log.Printf("Errore salvataggio sessioni: %v", err)
	}
}

func (s *Server) loadUsers() {
	file, err := os.Open(s.usersFile)
	if err != nil {
		return
	}
	defer file.Close()

	var usersList []User
	if err := json.NewDecoder(file).Decode(&usersList); err != nil {
		log.Printf("Errore decodifica database utenti: %v", err)
		return
	}

	for _, u := range usersList {
		s.users[u.Email] = u
	}
	log.Printf("Caricati %d utenti dal database '%s'", len(s.users), s.usersFile)
}

func (s *Server) saveUsers() {
	file, err := os.Create(s.usersFile)
	if err != nil {
		log.Printf("Errore creazione file utenti: %v", err)
		return
	}
	defer file.Close()

	usersList := make([]User, 0, len(s.users))
	for _, u := range s.users {
		usersList = append(usersList, u)
	}

	if err := json.NewEncoder(file).Encode(usersList); err != nil {
		log.Printf("Errore salvataggio database utenti: %v", err)
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

	errMessage := r.URL.Query().Get("error")

	// Pagina di login con stile premium e supporto sia Google sia Account Interno
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	errBlock := ""
	if errMessage != "" {
		errBlock = fmt.Sprintf(`<div class="error-msg">%s</div>`, errMessage)
	}

	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>WorldTunnel - Accesso</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #fff; text-align: center; padding: 4rem 1rem; margin: 0; }
			.card { background: #131a2b; display: inline-block; padding: 2.5rem; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.08); max-width: 400px; width: 100%%; box-sizing: border-box; text-align: left; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
			h1 { color: #06b6d4; font-size: 1.6rem; margin-top: 0; margin-bottom: 0.5rem; text-align: center; font-weight: 700; }
			p { color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; text-align: center; }
			.form-group { margin-bottom: 1.25rem; }
			label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.5rem; font-weight: 500; }
			input { width: 100%%; padding: 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(255,255,255,0.1); background: #0b0f19; color: #fff; box-sizing: border-box; font-size: 0.95rem; }
			input:focus { border-color: #06b6d4; outline: none; }
			.btn-primary { background: linear-gradient(135deg, #06b6d4, #10b981); border: none; padding: 0.85rem; border-radius: 0.5rem; font-weight: bold; color: #000; cursor: pointer; width: 100%%; font-size: 0.95rem; margin-top: 0.5rem; transition: opacity 0.2s; }
			.btn-primary:hover { opacity: 0.9; }
			.btn-google { display: flex; align-items: center; justify-content: center; background: #fff; color: #3c4043; border: 1px solid #dadce0; padding: 0.85rem; border-radius: 0.5rem; font-weight: bold; text-decoration: none; font-size: 0.95rem; text-align: center; transition: background-color 0.2s; }
			.btn-google:hover { background-color: #f8f9fa; }
			.divider { text-align: center; margin: 1.5rem 0; font-size: 0.8rem; color: #64748b; position: relative; }
			.divider::before, .divider::after { content: ""; position: absolute; top: 50%%; width: 25%%; height: 1px; background: rgba(255,255,255,0.08); }
			.divider::before { left: 0; }
			.divider::after { right: 0; }
			.error-msg { background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; color: #f87171; padding: 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; margin-bottom: 1.25rem; }
			.footer-link { text-align: center; margin-top: 1.5rem; font-size: 0.85rem; color: #94a3b8; }
			.footer-link a { color: #06b6d4; text-decoration: none; font-weight: bold; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1>Accedi a WorldTunnel</h1>
			<p>Associa il tuo dispositivo al tuo account di rete</p>
			
			%s

			<form action="/auth/login-submit" method="POST">
				<input type="hidden" name="device_id" value="%s">
				<div class="form-group">
					<label>Indirizzo Email</label>
					<input type="email" name="email" required placeholder="esempio@email.com">
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" required placeholder="Inserisci la password">
				</div>
				<button type="submit" class="btn-primary">Accedi</button>
			</form>
			
			<div class="footer-link">
				Non hai ancora un account? <a href="/register?id=%s">Registrati qui</a>
			</div>
		</div>
	</body>
	</html>
	`, errBlock, deviceID, deviceID)
}

func (s *Server) handleRegisterUI(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("id")
	errMessage := r.URL.Query().Get("error")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	errBlock := ""
	if errMessage != "" {
		errBlock = fmt.Sprintf(`<div class="error-msg">%s</div>`, errMessage)
	}

	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>WorldTunnel - Registrazione</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #fff; text-align: center; padding: 4rem 1rem; margin: 0; }
			.card { background: #131a2b; display: inline-block; padding: 2.5rem; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.08); max-width: 400px; width: 100%%; box-sizing: border-box; text-align: left; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
			h1 { color: #10b981; font-size: 1.6rem; margin-top: 0; margin-bottom: 0.5rem; text-align: center; font-weight: 700; }
			p { color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; text-align: center; }
			.form-group { margin-bottom: 1.25rem; }
			label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.5rem; font-weight: 500; }
			input { width: 100%%; padding: 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(255,255,255,0.1); background: #0b0f19; color: #fff; box-sizing: border-box; font-size: 0.95rem; }
			input:focus { border-color: #10b981; outline: none; }
			.btn-primary { background: linear-gradient(135deg, #10b981, #06b6d4); border: none; padding: 0.85rem; border-radius: 0.5rem; font-weight: bold; color: #000; cursor: pointer; width: 100%%; font-size: 0.95rem; margin-top: 0.5rem; transition: opacity 0.2s; }
			.btn-primary:hover { opacity: 0.9; }
			.error-msg { background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; color: #f87171; padding: 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; margin-bottom: 1.25rem; }
			.footer-link { text-align: center; margin-top: 1.5rem; font-size: 0.85rem; color: #94a3b8; }
			.footer-link a { color: #10b981; text-decoration: none; font-weight: bold; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1>Crea Account</h1>
			<p>Registra un nuovo account per la rete VPN di WorldTunnel</p>
			
			%s

			<form action="/auth/register-submit" method="POST">
				<input type="hidden" name="device_id" value="%s">
				<div class="form-group">
					<label>Indirizzo Email</label>
					<input type="email" name="email" required placeholder="esempio@email.com">
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" required placeholder="Scegli una password sicura">
				</div>
				<div class="form-group">
					<label>Conferma Password</label>
					<input type="password" name="confirm_password" required placeholder="Ripeti la password">
				</div>
				<button type="submit" class="btn-primary">Registrati</button>
			</form>
			
			<div class="footer-link">
				Hai già un account? <a href="/login?id=%s">Accedi qui</a>
			</div>
		</div>
	</body>
	</html>
	`, errBlock, deviceID, deviceID)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.FormValue("device_id")
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	if deviceID == "" || email == "" || password == "" {
		http.Redirect(w, r, fmt.Sprintf("/login?id=%s&error=%s", deviceID, url.QueryEscape("Tutti i campi sono obbligatori")), http.StatusSeeOther)
		return
	}

	s.mu.Lock()
	user, exists := s.users[email]
	s.mu.Unlock()

	if !exists || user.Password != hashPassword(password) {
		http.Redirect(w, r, fmt.Sprintf("/login?id=%s&error=%s", deviceID, url.QueryEscape("Email o password non corretti")), http.StatusSeeOther)
		return
	}

	// Associa il dispositivo a questa sessione
	s.mu.Lock()
	s.deviceToEmail[deviceID] = email
	s.saveSessions()
	s.mu.Unlock()

	log.Printf("Autenticazione Riuscita! Dispositivo %s associato all'account: %s", deviceID, email)
	s.serveSuccessPage(w, email)
}

func (s *Server) handleRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.FormValue("device_id")
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if deviceID == "" || email == "" || password == "" || confirmPassword == "" {
		http.Redirect(w, r, fmt.Sprintf("/register?id=%s&error=%s", deviceID, url.QueryEscape("Tutti i campi sono obbligatori")), http.StatusSeeOther)
		return
	}

	if password != confirmPassword {
		http.Redirect(w, r, fmt.Sprintf("/register?id=%s&error=%s", deviceID, url.QueryEscape("Le password non coincidono")), http.StatusSeeOther)
		return
	}

	if len(password) < 6 {
		http.Redirect(w, r, fmt.Sprintf("/register?id=%s&error=%s", deviceID, url.QueryEscape("La password deve contenere almeno 6 caratteri")), http.StatusSeeOther)
		return
	}

	s.mu.Lock()
	_, exists := s.users[email]
	s.mu.Unlock()

	if exists {
		http.Redirect(w, r, fmt.Sprintf("/register?id=%s&error=%s", deviceID, url.QueryEscape("Questo indirizzo email è già registrato")), http.StatusSeeOther)
		return
	}

	newUser := User{
		Email:    email,
		Password: hashPassword(password),
	}

	s.mu.Lock()
	s.users[email] = newUser
	s.saveUsers()
	s.mu.Unlock()

	log.Printf("Nuovo utente registrato con successo: %s", email)

	// Effettua subito l'autenticazione per questo dispositivo
	s.mu.Lock()
	s.deviceToEmail[deviceID] = email
	s.saveSessions()
	s.mu.Unlock()

	s.serveSuccessPage(w, email)
}



func (s *Server) serveSuccessPage(w http.ResponseWriter, email string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>WorldTunnel - Accesso Eseguito</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #fff; text-align: center; padding: 6rem 1rem; margin: 0; }
			.card { background: #131a2b; display: inline-block; padding: 3rem 2.5rem; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 4px 20px rgba(0,0,0,0.3); max-width: 400px; width: 100%%; box-sizing: border-box; }
			h1 { color: #10b981; margin-top: 0; margin-bottom: 1rem; font-size: 1.5rem; font-weight: 700; }
			p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; }
			.email { font-weight: bold; color: #06b6d4; display: block; margin: 0.5rem 0; font-size: 1.1rem; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1>Accesso Eseguito!</h1>
			<p>Il tuo dispositivo è stato associato con successo all'account:</p>
			<span class="email">%s</span>
			<p>Puoi chiudere questa pagina. Il client desktop si collegherà automaticamente in pochi istanti.</p>
		</div>
	</body>
	</html>
	`, email)
}

func (s *Server) handleLoginDirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var req struct {
		DeviceID string `json:"device_id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	s.mu.Lock()
	user, exists := s.users[email]
	s.mu.Unlock()

	if !exists || user.Password != hashPassword(req.Password) {
		http.Error(w, `{"error":"Email o password errati"}`, http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	s.deviceToEmail[req.DeviceID] = email
	s.saveSessions()
	s.mu.Unlock()

	log.Printf("Autenticazione Diretta Riuscita! Dispositivo %s associato a %s", req.DeviceID, email)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleRegisterDirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var req struct {
		DeviceID string `json:"device_id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	if len(req.Password) < 6 {
		http.Error(w, `{"error":"La password deve essere di almeno 6 caratteri"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	_, exists := s.users[email]
	s.mu.Unlock()

	if exists {
		http.Error(w, `{"error":"Questo indirizzo email è già registrato"}`, http.StatusConflict)
		return
	}

	newUser := User{
		Email:    email,
		Password: hashPassword(req.Password),
	}

	s.mu.Lock()
	s.users[email] = newUser
	s.saveUsers()
	s.deviceToEmail[req.DeviceID] = email
	s.saveSessions()
	s.mu.Unlock()

	log.Printf("Registrazione Diretta Riuscita! Creato utente %s per dispositivo %s", email, req.DeviceID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := map[string]interface{}{
		"registered_users":      len(s.users),
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
	http.HandleFunc("/register", server.handleRegisterUI)
	http.HandleFunc("/auth/login-submit", server.handleLoginSubmit)
	http.HandleFunc("/auth/register-submit", server.handleRegisterSubmit)
	http.HandleFunc("/auth/login-direct", server.handleLoginDirect)
	http.HandleFunc("/auth/register-direct", server.handleRegisterDirect)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/status", server.handleGetStatus)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server di coordinamento WorldTunnel (con Database utenti) avviato sulla porta %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Errore all'avvio del server: %v", err)
	}
}
