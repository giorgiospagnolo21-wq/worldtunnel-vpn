package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	Key       string          `json:"key"`
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

type Server struct {
	mu         sync.Mutex
	clients    map[string]map[string]*Client // key -> clientID -> Client
	assignedIP map[string]map[string]string   // key -> clientID -> VirtualIP
	ipPools    map[string][]string            // key -> []IPs
}

func NewServer() *Server {
	return &Server{
		clients:    make(map[string]map[string]*Client),
		assignedIP: make(map[string]map[string]string),
		ipPools:    make(map[string][]string),
	}
}

func (s *Server) getOrAssignIP(key, clientID, requestedIP string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Inizializza le mappe per la chiave se non esistono
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

	// Se ha già un IP assegnato in questo gruppo e non ne richiede uno nuovo specifico
	if ip, ok := s.assignedIP[key][clientID]; ok {
		if requestedIP == "" || requestedIP == ip {
			return ip, nil
		}
	}

	// Se ha richiesto un IP specifico
	if requestedIP != "" {
		// Controlla se quell'IP è già in uso da un ALTRO client
		for id, ip := range s.assignedIP[key] {
			if ip == requestedIP && id != clientID {
				return "", fmt.Errorf("l'IP virtuale %s è già occupato da un altro dispositivo", requestedIP)
			}
		}

		// Rimuove l'IP dal pool se presente
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

	// Assegnazione automatica dal pool
	pool := s.ipPools[key]
	if len(pool) == 0 {
		return "", fmt.Errorf("nessun IP virtuale disponibile nel pool di rete")
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
		log.Printf("[%s] Errore marshalling peer: %v", key, err)
		return
	}

	for _, client := range groupClients {
		err := client.Conn.WriteMessage(websocket.TextMessage, rawMsg)
		if err != nil {
			log.Printf("Errore invio peers a %s: %v", client.ID, err)
		}
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
	key := r.URL.Query().Get("key")
	requestedIP := r.URL.Query().Get("ip")

	if clientID == "" {
		log.Println("Connessione rifiutata: client ID mancante")
		return
	}
	if key == "" {
		key = "default_network"
	}

	virtualIP, err := s.getOrAssignIP(key, clientID, requestedIP)
	if err != nil {
		log.Printf("Connessione rifiutata per %s (chiave %s): %v", clientID, key, err)
		// Invia un messaggio di errore prima di chiudere la connessione
		errMsg, _ := json.Marshal(Message{Type: "register", Error: err.Error()})
		conn.WriteMessage(websocket.TextMessage, errMsg)
		return
	}

	client := &Client{
		ID:        clientID,
		VirtualIP: virtualIP,
		Key:       key,
		Conn:      conn,
	}

	s.mu.Lock()
	if _, ok := s.clients[key]; !ok {
		s.clients[key] = make(map[string]*Client)
	}
	if oldClient, ok := s.clients[key][clientID]; ok {
		oldClient.Conn.Close()
	}
	s.clients[key][clientID] = client
	s.mu.Unlock()

	log.Printf("Agent Connesso: %s | Account: '%s' | IP Virtuale: %s", clientID, key, virtualIP)

	regMsg := Message{
		Type: "register",
		IP:   virtualIP,
	}
	if err := conn.WriteJSON(regMsg); err != nil {
		s.removeClient(key, clientID)
		return
	}

	s.broadcastPeers(key)

	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Agent disconnesso %s (%s): %v", clientID, key, err)
			break
		}

		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "signal":
			s.routeSignal(key, clientID, msg)
		}
	}

	s.removeClient(key, clientID)
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

func main() {
	server := NewServer()

	http.HandleFunc("/ws", server.handleConnection)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server di coordinamento WorldTunnel (con supporto IP richiesto) avviato sulla porta %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Errore all'avvio del server: %v", err)
	}
}
