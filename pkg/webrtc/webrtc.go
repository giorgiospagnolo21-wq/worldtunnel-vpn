package webrtc

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
)

// SignalMessage definisce la struttura dei messaggi scambiati tramite il server
type SignalMessage struct {
	Type string `json:"type"` // "offer", "answer", "candidate"
	SDP  string `json:"sdp,omitempty"`
	Cand string `json:"cand,omitempty"`
}

// Peer rappresenta una connessione a un altro PC
type Peer struct {
	ID          string
	VirtualIP   string
	Connection  *webrtc.PeerConnection
	DataChannel *webrtc.DataChannel
	IsReady     bool
	LastActive  time.Time
}

type Manager struct {
	mu            sync.RWMutex
	peers         map[string]*Peer        // peerID -> Peer
	ipToPeer      map[string]string       // virtualIP -> peerID
	localID       string
	localIP       string
	onSignaling   func(target string, msgType string, data []byte)
	onPacket      func(packet []byte)
	webrtcAPI     *webrtc.API
	webrtcConfig  webrtc.Configuration
}

func NewManager(localID string, localIP string, onSignaling func(target, msgType string, data []byte), onPacket func([]byte)) (*Manager, error) {
	// Usiamo i server STUN pubblici di Google per il NAT traversal
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{
					"stun:stun.l.google.com:19302",
					"stun:stun1.l.google.com:19302",
					"stun:stun2.l.google.com:19302",
				},
			},
		},
	}

	// Creiamo l'API WebRTC di Pion
	s := webrtc.SettingEngine{}
	// Abilitiamo il loopback per testare più client sulla stessa macchina
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))

	return &Manager{
		peers:        make(map[string]*Peer),
		ipToPeer:     make(map[string]string),
		localID:      localID,
		localIP:      localIP,
		onSignaling:  onSignaling,
		onPacket:     onPacket,
		webrtcAPI:    api,
		webrtcConfig: config,
	}, nil
}

func (m *Manager) UpdateLocalIP(ip string) {
	m.mu.Lock()
	m.localIP = ip
	m.mu.Unlock()
}

// GetPeersList restituisce lo stato corrente delle connessioni peer
type PeerStatus struct {
	ID        string `json:"id"`
	VirtualIP string `json:"virtual_ip"`
	Connected bool   `json:"connected"`
}

func (m *Manager) GetPeersStatus() []PeerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]PeerStatus, 0, len(m.peers))
	for _, p := range m.peers {
		list = append(list, PeerStatus{
			ID:        p.ID,
			VirtualIP: p.VirtualIP,
			Connected: p.IsReady && p.DataChannel != nil && p.DataChannel.ReadyState() == webrtc.DataChannelStateOpen,
		})
	}
	return list
}

// AddPeer inizializza la connessione verso un nuovo peer scoperto
func (m *Manager) AddPeer(peerID string, virtualIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.peers[peerID]; exists {
		return // Già registrato
	}

	log.Printf("[WebRTC] Aggiunta del peer %s (%s)...", peerID, virtualIP)
	m.peers[peerID] = &Peer{
		ID:        peerID,
		VirtualIP: virtualIP,
	}
	m.ipToPeer[virtualIP] = peerID
}

// RemovePeer rimuove e chiude la connessione con un peer disconnesso
func (m *Manager) RemovePeer(peerID string) {
	m.mu.Lock()
	peer, exists := m.peers[peerID]
	if !exists {
		m.mu.Unlock()
		return
	}

	delete(m.peers, peerID)
	delete(m.ipToPeer, peer.VirtualIP)
	m.mu.Unlock()

	if peer.Connection != nil {
		peer.Connection.Close()
	}
	log.Printf("[WebRTC] Peer %s rimosso e connessione chiusa.", peerID)
}

// InitiateConnection invia un'offerta WebRTC al peer specificato
func (m *Manager) InitiateConnection(peerID string) error {
	m.mu.Lock()
	peer, exists := m.peers[peerID]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("peer non registrato: %s", peerID)
	}

	// Creiamo la PeerConnection
	peerConn, err := m.webrtcAPI.NewPeerConnection(m.webrtcConfig)
	if err != nil {
		return fmt.Errorf("errore creazione peer connection: %w", err)
	}

	peer.Connection = peerConn

	// Creiamo il data channel per il traffico VPN (non ordinato, non affidabile per ottimizzare i flussi TCP superiori)
	// ordered = false, maxRetransmits = 0 simula al meglio un canale UDP grezzo
	ordered := false
	var maxRetransmits uint16 = 0
	dcInit := &webrtc.DataChannelInit{
		Ordered:        &ordered,
		MaxRetransmits: &maxRetransmits,
	}

	dataChannel, err := peerConn.CreateDataChannel("vpn-traffic", dcInit)
	if err != nil {
		peerConn.Close()
		return fmt.Errorf("errore creazione data channel: %w", err)
	}

	m.setupDataChannel(peerID, dataChannel)

	// Callback per candidati ICE
	peerConn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		candJSON, err := json.Marshal(c.ToJSON())
		if err != nil {
			return
		}
		m.onSignaling(peerID, "candidate", candJSON)
	})

	// Crea l'offerta SDP
	offer, err := peerConn.CreateOffer(nil)
	if err != nil {
		peerConn.Close()
		return fmt.Errorf("errore creazione offerta: %w", err)
	}

	err = peerConn.SetLocalDescription(offer)
	if err != nil {
		peerConn.Close()
		return fmt.Errorf("errore set local description: %w", err)
	}

	offerJSON, err := json.Marshal(offer)
	if err != nil {
		peerConn.Close()
		return fmt.Errorf("errore marshalling offerta: %w", err)
	}

	m.onSignaling(peerID, "offer", offerJSON)
	return nil
}

// HandleSignal elabora i messaggi di segnalazione in arrivo (Offer, Answer, Candidate)
func (m *Manager) HandleSignal(senderID string, signalType string, signalData []byte) error {
	m.mu.Lock()
	peer, exists := m.peers[senderID]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("ricevuto segnale da peer non registrato: %s", senderID)
	}

	switch signalType {
	case "offer":
		var offer webrtc.SessionDescription
		if err := json.Unmarshal(signalData, &offer); err != nil {
			return err
		}

		peerConn, err := m.webrtcAPI.NewPeerConnection(m.webrtcConfig)
		if err != nil {
			return err
		}
		peer.Connection = peerConn

		// Callback candidati ICE
		peerConn.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				return
			}
			candJSON, err := json.Marshal(c.ToJSON())
			if err != nil {
				return
			}
			m.onSignaling(senderID, "candidate", candJSON)
		})

		// Gestiamo il data channel in entrata
		peerConn.OnDataChannel(func(dc *webrtc.DataChannel) {
			m.setupDataChannel(senderID, dc)
		})

		if err := peerConn.SetRemoteDescription(offer); err != nil {
			peerConn.Close()
			return err
		}

		// Crea risposta SDP
		answer, err := peerConn.CreateAnswer(nil)
		if err != nil {
			peerConn.Close()
			return err
		}

		if err := peerConn.SetLocalDescription(answer); err != nil {
			peerConn.Close()
			return err
		}

		answerJSON, err := json.Marshal(answer)
		if err != nil {
			peerConn.Close()
			return err
		}

		m.onSignaling(senderID, "answer", answerJSON)

	case "answer":
		if peer.Connection == nil {
			return fmt.Errorf("ricevuta risposta ma nessuna connessione attiva per %s", senderID)
		}
		var answer webrtc.SessionDescription
		if err := json.Unmarshal(signalData, &answer); err != nil {
			return err
		}
		return peer.Connection.SetRemoteDescription(answer)

	case "candidate":
		if peer.Connection == nil {
			return fmt.Errorf("ricevuto candidato ICE ma nessuna connessione per %s", senderID)
		}
		var candidate webrtc.ICECandidateInit
		if err := json.Unmarshal(signalData, &candidate); err != nil {
			return err
		}
		return peer.Connection.AddICECandidate(candidate)
	}

	return nil
}

func (m *Manager) setupDataChannel(peerID string, dc *webrtc.DataChannel) {
	m.mu.Lock()
	peer, exists := m.peers[peerID]
	if exists {
		peer.DataChannel = dc
	}
	m.mu.Unlock()

	if !exists {
		dc.Close()
		return
	}

	dc.OnOpen(func() {
		log.Printf("[WebRTC] Canale dati aperto con successo con il peer %s!", peerID)
		m.mu.Lock()
		peer.IsReady = true
		peer.LastActive = time.Now()
		m.mu.Unlock()
	})

	dc.OnClose(func() {
		log.Printf("[WebRTC] Canale dati chiuso con il peer %s.", peerID)
		m.mu.Lock()
		peer.IsReady = false
		m.mu.Unlock()
	})

	dc.OnError(func(err error) {
		log.Printf("[WebRTC] Errore sul canale dati con %s: %v", peerID, err)
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		m.mu.Lock()
		peer.LastActive = time.Now()
		m.mu.Unlock()
		
		// Inietta il pacchetto di rete ricevuto nel driver TUN locale
		m.onPacket(msg.Data)
	})
}

// SendPacket inoltra un pacchetto IP cifrato al peer corretto
func (m *Manager) SendPacket(dstIP string, packet []byte) bool {
	m.mu.RLock()
	peerID, exists := m.ipToPeer[dstIP]
	if !exists {
		m.mu.RUnlock()
		return false // Destinatario non registrato
	}

	peer, exists := m.peers[peerID]
	m.mu.RUnlock()

	if !exists || !peer.IsReady || peer.DataChannel == nil || peer.DataChannel.ReadyState() != webrtc.DataChannelStateOpen {
		return false // Peer disconnesso o canale non pronto
	}

	err := peer.DataChannel.Send(packet)
	if err != nil {
		log.Printf("[WebRTC] Errore durante l'invio del pacchetto a %s (%s): %v", peerID, dstIP, err)
		return false
	}
	return true
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, peer := range m.peers {
		if peer.Connection != nil {
			peer.Connection.Close()
		}
		delete(m.peers, id)
	}
	m.ipToPeer = make(map[string]string)
}

