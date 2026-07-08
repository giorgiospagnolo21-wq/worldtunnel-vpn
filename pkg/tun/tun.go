package tun

// Config contiene i parametri per l'interfaccia TUN
type Config struct {
	Name string
	IP   string
	MTU  int
}

// Tuner definisce l'interfaccia per leggere/scrivere pacchetti IP
type Tuner interface {
	ReadPacket() ([]byte, error)
	WritePacket(packet []byte) error
	Close() error
	IP() string
}
