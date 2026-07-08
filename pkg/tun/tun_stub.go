//go:build !windows

package tun

import (
	"errors"
)

type StubDevice struct {
	cfg Config
}

func CreateDevice(cfg Config) (Tuner, error) {
	return nil, errors.New("supporto TUN implementato solo per Windows in questo prototipo")
}

func (d *StubDevice) ReadPacket() ([]byte, error) {
	return nil, errors.New("non implementato")
}

func (d *StubDevice) WritePacket(packet []byte) error {
	return errors.New("non implementato")
}

func (d *StubDevice) Close() error {
	return nil
}

func (d *StubDevice) IP() string {
	return d.cfg.IP
}
