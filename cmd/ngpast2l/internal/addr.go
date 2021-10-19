package internal

import "net"

type Addr struct {
	Network,
	Address string
}

func (a Addr) Listen() (net.Listener, error) {
	return net.Listen(a.Network, a.Address)
}
