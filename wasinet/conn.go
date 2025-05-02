package wasinet

import (
	"github.com/asparkoffire/wasinet/wasinet/stdlib/wasip1syscall"
)

type sockaddr interface {
	Sockaddr() wasip1syscall.RawSocketAddress
}
