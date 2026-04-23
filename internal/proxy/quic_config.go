package proxy

import (
	"time"

	"github.com/quic-go/quic-go"
)

const (
	defaultInitialStreamReceiveWindow     = 2 << 20  // 2 MiB
	defaultMaxStreamReceiveWindow         = 16 << 20 // 16 MiB
	defaultInitialConnectionReceiveWindow = 4 << 20  // 4 MiB
	defaultMaxConnectionReceiveWindow     = 64 << 20 // 64 MiB
)

// DefaultQUICConfig returns a QUIC configuration tuned for sustained proxy
// traffic instead of short-lived request / response workloads.
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		Allow0RTT:                      true,
		InitialStreamReceiveWindow:     defaultInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         defaultMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: defaultInitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     defaultMaxConnectionReceiveWindow,
	}
}
