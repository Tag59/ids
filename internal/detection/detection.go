package detection

import (
	"sync"
	"time"

	"github.com/Tag59/ids/internal/configuration"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Detection holds tracking information for a single source IP
type Detection struct {
	ports map[uint16]bool // Set of contacted destination ports
	count int             // Number of unique ports contacted
	last  time.Time       // Last time we saw activity
}

var (
	detections = make(map[string]*Detection) // Global map: source IP -> Detection info
	mu         sync.Mutex                    // Mutex for concurrent access
)

// ProcessPacket: core logic with default thresholds (100 ports, 10s)
func ProcessPacket(pkt gopacket.Packet) (alert string, detected bool) {
	const defaultThreshold = 100
	const defaultWindow = 10
	return processPacketWithThreshold(pkt, defaultThreshold, defaultWindow)
}

// processPacketWithThreshold: core logic, threshold and time window are parameters
func processPacketWithThreshold(pkt gopacket.Packet, portScanThreshold int, timeWindowSeconds int) (alert string, detected bool) {
	ipLayer := pkt.NetworkLayer()
	if ipLayer == nil {
		return "", false
	}

	srcIP := ipLayer.NetworkFlow().Src().String()

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", false
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	if tcp.SYN && !tcp.ACK {
		mu.Lock()
		defer mu.Unlock()

		det, exists := detections[srcIP]
		if !exists {
			det = &Detection{
				ports: make(map[uint16]bool),
				last:  time.Now(),
			}
			detections[srcIP] = det
		}

		if !det.ports[uint16(tcp.DstPort)] {
			det.ports[uint16(tcp.DstPort)] = true
			det.count++
			det.last = time.Now()
		}

		if det.count >= portScanThreshold && time.Since(det.last) <= time.Duration(timeWindowSeconds)*time.Second {
			alert = "Port scan detected from " + srcIP
			detected = true

			// Reset the tracker to avoid spamming alerts
			detections[srcIP] = &Detection{
				ports: make(map[uint16]bool),
				last:  time.Now(),
			}
			return alert, detected
		}
	}

	return "", false
}

// ProcessPacketWithConfig: wrapper that uses config from YAML
func ProcessPacketWithConfig(pkt gopacket.Packet, cfg *configuration.Config) (alert string, detected bool) {
	return processPacketWithThreshold(pkt, *cfg.PortScanThreshold, *cfg.TimeWindowSeconds)
}
