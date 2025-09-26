package detection

import (
	"sync"
	"time"

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

// ProcessPacket analyzes a packet and detects simple port scans
func ProcessPacket(pkt gopacket.Packet) (alert string, detected bool) {
	// Get network layer (IP) information
	ipLayer := pkt.NetworkLayer()
	if ipLayer == nil {
		return "", false
	}

	srcIP := ipLayer.NetworkFlow().Src().String()

	// Get TCP layer
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", false
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// We are interested only in SYN packets without ACK
	// (first step of the TCP 3-way handshake, typical of port scans)
	if tcp.SYN && !tcp.ACK {
		//fmt.Println("Detected SYN from", srcIP, "to port", tcp.DstPort) // Debug print

		mu.Lock()
		defer mu.Unlock()

		// Look up this source IP in the detection map
		det, exists := detections[srcIP]
		if !exists {
			// Initialize new entry if it's the first packet for this IP
			det = &Detection{
				ports: make(map[uint16]bool),
				last:  time.Now(),
			}
			detections[srcIP] = det
		}

		// Record this destination port if not already seen
		if !det.ports[uint16(tcp.DstPort)] {
			det.ports[uint16(tcp.DstPort)] = true
			det.count++
			det.last = time.Now()
		}

		// Threshold: if >100 unique ports in less than 10 seconds → alert
		if det.count > 100 && time.Since(det.last) < 10*time.Second {
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
