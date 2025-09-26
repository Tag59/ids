package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Packet type represents a network packet
type Packet = gopacket.Packet

// StartCapture starts capturing packets on the specified network device
func StartCapture(device string, packetChan chan Packet) error {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}

	defer handle.Close()

	// Use the handle as a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}

	return nil
}

func ReadFromPcapFile(filepath string, packetChan chan Packet) error {
	handle, err := pcap.OpenOffline(filepath)
	if err != nil {
		return err
	}

	defer handle.Close()

	// Use the handle as a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}

	return nil
}
