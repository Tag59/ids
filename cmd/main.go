package main

import (
	"fmt"

	"github.com/Tag59/ids/internal/capture"
	"github.com/Tag59/ids/internal/detection"
)

func main() {
	// Channel to receive captured packets
	packetChan := make(chan capture.Packet)

	// Start packet capture in a separate goroutine
	// fmt.Println("Starting packet capture on device eth0...")
	// go capture.StartCapture("eth0", packetChan)
	// fmt.Println("Packet capture started.")

	fmt.Println("Reading packets from pcap file...")
	go capture.ReadFromPcapFile("captureTest/nmap_standard_scan", packetChan)
	fmt.Println("Reading packets from pcap file started.")

	// Process packets as they are captured
	for packet := range packetChan {
		// Process the packet (e.g., print its summary)
		if alert, detected := detection.ProcessPacket(packet); detected {
			fmt.Println("ALERT:", alert)
		}
	}
	fmt.Println("Reading packets from pcap file completed.")
}
