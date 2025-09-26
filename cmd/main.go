package main

import (
	"fmt"
	"log"

	"github.com/Tag59/ids/internal/configuration"
	"github.com/Tag59/ids/internal/detection"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	/// Load YAML config
	cfg, err := configuration.LoadConfig("internal/configuration/config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	if cfg == nil {
		log.Fatalf("Config is nil")
	}

	// Apply defaults for missing fields
	configuration.FillDefaults(cfg)

	// Print values to check that everything is loaded correctly
	fmt.Println("==== Configuration Loaded ====")
	fmt.Println("Interface        :", *cfg.Interface)
	fmt.Println("Snaplen          :", *cfg.Snaplen)
	fmt.Println("Promiscuous      :", *cfg.Promiscuous)
	fmt.Println("Timeout   :", *cfg.Timeout)
	fmt.Println("PortScanThreshold:", *cfg.PortScanThreshold)
	fmt.Println("TimeWindowSeconds:", *cfg.TimeWindowSeconds)
	fmt.Println("PcapFile  :", *cfg.PcapFile)
	fmt.Println("================================")

	// Open Packet Source
	var handle *pcap.Handle
	if *cfg.PcapFile != "" {
		handle, err = pcap.OpenOffline(*cfg.PcapFile)
		if err != nil {
			log.Fatalf("Error opening pcap file: %v", err)
		}
		fmt.Println("Reading from pcap file:", *cfg.PcapFile)
	} else {
		handle, err = pcap.OpenLive(*cfg.Interface, *cfg.Snaplen, *cfg.Promiscuous, pcap.BlockForever)
		if err != nil {
			log.Fatalf("Error opening device %s: %v", *cfg.Interface, err)
		}
		fmt.Println("Capturing on interface:", *cfg.Interface)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets
	for packet := range packetSource.Packets() {
		alert, detected := detection.ProcessPacketWithConfig(packet, cfg)
		if detected {
			fmt.Println(alert)
		}
	}

	fmt.Println("Packet processing finished.")
}
