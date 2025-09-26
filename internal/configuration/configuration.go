package configuration

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface         *string `yaml:"interface"`
	Snaplen           *int32  `yaml:"snaplen"`
	Promiscuous       *bool   `yaml:"promiscuous"`
	Timeout           *int    `yaml:"timeout"`
	PortScanThreshold *int    `yaml:"portScanThreshold"`
	TimeWindowSeconds *int    `yaml:"timeWindowSeconds"`
	PcapFile          *string `yaml:"pcapFile"`
}

// LoadConfig reads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// FillDefaults sets default values for any nil fields in the Config
func FillDefaults(cfg *Config) {
	if cfg.Interface == nil {
		defaultInterface := "eth0"
		cfg.Interface = &defaultInterface
	}

	if cfg.Snaplen == nil {
		defaultSnaplen := int32(65535)
		cfg.Snaplen = &defaultSnaplen
	}

	if cfg.Promiscuous == nil {
		defaultPromiscuous := true
		cfg.Promiscuous = &defaultPromiscuous
	}

	if cfg.Timeout == nil {
		defaultTimeout := 0 // BlockForever
		cfg.Timeout = &defaultTimeout
	}

	if cfg.PortScanThreshold == nil {
		defaultThreshold := 100
		cfg.PortScanThreshold = &defaultThreshold
	}

	if cfg.TimeWindowSeconds == nil {
		defaultWindow := 10
		cfg.TimeWindowSeconds = &defaultWindow
	}

	if cfg.PcapFile == nil {
		defaultPcapFile := ""
		cfg.PcapFile = &defaultPcapFile
	}
}
