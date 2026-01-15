package bpf 

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)



// Config represents the top-level structure of your init.yaml
type Config struct {
	Interface     string `yaml:"interface"`
	Mode          string `yaml:"mode"`
	DefaultAction uint32  `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
}



// LoadConfig reads a YAML file and converts it into our Config struct
func LoadConfig(path string) (*Config, error) {
        file, err := os.ReadFile(path)
        if err != nil {
                return nil, fmt.Errorf("could not read config file: %w", err)
        }

        var rawCfg struct {
                Interface     string     `yaml:"interface"`
                Mode          string     `yaml:"mode"`
                DefaultAction uint32     `yaml:"default_action"`
                Rules         []YamlRule `yaml:"rules"`
        }

        if err := yaml.Unmarshal(file, &rawCfg); err != nil {
                return nil, fmt.Errorf("could not parse yaml: %w", err)
        }

        cfg := &Config{
                Interface:     rawCfg.Interface,
                Mode:          rawCfg.Mode,
                DefaultAction: rawCfg.DefaultAction,
                Rules:         make([]Rule, 0, len(rawCfg.Rules)),
        }

        for _, r := range rawCfg.Rules {
                ip, ipNet, err := net.ParseCIDR(r.SubnetAddr)
                if err != nil {
                        return nil, fmt.Errorf("invalid CIDR %s: %w", r.SubnetAddr, err)
                }

                ip = ip.To4()
                if ip == nil {
                        return nil, fmt.Errorf("only IPv4 is supported: %s", r.SubnetAddr)
                }

                maskLen, bits := ipNet.Mask.Size()
                if bits != 32 {
                        return nil, fmt.Errorf("invalid IPv4 mask: %s", r.SubnetAddr)
                }

                network := ip.Mask(ipNet.Mask)

                cfg.Rules = append(cfg.Rules, Rule{
                        Addr:    network,
                        Masklen: uint32(maskLen),
                        Port:    r.Port,
                        Proto:   r.Proto,
                        Action:  r.Action,
                })
        }

        return cfg, nil
}

