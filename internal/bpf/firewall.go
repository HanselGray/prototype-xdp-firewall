package bpf 

import "github.com/cilium/ebpf"
import "net"

// Rule is used by AddRule and internal logic
type Rule struct {
    Addr   net.IP
    Masklen uint32
    Proto int32
    Port   uint32
    Action uint32
}

// YamlRule is used specifically for the config parser
type YamlRule struct {
    SubnetAddr string `yaml:"subnetAddr"`
    Proto  int32  `yaml:"proto"`
    Port   uint32 `yaml:"port"`
    Action uint32 `yaml:"action"`
}

type Firewall struct {
    ipTrie      *ebpf.Map
    policies    *ebpf.Map
    //stats       *ebpf.Map
    defaultAction *ebpf.Map

    prefixToID  map[string]uint32
    idToPrefix  map[uint32]xdp_packet_filterIpv4LpmKey
    nextID      uint32
}

func New(ipTrie, policies,	 defaultAction *ebpf.Map) *Firewall {
    return &Firewall{
        ipTrie:        ipTrie,
        policies:      policies,
        //stats:         stats,
        defaultAction: defaultAction,

        prefixToID: make(map[string]uint32),
        idToPrefix: make(map[uint32]xdp_packet_filterIpv4LpmKey),
        nextID:     1, // start IDs at 1 (0 is usually reserved)
    }
}

