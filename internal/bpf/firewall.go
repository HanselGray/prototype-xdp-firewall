package bpf 

import ("github.com/cilium/ebpf"
	"net"
	"time"
)

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
    // ---- eBPF objects ----
    ipTrie        *ebpf.Map
    policies      *ebpf.Map
    // stats       *ebpf.Map
    defaultAction *ebpf.Map

    // ---- Control-plane state ----
    prefixToID map[string]uint32
    idToPrefix map[uint32]xdp_packet_filterIpv4LpmKey
    nextID     uint32

    // ---- Health / runtime info ----
    startTime time.Time

    // Cached system metrics (updated by control plane)
    cpuUsagePercent float64
    memUsageMB      uint64

    // Status flags
    xdpAttached bool
	
}

func New(ipTrie, policies, defaultAction *ebpf.Map) *Firewall {
    return &Firewall{
        ipTrie:        ipTrie,
        policies:      policies,
        defaultAction: defaultAction,

        prefixToID: make(map[string]uint32),
        idToPrefix: make(map[uint32]xdp_packet_filterIpv4LpmKey),
        nextID:     1,

    }
}

