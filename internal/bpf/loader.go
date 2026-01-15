package bpf

import (
	"fmt"
	"net"
	"log"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf"
)

// BPF is the kernel-facing handle
type BPF struct {
	Objs *xdp_packet_filterObjects
	Link link.Link
}

// Getting XDP status post attachment

func getXDPStatus(lnk link.Link) (ebpf.ProgramID, *link.XDPInfo, error) {
    info, err := lnk.Info()
    if err != nil {
        return 0, nil, err
    }

    xdp := info.XDP()
    if xdp == nil {
        return 0, nil, fmt.Errorf("link is not XDP")
    }

    return info.Program, xdp, nil
}

// LoadAndAttach loads the eBPF object and attaches XDP
func LoadAndAttach(ifaceName string, mode string) (*BPF, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Printf("[fatal!] Cannot find interface with if_name: %s", ifaceName)
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Load BPF into kernel
	objs := xdp_packet_filterObjects{}
	if err := loadXdp_packet_filterObjects(&objs, nil); err != nil {
		log.Printf("[fatal!] Cannot load eBPF program: %v", err)
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Select XDP mode
	var flags link.XDPAttachFlags

	switch mode {
	case "native":
		flags = link.XDPDriverMode
	case "skb":
		flags = link.XDPGenericMode
		default: // auto / unspecified
		flags = link.XDPGenericMode
	}

	// Attach XDP
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPacketFilter,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		log.Printf("ERROR attaching XDP: %v", err)
		objs.Close()
		return nil, fmt.Errorf("[fatal!] cannot attach XDP: %w", err)
	}

	//Emit a log if attachment successful
	
	programId, xdpStatus, err := getXDPStatus(lnk)
	if err!= nil {
		fmt.Println("[warning] failed to obtain XDP program metadata: %v", err)
		log.Printf("[warning] failed to obtain XDP program metadata: %v", err)
	} else {
		fmt.Println("[success] xdp program attached: if_index: %d, if_name: %s, xdp_prog_id: %d", xdpStatus.Ifindex, iface.Name, programId)
		log.Printf("[success] xdp program attached: if_index: %d, if_name: %s, xdp_prog_id: %d", xdpStatus.Ifindex, iface, programId)
	}

	return &BPF{
		Objs: &objs,
		Link: lnk,
	}, nil
}

// Close detaches XDP and frees maps/programs
func (b *BPF) Close() {
	if b.Link != nil {
		b.Link.Close()
	}
	if b.Objs != nil {
		b.Objs.Close()
	}
}

