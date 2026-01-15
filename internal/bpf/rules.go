package bpf 

import ( "net"
	 "fmt"
	 "encoding/binary"
 	 "github.com/cilium/ebpf"
 )


// ------------------------
// --- Helper functions ---
// ------------------------
func (fw *Firewall) lookupPolicyID(ip net.IP, masklen uint32) (uint32, error) {
	key := xdp_packet_filterIpv4LpmKey{
		Prefixlen: masklen,
		Addr:      binary.BigEndian.Uint32(ip.To4()),
	}

	var policyID uint32
	err := fw.ipTrie.Lookup(&key, &policyID)
	if err != nil {
		return 0, err
	}
	return policyID, nil
}


func (fw *Firewall) updateRule(policyID uint32, r Rule) error {
	key := xdp_packet_filterRuleId{
		SubnetId: policyID,
		Proto:    int32(r.Proto),
		Port:     r.Port,
	}
	return fw.policies.Update(&key, &r.Action, ebpf.UpdateAny)
}


func (fw *Firewall) deleteRule(policyID uint32, r Rule) error {
	key := xdp_packet_filterRuleId{
		SubnetId: policyID,
		Proto:    int32(r.Proto),
		Port:     r.Port,
	}

	return fw.policies.Delete(&key)
}



// -----------------------------------------------------------
// --- CRUD function for maps, these are called by the API ---
// -----------------------------------------------------------
func (fw *Firewall) AddRule(r Rule) error {
        fmt.Println("--------------------------------------------------")
        fmt.Println("[AddRule] called")
        fmt.Printf("[AddRule] Rule: Addr=%s Masklen=%d Port=%d Proto=%d Action=%d\n",
                r.Addr, r.Masklen, r.Port, r.Proto, r.Action)

        if r.Addr == nil || r.Addr.To4() == nil {
                fmt.Println("[AddRule] ERROR: not IPv4")
                return fmt.Errorf("only IPv4 is supported")
        }
        if r.Masklen > 32 {
                fmt.Println("[AddRule] ERROR: invalid masklen")
                return fmt.Errorf("invalid mask length %d", r.Masklen)
        }

        // Canonical network address
        mask := net.CIDRMask(int(r.Masklen), 32)
        network := r.Addr.Mask(mask)

        fmt.Printf("[AddRule] Canonical network: %s/%d\n", network.String(), r.Masklen)

        // Stable prefix key
        prefix := fmt.Sprintf("%s/%d", network.String(), r.Masklen)
        fmt.Printf("[AddRule] Prefix string: %s\n", prefix)

        policyID, exists := fw.prefixToID[prefix]
        fmt.Printf("[AddRule] prefix exists? %v\n", exists)

        if !exists {
                policyID = fw.nextID
                fw.nextID++

                fmt.Printf("[AddRule] Allocated new policyID = %d\n", policyID)

                // Kernel LPM key
                lpmKey := xdp_packet_filterIpv4LpmKey{
                        Prefixlen: r.Masklen,
                        Addr:      binary.BigEndian.Uint32(network.To4()),
                }

                fmt.Printf("[AddRule] LPM key: Prefixlen=%d Addr(hex)=0x%08x Addr(uint32)=%d\n",
                        lpmKey.Prefixlen, lpmKey.Addr, lpmKey.Addr)

                if err := fw.ipTrie.Update(&lpmKey, &policyID, ebpf.UpdateNoExist); err != nil {
                        fmt.Println("[AddRule] ERROR: ipTrie.Update failed")
                        return fmt.Errorf("failed to insert prefix into LPM trie: %w", err)
                }

                fmt.Println("[AddRule] Inserted into kernel LPM trie")

                fw.prefixToID[prefix] = policyID
                fw.idToPrefix[policyID] = lpmKey

                fmt.Println("[AddRule] Updated control-plane caches")
        } else {
                fmt.Printf("[AddRule] Using existing policyID = %d\n", policyID)
        }

        fmt.Println("[AddRule] Installing L4 rule")
        err := fw.updateRule(policyID, r)
        if err != nil {
                fmt.Println("[AddRule] ERROR: updateRule failed")
        } else {
                fmt.Println("[AddRule] updateRule succeeded")
        }

        fmt.Println("--------------------------------------------------")
        return err
}

func (fw *Firewall) DeleteRule(r Rule) error {
        fmt.Println("--------------------------------------------------")
        fmt.Println("[DeleteRule] called")
        fmt.Printf("[DeleteRule] Rule: Addr=%s Masklen=%d Port=%d Proto=%d Action=%d\n",
                r.Addr, r.Masklen, r.Port, r.Proto)

        if r.Addr == nil || r.Addr.To4() == nil {
                fmt.Println("[DeleteRule] ERROR: not IPv4")
                return fmt.Errorf("only IPv4 is supported")
        }
        if r.Masklen > 32 {
                fmt.Println("[DeleteRule] ERROR: invalid masklen")
                return fmt.Errorf("invalid mask length %d", r.Masklen)
        }

        // Canonical network
        mask := net.CIDRMask(int(r.Masklen), 32)
        network := r.Addr.Mask(mask)

        fmt.Printf("[DeleteRule] Canonical network: %s/%d\n", network.String(), r.Masklen)

        // Stable prefix key
        prefix := fmt.Sprintf("%s/%d", network.String(), r.Masklen)
        fmt.Printf("[DeleteRule] Prefix string: %s\n", prefix)

        policyID, exists := fw.prefixToID[prefix]
        fmt.Printf("[DeleteRule] prefix exists? %v\n", exists)

        if !exists {
                fmt.Println("[DeleteRule] ERROR: subnet not found in control-plane cache")
                return fmt.Errorf("policyID matching subnet %s/%d not found", network.String(), r.Masklen)
        }

        fmt.Printf("[DeleteRule] Using policyID = %d\n", policyID)
        fmt.Println("[DeleteRule] Deleting L4 rule")

        if err := fw.deleteRule(policyID, r); err != nil {
                fmt.Println("[DeleteRule] ERROR: deleteRule failed")
                return fmt.Errorf("failed to delete rule: %w", err)
        }

        fmt.Println("[DeleteRule] deleteRule succeeded")
        fmt.Println("--------------------------------------------------")
        return nil
}


func (fw *Firewall) ListRules() ([]Rule, error) {
	var rules []Rule

	iter := fw.policies.Iterate()
	var key xdp_packet_filterRuleId
	var action uint32

	for iter.Next(&key, &action) {
		prefix, ok := fw.idToPrefix[key.SubnetId]
		if !ok {
			continue
		}

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, prefix.Addr)

		rules = append(rules, Rule{
			Addr:    ip,
			Masklen: prefix.Prefixlen,
			Port:    key.Port,
			Proto:   key.Proto,
			Action:  action,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}


// These functions defined default behaviour of the firewall
func (fw *Firewall) SetDefaultBehaviour(action uint32) error {
	var key uint32 = 0
	return fw.defaultAction.Update(&key, &action, ebpf.UpdateAny)
}

func (fw *Firewall) GetDefaultBehaviour() (uint32, error) {
	var key uint32 = 0
	var val uint32

	if err := fw.defaultAction.Lookup(&key, &val); err != nil {
		return 0, err
	}

	return val, nil
}


func (fw *Firewall) Flush() error {
	// delete everything from maps
	return nil
}

