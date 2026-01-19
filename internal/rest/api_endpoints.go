package rest 

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"fmt"
	"xdpfilter/internal/bpf"
)

// -----------------------
// --- Rules REST APIs ---
// -----------------------


type RuleRequest struct {
	Subnet string `json:"subnet"`
	Proto  int32  `json:"proto"`
	Port   uint32 `json:"port"`
	Action string  `json:"action"`
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.addRule(w, r)
	case http.MethodDelete:
		s.deleteRule(w, r)
	case http.MethodGet:
		s.listRules(w)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
        var req RuleRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, err.Error(), 400)
                return
        }
	fmt.Println("[API] Add rule endpoint hit")
        // --- NEW: parse and validate action string ---
        action, ok := ParseAction(req.Action)
        if !ok {
                http.Error(w, "action must be PASS or DROP", 400)
                return
        }
        // --------------------------------------------

        ip, ipnet, err := net.ParseCIDR(req.Subnet)
        if err != nil {
                http.Error(w, "invalid subnet", 400)
                return
        }

        // Force IPv4 and normalize
        ip = ip.To4()
        if ip == nil {
                http.Error(w, "only IPv4 is supported", 400)
                return
        }

        // Extract mask length
        maskLen, bits := ipnet.Mask.Size()
        if bits != 32 {
                http.Error(w, "invalid IPv4 mask", 400)
                return
        }

        // Compute canonical network address
        network := ip.Mask(ipnet.Mask)

        rule := bpf.Rule{
                Addr:    network,
                Masklen: uint32(maskLen),
                Port:    req.Port,
                Proto:   req.Proto,
                Action:  uint32(action),   // ← use parsed XDP value
        }

        if err := s.fw.AddRule(rule); err != nil {
                http.Error(w, err.Error(), 500)
                return
        }
	
        w.WriteHeader(http.StatusCreated)
}


func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
        var req RuleRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, err.Error(), 400)
                return
        }

        // --------------------------------------------

        ip, ipnet, err := net.ParseCIDR(req.Subnet)
        if err != nil {
                http.Error(w, "invalid subnet", 400)
                return
        }

        ip = ip.To4()
        if ip == nil {
                http.Error(w, "only IPv4 is supported", 400)
                return
        }

        maskLen, bits := ipnet.Mask.Size()
        if bits != 32 {
                http.Error(w, "invalid IPv4 mask", 400)
                return
        }

        network := ip.Mask(ipnet.Mask)

        rule := bpf.Rule{
                Addr:    network,
                Masklen: uint32(maskLen),
                Port:    req.Port,
                Proto:   req.Proto,
        }

        if err := s.fw.DeleteRule(rule); err != nil {
                http.Error(w, err.Error(), 500)
                return
        }

        w.WriteHeader(http.StatusOK)
}

func (s *Server) listRules(w http.ResponseWriter) {
	rules, err := s.fw.ListRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := make([]RuleRequest, 0, len(rules))

	for _, r := range rules {
		actionStr, ok := actionToString[r.Action]
		if !ok {
			actionStr = "UNKNOWN"
		}

		subnet := fmt.Sprintf("%s/%d", r.Addr.String(), r.Masklen)

		resp = append(resp, RuleRequest{
			Subnet: subnet,
			Port:   r.Port,
			Proto:  r.Proto,
			Action: actionStr,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
// -----------------------------------
// --- Default behaviour REST APIs ---
// -----------------------------------

type DefaultRequest struct {
        Action string `json:"action"`
}

func (s *Server) handleDefault(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getDefault(w)
	case http.MethodPost:
		s.setDefault(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}


func (s *Server) getDefault(w http.ResponseWriter) {
        action, err := s.fw.GetDefaultBehaviour()
        if err != nil {
                http.Error(w, err.Error(), 500)
                return
        }

        actionStr, ok := actionToString[action]
        if !ok {
                actionStr = "UNKNOWN"
        }

        json.NewEncoder(w).Encode(DefaultRequest{Action: actionStr})
}


func (s *Server) setDefault(w http.ResponseWriter, r *http.Request) {
        var req DefaultRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, err.Error(), 400)
                return
        }

        action, ok := stringToAction[strings.ToUpper(req.Action)]
        if !ok {
                http.Error(w, "invalid action (must be PASS or DROP)", 400)
                return
        }

        if err := s.fw.SetDefaultBehaviour(action); err != nil {
                http.Error(w, err.Error(), 500)
                return
        }

        w.WriteHeader(http.StatusOK)
}


// ------------------------
// --- Health check API ---
// ------------------------

type HealthStatus struct {
    Status      string  `json:"status"`
    XDPAttached bool    `json:"xdp_attached"`
    CPUPercent  float64 `json:"cpu_percent"`
    MemoryMB    uint64  `json:"memory_mb"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    cpuPct, err := getCPUPercent()
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    memMB, err := getMemMB()
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    attached := false
    if s.bpf != nil && s.bpf.Link != nil {
	    attached = true
    }

    health := HealthStatus{
	    Status:      "ok",
	    XDPAttached: attached,
	    CPUPercent:  cpuPct,
	    MemoryMB:    memMB,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(health)
}

