package rest

import (
	"log"
	"net/http"

	"xdpfilter/internal/bpf"
)

type Server struct {
	fw  *bpf.Firewall
	bpf *bpf.BPF
	mux *http.ServeMux
}

func New(fw *bpf.Firewall, bpfHandle *bpf.BPF) *Server {
	s := &Server{
		fw:  fw,
		bpf: bpfHandle,
		mux: http.NewServeMux(),
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/rules", s.handleRules)
	s.mux.HandleFunc("/default", s.handleDefault)
	//s.mux.HandleFunc("/stats", s.handleStats)
	s.mux.HandleFunc("/health", s.handleHealth)
}

func (s *Server) Listen(addr string) error {
	log.Printf("Starting REST server on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

