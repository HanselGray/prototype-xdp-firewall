package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"fmt"
	"xdpfilter/internal/bpf"
	"xdpfilter/internal/rest"
)

func main() {
	fmt.Println("[BOOT] xdp-fw starting")
	// --- Initialize logging --- 
	logFile, err := os.OpenFile("/var/log/xdp-firewall.log",
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	log.Println("xdp-firewall starting")
	


	// --- Loading and parsing config ---
	cfg, err := bpf.LoadConfig("init.yaml")
	if err != nil {
		log.Fatalf("[fatal!] cannot load config, error: %v", err)
	}

	log.Printf("[success] config loaded")



	// --- Loading XDP data plane ---
	bpfHandle, err := bpf.LoadAndAttach(cfg.Interface, cfg.Mode)
	if err != nil {
		log.Fatalf("[fatal!] Failed to initialize BPF data-plane, error: %v", err)
	}
	defer bpfHandle.Close()

	log.Println("BPF dataplane loaded")
	


	// --- Initialize the control plane ---
	fw := bpf.New(
		bpfHandle.Objs.SubnetMap,
		bpfHandle.Objs.RuleMap,
		bpfHandle.Objs.DefaultActionMap,
	)	
	// --- Set default firewall action ---
	if err := fw.SetDefaultBehaviour(cfg.DefaultAction); err != nil {
		log.Fatalf("failed to set default action: %v", err)
	}
	log.Printf("default action set to %d", cfg.DefaultAction)

	//  --- Load initial rules ---
	for _, rule := range cfg.Rules {
		if err := fw.AddRule(rule); err != nil {
			log.Fatalf("failed to load rule: %v", err)
		}
	}
	log.Printf("loaded %d rules", len(cfg.Rules))
	


	// --- Setting up REST API server --- 
	api := rest.New(fw, bpfHandle)
	go func() {
		log.Println("REST API listening on :8080")
		if err := api.Listen(":8080"); err != nil {
			log.Fatalf("REST API failed: %v", err)
		}
	}()



	// --- Shutting down ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	<-sig
	log.Println("shutting down")
}

