package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/bi-zone/etw"
	"golang.org/x/sys/windows"
)

func main() {
	// Subscribe to Microsoft-Windows-DNS-Client
	guid, _ := windows.GUIDFromString("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
	session, err := etw.NewSession(guid)
	if err != nil {
		log.Fatalf("Failed to create etw session: %s", err)
	}

	// Wait for "DNS query request" events to log outgoing DNS requests.
	cb := func(e *etw.Event) {
		if e.Header.ID != 3006 {
			return
		}
		if data, err := e.EventProperties(); err == nil && data["QueryType"] == "1" {
			log.Printf("PID %d just queried DNS for domain %v", e.Header.ProcessID, data["QueryName"])
		}
	}

	// `session.Process` blocks until `session.Close()`, so start it in routine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := session.Process(cb); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		}
		wg.Done()
	}()

	// Trap cancellation.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh

	if err := session.Close(); err != nil {
		log.Printf("[ERR] Got error closing the session: %s", err)
	}
	wg.Wait()
}

