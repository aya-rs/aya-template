package main

import (
        "context"
        "fmt"
        "log"
        "net"
        "os"
        "os/signal"
        "syscall"
	"bytes"

        "github.com/cilium/ebpf"
        "github.com/cilium/ebpf/link"
        "github.com/cilium/ebpf/ringbuf"

	_ "embed"
)

const progName = "{{crate_name}}"

//go:embed .ebpf/{{project-name}}
var ebpfBytes []byte

func main() {
        if len(os.Args) < 2 {
                fmt.Printf("Usage: %s <interface>\n", os.Args[0])
                os.Exit(1)
        }
        ifaceName := os.Args[1]

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfBytes))
        if err != nil {
                log.Fatalf("LoadCollectionSpec failed: %v", err)
        }

        coll, err := ebpf.NewCollection(spec)
        if err != nil {
                log.Fatalf("NewCollection failed: %v", err)
        }
        defer coll.Close()

        prog := coll.Programs[progName]
        if prog == nil {
                log.Fatalf("Program %s not found", progName)
        }

        iface, err := net.InterfaceByName(ifaceName)
        if err != nil {
                log.Fatalf("Interface not found: %v", err)
        }

        l, err := link.AttachXDP(link.XDPOptions{
                Program:   prog,
                Interface: iface.Index,
        })
        if err != nil {
                log.Fatalf("AttachXDP failed: %v", err)
        }
        defer l.Close()
        fmt.Printf("✅ Program '%s' attached to %s\n", progName, ifaceName)

        logMap, ok := coll.Maps["AYA_LOGS"]
        if !ok {
                log.Fatal("AYA_LOGS map not found")
        }

        reader, err := ringbuf.NewReader(logMap)
        if err != nil {
                log.Fatalf("failed to create ringbuf reader: %v", err)
        }
        defer reader.Close()

        ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
        defer stop()

        go func() {
                fmt.Println("Listening to Aya logs...")
                for {
                        select {
                        case <-ctx.Done():
                                return
                        default:
                                record, err := reader.Read()
                                if err != nil {
                                        continue
                                }
                                fmt.Printf("Aya log: %s\n", string(record.RawSample))
                        }
                }
        }()

        <-ctx.Done()
        fmt.Println("Shutting down...")
}
