package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

{% if program_type == "xdp" %}
	"net"
{% endif %}

	"os"
	"os/signal"
{% if program_type == "tracepoint" %}
	"strings"
{% endif %}
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	_ "embed"
)

const progName = "{{crate_name}}"

{%- case program_type -%}
{%- when "tracepoint" %}
const defaultCategory = "{{tracepoint_category}}"
const defaultName = "{{tracepoint_name}}"
{%- when "xdp" %}
const defaultIface = "{{default_iface}}"
{%- endcase %}

//go:embed .ebpf/{{project-name}}
var ebpfBytes []byte

func extractPrintableStrings(raw []byte) []string {
	var result []string
	var current []byte

	for _, b := range raw {
		if b >= 0x20 && b <= 0x7E {
			current = append(current, b)
		} else {
			if len(current) > 0 {
				result = append(result, string(current))
				current = nil
			}
		}
	}

	if len(current) > 0 {
		result = append(result, string(current))
	}

	return result
}

func main() {
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

    {%- case program_type -%}
        {%- when "tracepoint" %}
        category := defaultCategory
        name := defaultName
	attachment := fmt.Sprintf("%s:%s", category, name)

        if len(os.Args) > 1 {
            attachment = os.Args[1]
            parts := strings.SplitN(attachment, ":", 2)
            if len(parts) != 2 {
                log.Fatalf("invalid attachment format: %s, expected category:name", attachment)
            }
            category, name = parts[0], parts[1]
        }

	tp, err := link.Tracepoint(category, name, prog, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()
        {%- when "xdp" %}
	attachment := defaultIface
	if len(os.Args) > 1 {
		attachment = os.Args[1]
	}
	iface, err := net.InterfaceByName(attachment)
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
    {%- endcase %}
	fmt.Printf("✅ Program '%s' attached to %s\n", progName, attachment)

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
				msg := extractPrintableStrings(record.RawSample)
				fmt.Printf("[INFO  %s] %s\n", msg[1], msg[len(msg)-1])
			}
		}
	}()

	<-ctx.Done()
	fmt.Println("Shutting down...")
}
