package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/afpacket"
	"github.com/florianl/go-nfqueue"
)

const (
	fragSize = 512
	queueNum = 0
)

func main() {
	nfq, err := nfqueue.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer nfq.Close()

	if err := nfq.Bind(queueNum, nfqueue.AF_INET); err != nil {
		log.Fatal(err)
	}
	defer nfq.Unbind(queueNum)

	config := nfqueue.Config{
		QueueMaxLen: 10000,
		Copymode:    nfqueue.CopyPacket,
		Flags:       nfqueue.FailOpen,
	}
	if err := nfq.SetConfig(queueNum, config); err != nil {
		log.Fatal(err)
	}

	packets := nfq.GetPackets(queueNum)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case p := <-packets:
			handlePacket(nfq, p)
		case <-sigCh:
			return
		}
	}
}

func handlePacket(nfq *nfqueue.Nfqueue, p nfqueue.Packet) {
	pkt := gopacket.NewPacket(p.Payload, layers.LayerTypeIPv4, gopacket.Default)
	
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}
	
	ipv4 := ipLayer.(*layers.IPv4)
	
	var transport gopacket.Layer
	if ipv4.Protocol == layers.IPProtocolTCP {
		transport = pkt.Layer(layers.LayerTypeTCP)
	} else if ipv4.Protocol == layers.IPProtocolUDP {
		transport = pkt.Layer(layers.LayerTypeUDP)
	} else {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}
	
	if transport == nil {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	payload := transport.LayerPayload()
	if len(payload) <= fragSize {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	fragments := fragmentPayload(payload, fragSize)
	
	for i, frag := range fragments {
		newPkt := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		newIPv4 := *ipv4
		newIPv4.Flags = layers.IPv4MoreFragments
		if i == len(fragments)-1 {
			newIPv4.Flags = 0
		}
		newIPv4.FragOffset = uint16(i * fragSize / 8)

		var newTransport gopacket.SerializableLayer
		if ipv4.Protocol == layers.IPProtocolTCP {
			tcp := transport.(*layers.TCP)
			newTCP := *tcp
			newTCP.SetNetworkLayerForChecksum(&newIPv4)
			newTransport = &newTCP
		} else {
			udp := transport.(*layers.UDP)
			newUDP := *udp
			newUDP.SetNetworkLayerForChecksum(&newIPv4)
			newTransport = &newUDP
		}

		gopacket.SerializeLayers(newPkt, opts,
			&newIPv4,
			newTransport,
			gopacket.Payload(frag),
		)

		if i == 0 {
			p.SetVerdictModified(nfqueue.NF_ACCEPT, newPkt.Bytes())
		} else {
			nfq.Inject(newPkt.Bytes(), nfqueue.AF_INET)
		}
	}
}

func fragmentPayload(payload []byte, size int) [][]byte {
	var fragments [][]byte
	for i := 0; i < len(payload); i += size {
		end := i + size
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}
	return fragments
}