package netprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"time"
)

// echo matches source, type, ID, sequence and a random payload. Other raw socket
// traffic must not turn a failed probe into a successful observation.
func echo(ctx context.Context, ip net.IP) (*float64, bool, string) {
	if ctx.Err() != nil {
		return nil, false, "cancelled"
	}
	network, address, protocol := "ip4:icmp", "0.0.0.0", 1
	var requestType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if ip.To4() == nil {
		network, address, protocol = "ip6:ipv6-icmp", "::", 58
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}
	socket, e := icmp.ListenPacket(network, address)
	if e != nil {
		return nil, false, "socket-unavailable"
	}
	defer socket.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	}
	socket.SetDeadline(deadline)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			socket.Close()
		case <-done:
		}
	}()
	nonce := make([]byte, 20)
	if _, e = rand.Read(nonce); e != nil {
		return nil, false, "local-error"
	}
	id, sequence := int(binary.BigEndian.Uint16(nonce[:2])), int(binary.BigEndian.Uint16(nonce[2:4]))
	packet, e := (&icmp.Message{Type: requestType, Code: 0, Body: &icmp.Echo{ID: id, Seq: sequence, Data: nonce[4:]}}).Marshal(nil)
	if e != nil {
		return nil, false, "local-error"
	}
	start := time.Now()
	if _, e = socket.WriteTo(packet, &net.IPAddr{IP: ip}); e != nil {
		return nil, false, "send-failed"
	}
	buffer := make([]byte, 1500)
	for {
		n, peer, e := socket.ReadFrom(buffer)
		if e != nil {
			if ctx.Err() != nil && ctx.Err() != context.DeadlineExceeded {
				return nil, true, "cancelled"
			}
			return nil, true, "timeout"
		}
		peerIP, ok := peer.(*net.IPAddr)
		if !ok || !peerIP.IP.Equal(ip) {
			continue
		}
		message, e := icmp.ParseMessage(protocol, buffer[:n])
		if e != nil || message.Type != replyType || message.Code != 0 {
			continue
		}
		body, ok := message.Body.(*icmp.Echo)
		if !ok || body.ID != id || body.Seq != sequence || !bytes.Equal(body.Data, nonce[4:]) {
			continue
		}
		elapsed := float64(time.Since(start).Microseconds()) / 1000
		return &elapsed, true, ""
	}
}
