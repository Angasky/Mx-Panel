package remote

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// Exercise UDP ASSOCIATE over a real SOCKS client core. The target only exists
// on loopback; no production server or public destination is used.
func socksUDPProbe(socks, destination string, payload []byte) error {
	control, err := net.DialTimeout("tcp", socks, time.Second)
	if err != nil {
		return err
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(control, reply); err != nil {
		return err
	}
	if !bytes.Equal(reply, []byte{5, 0}) {
		return errors.New("SOCKS authentication rejected")
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(control, header); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return errors.New("UDP association rejected")
	}
	size := 4
	if header[3] == 4 {
		size = 16
	} else if header[3] != 1 {
		return errors.New("unexpected UDP relay address")
	}
	address := make([]byte, size+2)
	if _, err = io.ReadFull(control, address); err != nil {
		return err
	}
	relay := &net.UDPAddr{IP: net.IP(address[:size]), Port: int(binary.BigEndian.Uint16(address[size:]))}
	if relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP("127.0.0.1")
	}
	if !relay.IP.IsLoopback() || relay.Port == 0 {
		return errors.New("non-loopback relay")
	}
	target, err := net.ResolveUDPAddr("udp4", destination)
	if err != nil {
		return err
	}
	packet := []byte{0, 0, 0, 1}
	packet = append(packet, target.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(target.Port))
	packet = append(packet, payload...)
	socket, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return err
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err = socket.Write(packet); err != nil {
		return err
	}
	buf := make([]byte, 65535)
	n, err := socket.Read(buf)
	if err != nil {
		return err
	}
	if n < 10 || !bytes.Equal(buf[:4], []byte{0, 0, 0, 1}) || !net.IP(buf[4:8]).Equal(target.IP) || binary.BigEndian.Uint16(buf[8:10]) != uint16(target.Port) || !bytes.Equal(buf[10:n], payload) {
		return errors.New("UDP response mismatch")
	}
	return nil
}
