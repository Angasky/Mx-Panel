package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

type coreStatsQueryKey struct{}
type coreStatsQuery func(context.Context, string) (string, error)
type coreStatsDial func(context.Context, string, string) (net.Conn, error)

const singStatsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"

// sing-box registers the V2Ray compatibility service name. Query it through the existing
// pinned SSH connection, without exposing the API or installing another tool.
func querySingStats(ctx context.Context, address string, dial coreStatsDial) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || dial == nil {
		return "", errCoreStats
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols, MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != address {
				return nil, errCoreStats
			}
			return dial(ctx, "tcp", address)
		}}
	defer transport.CloseIdleConnections()
	// Field 1 is the user prefix. Omit reset (field 2), so reads never clear counters.
	message := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "user>>>")
	frame := make([]byte, 5, 5+len(message))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
	frame = append(frame, message...)
	request, err := http.NewRequestWithContext(ctx, "POST", "http://"+address+singStatsMethod, bytes.NewReader(frame))
	if err != nil {
		return "", errCoreStats
	}
	request.Header.Set("Content-Type", "application/grpc+proto")
	request.Header.Set("TE", "trailers")
	request.Header.Set("Grpc-Timeout", "8000m")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return "", errCoreStats
	}
	defer response.Body.Close()
	contentType := response.Header.Get("Content-Type")
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 ||
		(contentType != "application/grpc" && contentType != "application/grpc+proto") {
		return "", errCoreStats
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 || len(raw) < 5 || raw[0] != 0 ||
		uint64(binary.BigEndian.Uint32(raw[1:5])) != uint64(len(raw)-5) {
		return "", errCoreStats
	}
	headerStatus, trailerStatus := response.Header.Get("Grpc-Status"), response.Trailer.Get("Grpc-Status")
	if len(response.Header.Values("Grpc-Status")) > 1 || len(response.Trailer.Values("Grpc-Status")) > 1 ||
		(headerStatus != "" && headerStatus != "0") || (trailerStatus != "" && trailerStatus != "0") ||
		(headerStatus == "" && trailerStatus == "") {
		return "", errCoreStats
	}
	return singStatsJSON(raw[5:])
}

func singStatsJSON(raw []byte) (string, error) {
	entries := []Record{}
	for len(raw) > 0 {
		number, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return "", errCoreStats
		}
		raw = raw[n:]
		if number != 1 {
			n = protowire.ConsumeFieldValue(number, kind, raw)
			if n < 0 {
				return "", errCoreStats
			}
			raw = raw[n:]
			continue
		}
		if kind != protowire.BytesType {
			return "", errCoreStats
		}
		entry, n := protowire.ConsumeBytes(raw)
		if n < 0 {
			return "", errCoreStats
		}
		raw = raw[n:]
		name, value, seenName, seenValue := "", uint64(0), false, false
		for len(entry) > 0 {
			field, wire, n := protowire.ConsumeTag(entry)
			if n < 0 {
				return "", errCoreStats
			}
			entry = entry[n:]
			switch field {
			case 1:
				if wire != protowire.BytesType || seenName {
					return "", errCoreStats
				}
				name, n = protowire.ConsumeString(entry)
				seenName = true
			case 2:
				if wire != protowire.VarintType || seenValue {
					return "", errCoreStats
				}
				value, n = protowire.ConsumeVarint(entry)
				seenValue = true
			default:
				n = protowire.ConsumeFieldValue(field, wire, entry)
			}
			if n < 0 {
				return "", errCoreStats
			}
			entry = entry[n:]
		}
		if !seenName || !utf8.ValidString(name) || value > math.MaxInt64 || !strings.HasPrefix(name, "user>>>") {
			return "", errCoreStats
		}
		entries = append(entries, Record{"name": name, "value": strconv.FormatUint(value, 10)})
	}
	encoded, err := json.Marshal(Record{"stat": entries})
	if err != nil {
		return "", errCoreStats
	}
	// Reuse the same strict duplicate-name and counter-shape validation as Xray.
	if _, err := parseCoreCounters(string(encoded)); err != nil {
		return "", err
	}
	return string(encoded), nil
}
