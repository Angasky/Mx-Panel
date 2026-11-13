package web

import (
	"context"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"time"
)

// Enrich only the authenticated administrator inventory; never publish probe IPs.
func (s *Server) attachProbeRegions(ctx context.Context, servers []remote.Record) {
	var linked remote.Record
	for _, row := range servers {
		if probeLinked(row) {
			linked = row
			break
		}
	}
	if linked == nil {
		return
	}
	cfg, e := s.probeConfigFor(linked)
	if e != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	var clients []probeClient
	if s.probeCached(ctx, cfg, "/api/admin/client/list", 5*time.Minute, &clients) != nil {
		return
	}
	regions := map[string]string{}
	for _, c := range clients {
		regions[c.UUID] = c.Region
	}
	for _, row := range servers {
		if stringField(row, "probeSource") == cfg.URL {
			row["probeRegion"] = regions[stringField(row, "probeUUID")]
		}
	}
}
