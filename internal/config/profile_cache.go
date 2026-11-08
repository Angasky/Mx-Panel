package config

// The digest is rechecked against file contents on every access. All access is
// under Repository.mu, and both generic and typed consumers receive copies.
type profileIndexEntry struct {
	digest   [32]byte
	document Document
	profiles []Profile
}

func cloneProfiles(profiles []Profile) []Profile {
	result := make([]Profile, len(profiles))
	for i, p := range profiles {
		p.Files = append([]string(nil), p.Files...)
		if p.Traffic != nil {
			p.Traffic = cloneConfig(p.Traffic).(Document)
		}
		if p.RemoteNodes != nil {
			p.RemoteNodes = cloneConfig(p.RemoteNodes).([]any)
		}
		if p.Failovers != nil {
			rows := make([]Document, len(p.Failovers))
			for i, row := range p.Failovers {
				rows[i] = cloneConfig(row).(Document)
			}
			p.Failovers = rows
		}
		if p.Plans != nil {
			rows := make([]Document, len(p.Plans))
			for i, row := range p.Plans {
				rows[i] = cloneConfig(row).(Document)
			}
			p.Plans = rows
		}
		p.LastEnforcedAt = cloneConfig(p.LastEnforcedAt)
		result[i] = p
	}
	return result
}
