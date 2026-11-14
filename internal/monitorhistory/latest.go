package monitorhistory

// Latest reads the last observation without pruning or writing history. List
// views must not trigger collection or hide an old sample by expiring it.
func (s *Store) Latest(id string) (enabled bool, point *Point, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.read(id)
	if err != nil {
		return false, nil, err
	}
	for _, p := range state.Points {
		if point == nil || p.Time >= point.Time {
			copy := p
			point = &copy
		}
	}
	return state.Enabled, point, nil
}
