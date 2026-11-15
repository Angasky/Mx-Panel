package billing

import "time"

// NextResetDay returns a strictly future UTC calendar boundary. Short months
// clamp locally without changing the configured day for subsequent months.
func NextResetDay(now time.Time, day int) time.Time {
	now = now.UTC()
	boundary := func(month time.Month) time.Time {
		first := time.Date(now.Year(), month, 1, 0, 0, 0, 0, time.UTC)
		last := time.Date(first.Year(), first.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
		d := day
		if d > last {
			d = last
		}
		return time.Date(first.Year(), first.Month(), d, 0, 0, 0, 0, time.UTC)
	}
	next := boundary(now.Month())
	if !next.After(now) {
		next = boundary(now.Month() + 1)
	}
	return next
}
