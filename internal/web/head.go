package web

import "net/http"

// HEAD follows the same authentication and routing as GET, but never sends a
// response body (including errors). The original request remains unchanged.
type headResponse struct{ http.ResponseWriter }

func (w headResponse) Write(body []byte) (int, error) { return len(body), nil }
