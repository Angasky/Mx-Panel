package config

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
)

var ErrSubscriptionMissing = errors.New("订阅不存在")
var ErrSubscriptionBlocked = errors.New("订阅已过期或流量已用尽")

type Subscription struct {
	Name, Slug string
	Document   Document
	Raw        []byte
	Traffic    Document
	Userinfo   string
}

// PublicSubscription resolves capability tokens only. Profile IDs, old index
// paths and HTTP profile headers never authorize a public subscription read.
func (r *Repository) PublicSubscription(slug string, now time.Time) (Subscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slugPattern.MatchString(slug) {
		return Subscription{}, ErrSubscriptionMissing
	}
	index, err := r.index()
	if err != nil {
		return Subscription{}, err
	}
	var record Document
	for _, v := range index["profiles"].([]any) {
		p := v.(map[string]any)
		if subtle.ConstantTimeCompare([]byte(stringValue(p["slug"])), []byte(slug)) == 1 {
			if record != nil {
				return Subscription{}, errors.New("订阅标识重复")
			}
			record = p
		}
	}
	if record == nil {
		return Subscription{}, ErrSubscriptionMissing
	}
	return r.subscriptionRecord(record, now)
}

func (r *Repository) subscriptionRecord(record Document, now time.Time) (Subscription, error) {
	info, err := TrafficInfo(record, now)
	if err != nil {
		return Subscription{}, err
	}
	if record["accessRevoked"] == true || info["configured"] == true && info["enforce"] == true && (info["expired"] == true || info["exhausted"] == true) {
		return Subscription{}, ErrSubscriptionBlocked
	}
	p, err := profileFrom(record)
	if err != nil || len(p.Files) == 0 {
		return Subscription{}, ErrSubscriptionMissing
	}
	doc, raw, err := r.cachedRead(p)
	if err != nil {
		return Subscription{}, err
	}
	u := billing.Usage{Enabled: info["configured"] == true, Upload: info["upload"].(int64), Download: info["download"].(int64)}
	if value, ok := info["total"].(int64); ok {
		u.Total = &value
	}
	if value, ok := info["expire"].(int64); ok {
		u.Expire = &value
	}
	header, err := u.Userinfo()
	if err != nil {
		return Subscription{}, err
	}
	return Subscription{Name: p.Name, Slug: p.Slug, Document: cloneConfig(doc).(Document), Raw: raw, Traffic: info, Userinfo: header}, nil
}

// ConversionSource is an authenticated management read. It remains available
// when expired so the administrator can inspect compatibility before renewal.
func (r *Repository) ConversionSource(id string, now time.Time) (Subscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return Subscription{}, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return Subscription{}, err
	}
	copy := Document{}
	for key, value := range record {
		copy[key] = value
	}
	copy["accessRevoked"] = false
	if t, ok := record["traffic"].(map[string]any); ok {
		next := Document{}
		for key, value := range t {
			next[key] = value
		}
		next["enforce"] = false
		copy["traffic"] = next
	}
	return r.subscriptionRecord(copy, now)
}
