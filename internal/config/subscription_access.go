package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

var ErrSubscriptionIPDenied = errors.New("当前 IP 不在订阅访问白名单中")

type SubscriptionAccess struct {
	Enabled  bool     `json:"enabled"`
	Networks []string `json:"networks"`
}

func normalizeSubscriptionAccess(input SubscriptionAccess) (SubscriptionAccess, error) {
	result := SubscriptionAccess{Enabled: input.Enabled, Networks: []string{}}
	if len(input.Networks) > 64 {
		return result, errors.New("最多允许 64 个 IP 或网段")
	}
	seen := map[string]bool{}
	for _, value := range input.Networks {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > 80 {
			return result, errors.New("IP 或网段长度无效")
		}
		var prefix netip.Prefix
		if ip, err := netip.ParseAddr(value); err == nil {
			if ip.Zone() != "" {
				return result, errors.New("不支持带区域标识的 IP")
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		} else {
			var err error
			prefix, err = netip.ParsePrefix(value)
			if err != nil {
				return result, errors.New("请输入有效 IPv4、IPv6 或 CIDR 网段")
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return result, errors.New("IPv4 映射网段的前缀不能小于 96")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
		}
		prefix = prefix.Masked()
		text := prefix.String()
		if !seen[text] {
			result.Networks = append(result.Networks, text)
			seen[text] = true
		}
	}
	if result.Enabled && len(result.Networks) == 0 {
		return result, errors.New("启用白名单时至少填写一个 IP 或网段")
	}
	return result, nil
}

func readSubscriptionAccess(record Document) (SubscriptionAccess, error) {
	value, exists := record["subscriptionAccess"]
	if !exists {
		return SubscriptionAccess{Networks: []string{}}, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return SubscriptionAccess{}, errors.New("订阅访问设置损坏")
	}
	var input struct {
		Enabled  *bool    `json:"enabled"`
		Networks []string `json:"networks"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || input.Enabled == nil {
		return SubscriptionAccess{}, errors.New("订阅访问设置损坏")
	}
	return normalizeSubscriptionAccess(SubscriptionAccess{Enabled: *input.Enabled, Networks: input.Networks})
}

// PreviewSubscriptionAccess validates and normalizes without persisting a policy.
func PreviewSubscriptionAccess(options SubscriptionAccess, address string) (SubscriptionAccess, bool, error) {
	normalized, err := normalizeSubscriptionAccess(options)
	if err != nil {
		return normalized, false, err
	}
	return normalized, subscriptionAccessAllows(normalized, address), nil
}
func subscriptionAccessAllows(options SubscriptionAccess, address string) bool {
	if !options.Enabled {
		return true
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, value := range options.Networks {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func subscriptionAddressAllowed(record Document, address string) error {
	options, err := readSubscriptionAccess(record)
	if err != nil {
		return err
	}
	if subscriptionAccessAllows(options, address) {
		return nil
	}
	return ErrSubscriptionIPDenied
}
func (r *Repository) SubscriptionAccess(id string) (SubscriptionAccess, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return SubscriptionAccess{}, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return SubscriptionAccess{}, err
	}
	return readSubscriptionAccess(record)
}
func (r *Repository) SetSubscriptionAccess(id string, input SubscriptionAccess) (SubscriptionAccess, error) {
	options, err := normalizeSubscriptionAccess(input)
	if err != nil {
		return options, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return options, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return options, err
	}
	raw, _ := json.Marshal(options)
	var value Document
	json.Unmarshal(raw, &value)
	record["subscriptionAccess"] = value
	return options, r.writeIndex(index)
}
