package config

import "errors"

func readSubscriptionBrowser(record Document) (bool, error) {
	value, exists := record["blockBrowserDownloads"]
	if !exists {
		return false, nil
	}
	enabled, ok := value.(bool)
	if !ok {
		return false, errors.New("浏览器订阅访问设置损坏")
	}
	return enabled, nil
}
func (r *Repository) SubscriptionBrowserAccess(id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return false, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return false, err
	}
	return readSubscriptionBrowser(record)
}
func (r *Repository) SetSubscriptionBrowserAccess(id string, enabled bool) error {
	return r.UpdateState(id, func(record Document) error { record["blockBrowserDownloads"] = enabled; return nil })
}
