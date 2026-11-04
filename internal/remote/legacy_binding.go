package remote

import (
	"errors"
	"maps"
)

func LegacyUserBinding(row, binding Record) (Record, error) {
	if row == nil || row["enable"] == false {
		return nil, errors.New("旧版入站缺失、停用或尚未核对")
	}
	hash, err := LegacyInboundIdentity(row)
	if err != nil || value(binding["identityHash"]) == "" || binding["identityHash"] != hash {
		return nil, errors.New("旧版入站身份不一致，不能迁移")
	}
	settings, err := inboundObject(row["settings"])
	if err != nil {
		return nil, err
	}
	clients, _ := settings["clients"].([]any)
	if len(clients) != 1 {
		return nil, errors.New("旧版入站必须只有一个用户")
	}
	user, ok := clients[0].(Record)
	if !ok || user["enable"] == false || value(user["email"]) == "" {
		return nil, errors.New("旧版入站缺少可核对的启用用户")
	}
	proposed := maps.Clone(binding)
	proposed["scope"], proposed["userEmail"] = "user", user["email"]
	proposed["identityHash"], err = EndpointIdentity(row)
	if err != nil {
		return nil, err
	}
	proposed["userHash"], err = UserIdentity(user)
	if err != nil {
		return nil, err
	}
	if _, err := FindUser(row, proposed, false); err != nil {
		return nil, err
	}
	return proposed, nil
}

func VerifyDedicatedBinding(row, binding Record) error {
	settings, err := inboundObject(row["settings"])
	if err != nil {
		return err
	}
	clients, ok := settings["clients"].([]any)
	if !ok || len(clients) != 1 {
		return errors.New("链路入站不是独占单用户入站")
	}
	_, err = FindUser(row, binding, false)
	return err
}
