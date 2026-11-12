package config

import (
	"errors"
	"regexp"
	"strings"
)

const AppPrivacyGroup = "🔒 App 隐私代理"

// A transparent, versioned preset rather than a claim to recognize every app.
// Domains are a fallback for clients without process attribution, not a substitute
// for Android package rules (an app may use arbitrary third-party endpoints).
type AppPrivacyCategory struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
	Domains  []string `json:"domains"`
}

func AppPrivacyCatalog() []AppPrivacyCategory {
	return []AppPrivacyCategory{
		{"google", "Google / Chrome", strings.Fields("com.android.chrome com.chrome.beta com.chrome.dev com.chrome.canary com.google.android.gms com.google.android.gsf com.google.android.gsf.login com.android.vending com.google.android.googlequicksearchbox com.google.android.gm com.google.android.apps.maps com.google.android.apps.photos com.google.android.apps.docs com.google.android.apps.docs.editors.docs com.google.android.apps.docs.editors.sheets com.google.android.apps.docs.editors.slides com.google.android.apps.nbu.files com.google.android.keep com.google.android.calendar com.google.android.contacts com.google.android.apps.translate com.google.android.apps.walletnfcrel com.google.android.apps.chromecast.app com.google.android.apps.tachyon com.google.android.apps.meetings com.google.android.apps.messaging com.google.android.apps.authenticator2 com.google.android.apps.subscriptions.red"), strings.Fields("google.com googleapis.com gstatic.com googleusercontent.com googlevideo.com gvt1.com gvt2.com android.com gmail.com googleadservices.com")},
		{"ai", "AI 助手", strings.Fields("com.openai.chatgpt com.anthropic.claude com.google.android.apps.bard ai.perplexity.app com.xai.grok com.microsoft.copilot com.microsoft.bing com.poe.android com.characterai.app"), strings.Fields("openai.com chatgpt.com oaistatic.com oaiusercontent.com anthropic.com claude.ai claude.com perplexity.ai grok.com x.ai copilot.microsoft.com bing.com poe.com character.ai")},
		{"streaming", "流媒体 / 音乐", strings.Fields("com.google.android.youtube com.google.android.apps.youtube.music com.google.android.apps.youtube.kids com.google.android.youtube.tv com.google.android.apps.youtube.unplugged com.netflix.mediaclient com.netflix.ninja com.disney.disneyplus com.disney.disneyplus.tv com.amazon.avod.thirdpartyclient com.amazon.amazonvideo.livingroom com.hbo.hbonow com.wbd.stream com.hulu.plus com.spotify.music com.spotify.tv.android com.apple.android.music tv.twitch.android.app tv.twitch.android.viewer tv.plex.android.app com.crunchyroll.crunchyroid com.peacocktv.peacockandroid"), strings.Fields("youtube.com youtu.be ytimg.com youtube-nocookie.com googlevideo.com netflix.com netflix.net nflxvideo.net nflximg.net nflxso.net nflxext.com disneyplus.com disney-plus.net bamgrid.com dssott.com primevideo.com aiv-cdn.net max.com hbomax.com hulu.com huluim.com spotify.com scdn.co twitch.tv ttvnw.net jtvnw.net plex.tv crunchyroll.com peacocktv.com music.apple.com")},
		{"social", "社交 / 即时通信", strings.Fields("com.twitter.android com.instagram.android com.instagram.barcelona com.facebook.katana com.facebook.lite com.facebook.orca com.facebook.mlite com.whatsapp com.whatsapp.w4b org.telegram.messenger org.telegram.messenger.web org.thoughtcrime.securesms com.discord com.reddit.frontpage com.snapchat.android com.zhiliaoapp.musically com.ss.android.ugc.trill com.linkedin.android jp.naver.line.android com.viber.voip com.skype.raider xyz.blueskyweb.app org.joinmastodon.android com.pinterest"), strings.Fields("twitter.com x.com t.co twimg.com facebook.com facebook.net fbcdn.net fbsbx.com instagram.com cdninstagram.com threads.net threads.com whatsapp.com whatsapp.net telegram.org t.me telegra.ph telegram.me signal.org signal.art discord.com discord.gg discordapp.com discordapp.net reddit.com redd.it redditmedia.com redditstatic.com snapchat.com sc-cdn.net tiktok.com tiktokv.com tiktokcdn.com tiktokcdn-us.com musical.ly linkedin.com licdn.com line.me line-apps.com line-scdn.net viber.com skype.com bsky.app bsky.social pinterest.com pinimg.com")},
	}
}

var appPackagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func appPrivacySelection(o ClientOptions) ([]string, []string, error) {
	chosen := map[string]bool{}
	if len(o.AppCategories) > 200 || len(o.AppExtraPackages) > 16000 {
		return nil, nil, errors.New("应用分类或包名列表过长")
	}
	raw := o.AppCategories
	if raw == "" {
		raw = "google,ai,streaming,social"
	}
	for _, id := range strings.Split(raw, ",") {
		id = strings.TrimSpace(id)
		if chosen[id] {
			continue
		}
		found := false
		for _, c := range AppPrivacyCatalog() {
			if c.ID == id {
				found = true
			}
		}
		if !found {
			return nil, nil, errors.New("应用保护分类无效")
		}
		chosen[id] = true
	}
	packages, domains := []string{}, []string{}
	seenP, seenD := map[string]bool{}, map[string]bool{}
	for _, c := range AppPrivacyCatalog() {
		if !chosen[c.ID] {
			continue
		}
		for _, p := range c.Packages {
			if !seenP[p] {
				packages = append(packages, p)
				seenP[p] = true
			}
		}
		for _, d := range c.Domains {
			if !seenD[d] {
				domains = append(domains, d)
				seenD[d] = true
			}
		}
	}
	extra := strings.FieldsFunc(o.AppExtraPackages, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' })
	if len(extra) > 100 {
		return nil, nil, errors.New("额外应用包名最多 100 个")
	}
	for _, p := range extra {
		if len(p) > 200 || !appPackagePattern.MatchString(p) {
			return nil, nil, errors.New("额外包名必须为有效 Android 包名，不能包含规则或通配符")
		}
		if !seenP[p] {
			packages = append(packages, p)
			seenP[p] = true
		}
	}
	return packages, domains, nil
}

// Only concrete proxy nodes enter this selector: no DIRECT, provider, nested
// selector, dialer-proxy, or fallback-to-direct can accidentally escape it.
func installAppPrivacy(doc Document, o ClientOptions) ([]any, error) {
	packages, domains, e := appPrivacySelection(o)
	if e != nil {
		return nil, e
	}
	for _, v := range rows(doc, "proxy-groups") {
		g, _ := v.(Document)
		if g["name"] == AppPrivacyGroup {
			return nil, errors.New("配置已有同名 App 隐私代理组，请先重命名该自定义组")
		}
	}
	members := []any{}
	for _, v := range rows(doc, "proxies") {
		node, ok := v.(Document)
		if !ok {
			continue
		}
		name := stringValue(node["name"])
		if name == AppPrivacyGroup {
			return nil, errors.New("节点名称与 App 隐私代理组冲突")
		}
		if name == "" || name == "DIRECT" || name == "REJECT" || name == "PASS" || name == "COMPATIBLE" || node["udp"] == false || stringValue(node["dialer-proxy"]) != "" {
			continue
		}
		switch stringValue(node["type"]) {
		case "ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "wireguard":
		case "socks5":
			if node["udp"] != true {
				continue
			}
		default:
			continue
		}
		members = append(members, name)
	}
	if len(members) == 0 {
		members = []any{"REJECT"}
	}
	doc["proxy-groups"] = append(rows(doc, "proxy-groups"), Document{"name": AppPrivacyGroup, "type": "select", "proxies": members})
	doc["find-process-mode"] = "always"
	rules := []any{}
	for _, p := range packages {
		rules = append(rules, "PROCESS-NAME,"+p+","+AppPrivacyGroup)
	}
	for _, d := range domains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+AppPrivacyGroup)
	}
	return rules, nil
}
