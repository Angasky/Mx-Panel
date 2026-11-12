# 界面排版与设计参考

2026-11-12 查看以下 GitHub 项目的公开 README，参考布局和组件设计方向；没有复制其页面代码，也没有引入 Bootstrap、React 或 Tailwind 运行时。

- https://github.com/tabler/tabler （MIT）：管理台的信息密度、卡片、表单与导航。
- https://github.com/shadcn-ui/ui （MIT）：中性色表面、统一控件与清晰的主次操作。
- https://github.com/rsms/inter （SIL OFL 1.1）：屏幕用英文字体，本地包含 Inter Variable。
- https://github.com/notofonts/noto-cjk （字体为 SIL OFL 1.1）：中文界面字形。本地包含 Noto Sans CJK SC Regular 的界面字符子集，缺失字形回退系统中文字体。

字体及许可证位于 internal/web/assets/fonts，随 Go 二进制嵌入，经同源 /sub/ui-fonts/ 提供，不请求第三方 CDN。中文子集按 index.html 的非 ASCII 字符生成；增加界面文字时应重新生成。字体 display:swap，加载失败仍可使用系统字体。

云白主题默认用于没有保存偏好的浏览器；已选主题保留，五套主题共享相同的字号、卡片、表单和按钮布局。代码编辑仍使用等宽字体。

订阅总览：宽屏两列、900px 以下一列；Clash、v2rayN、v2rayNG、V2Ray 通用优先。链接保持完整，只在单行输入框中截断显示，点选可复制完整内容。二维码可放大；长说明折叠。快速跳转选择器可定位并聚焦指定客户端，也可点击打开链接或下载。
