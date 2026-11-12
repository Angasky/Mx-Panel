# 我的世界 · 方块工作台

设置 → 外观与性能 → 我的世界。管理员与普通用户门户均可切换，偏好保存在当前浏览器；不改变其他设备或已有主题选择。

源项目：当前服务器的 Craft Monitor（monitor.mxioc.com），主题 mxioc-craft 3.35.0。复用该项目的原创草方块图标、泥土/石块/木板 SVG，以及其首页 #world Canvas 的主世界静态主图。主图以本地 PNG 快照随程序分发，不调用探针接口，也不读取或展示探针节点数据。没有移植 3D 建造游戏、音乐或探针业务脚本。

全站使用草地绿、羊皮纸色表面、石质卡片与木板装饰；首页展示同源像素风景。英文装饰标题与统计数字使用 Monocraft，正文、按钮、导航与表单使用 Inter / Noto 中文界面字体。补齐浅色状态色，正文采用深色文字，加入物品栏凹槽、立体按钮和原创钻石镐、储物箱 SVG。资源由 Go embed 打包，经 /sub/ui-craft/ 提供，不依赖探针域名或 CDN。

Silkscreen 来源：https://github.com/google/fonts/tree/main/ofl/silkscreen
Copyright 2001 The Silkscreen Project Authors，SIL OFL 1.1；完整许可证在 internal/web/assets/craft/Silkscreen-OFL.txt。

风景、草方块及材质为源项目自有程序绘图，没有提取游戏素材。本主题为独立设计，非 Minecraft 官方产品。

验证：桌面/手机布局、六主题切换、刷新后偏好保留、主图和二维码真实加载；节点/订阅导出、普通用户、元信息/地球、Agent/DNS 表单及分享窗口回归。没有操作真实用户节点。

2026-11-12 可读性更新：参考 Mojang/web-theme-bootstrap 的草地绿与中性灰配色，以及 Minecraft-CSS 的 Ore UI 立体控件。主按钮使用更深的绿色保证白字清晰。物品栏仅为装饰，不模拟可点击控件。

参考：
- https://github.com/Mojang/web-theme-bootstrap/blob/main/scss/abstract/_colors.scss
- https://github.com/Jiyath5516F/Minecraft-CSS
- https://github.com/IdreesInc/Monocraft

Monocraft 字体以 SIL OFL 1.1 分发，许可保存在 internal/web/assets/craft/Monocraft-LICENSE.txt。新物品图标为原创 SVG，没有复制游戏贴图。

DNS / 密集表格可读性修正：参考 https://github.com/primer/primitives/blob/main/DESIGN_TOKENS_GUIDE.md 的前景/背景搭配规则。表格采用 #24292f 深灰文字、白色底，数据代码从 12px 增至 14px，去除逐项边框，DNS 多地址以 8px 间距排布并允许长地址换行。小按钮和导航使用正常界面字体，像素字用于装饰标题。仅我的世界主题调整表格配色，其余主题保留各自配色。

节点协议标签采用浅灰绿色底（#dbe2d1）、深色文字（#293525）和低对比边框，消除卡片内纯白色块，标签使用清晰界面字体并支持换行。
