# 我的世界 · 方块工作台

设置 → 外观与性能 → 我的世界。管理员与普通用户门户均可切换，偏好保存在当前浏览器；不改变其他设备或已有主题选择。

源项目：当前服务器的 Craft Monitor（monitor.mxioc.com），主题 mxioc-craft 3.35.0。复用该项目的原创草方块图标、泥土/石块/木板 SVG，以及其首页 #world Canvas 的主世界静态主图。主图以本地 PNG 快照随程序分发，不调用探针接口，也不读取或展示探针节点数据。没有移植 3D 建造游戏、音乐或探针业务脚本。

全站使用草地绿、羊皮纸色表面、石质卡片与木板装饰；首页展示同源像素风景。英文装饰标题使用 Silkscreen Regular，正文与中文表单沿用 Inter / Noto 中文界面字体。资源由 Go embed 打包，经 /sub/ui-craft/ 提供，不依赖探针域名或 CDN。

Silkscreen 来源：https://github.com/google/fonts/tree/main/ofl/silkscreen
Copyright 2001 The Silkscreen Project Authors，SIL OFL 1.1；完整许可证在 internal/web/assets/craft/Silkscreen-OFL.txt。

风景、草方块及材质为源项目自有程序绘图，没有提取游戏素材。本主题为独立设计，非 Minecraft 官方产品。

验证：桌面/手机布局、六主题切换、刷新后偏好保留、主图和二维码真实加载；节点/订阅导出、普通用户、元信息/地球、Agent/DNS 表单及分享窗口回归。没有操作真实用户节点。
