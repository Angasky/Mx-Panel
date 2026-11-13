# Mx-Panel 界面排版规范（v0.1.41）

## 设计参考

本次实际读取了以下 GitHub 项目的组件实现。采用它们的操作层级、间距、表格滚动容器与移动导航思路，以原生 HTML/CSS/JavaScript 实现，未引入 React、Bootstrap 或远端 CDN 依赖；下列项目均使用 MIT 许可证。

- [tabler/tabler](https://github.com/tabler/tabler)：参考版本 `4257ebcd1cd5`，[_buttons.scss](https://github.com/tabler/tabler/blob/4257ebcd1cd5494f71b84c485fd15749fc6d5f92/core/scss/ui/_buttons.scss)、[_cards.scss](https://github.com/tabler/tabler/blob/4257ebcd1cd5494f71b84c485fd15749fc6d5f92/core/scss/ui/_cards.scss)、[_tables.scss](https://github.com/tabler/tabler/blob/4257ebcd1cd5494f71b84c485fd15749fc6d5f92/core/scss/ui/_tables.scss)、[_page.scss](https://github.com/tabler/tabler/blob/4257ebcd1cd5494f71b84c485fd15749fc6d5f92/core/scss/layout/_page.scss)。
- [shadcn-ui/ui](https://github.com/shadcn-ui/ui)：参考版本 `dd41d19e2f80`，[button.tsx](https://github.com/shadcn-ui/ui/blob/dd41d19e2f80ff6891951f7ced74c2c9a650b065/apps/v4/registry/new-york-v4/ui/button.tsx)、[table.tsx](https://github.com/shadcn-ui/ui/blob/dd41d19e2f80ff6891951f7ced74c2c9a650b065/apps/v4/registry/new-york-v4/ui/table.tsx)、[sidebar.tsx](https://github.com/shadcn-ui/ui/blob/dd41d19e2f80ff6891951f7ced74c2c9a650b065/apps/v4/registry/new-york-v4/ui/sidebar.tsx)。
- [ant-design/ant-design](https://github.com/ant-design/ant-design)：参考版本 `94ae623993a0`，[seed.ts](https://github.com/ant-design/ant-design/blob/94ae623993a0c55570a683e7c78be5a094966dee/components/theme/themes/seed.ts)、[index.ts](https://github.com/ant-design/ant-design/blob/94ae623993a0c55570a683e7c78be5a094966dee/components/form/style/index.ts)。

- Tabler：工作台侧栏、页面标题与工具区分层，卡片留白，表格独立横向滚动。
- shadcn/ui：主操作、普通操作、轻量操作和危险操作的按钮层级；聚焦状态；手机抽屉导航。
- Ant Design：统一字体与控件尺寸，基于 4/8 px 的间距，表单标签与帮助文字层级。

## 全局规则

界面正文 14 px，辅助文字 12–13 px，模块标题 17 px，页面标题 24–30 px；使用已随程序分发的 Inter 与 Noto 中文字体，代码保留等宽字体。六种主题保留自身配色与品牌元素，数据和操作使用一致的字体尺寸。我的世界主题保留方块装饰及低圆角，不再让像素字承担表单与密集数据。

常规按钮桌面 40 px、手机 44 px；行内小按钮桌面 34 px、手机 40 px。按钮字数变多时允许换行，图标固定尺寸。主操作使用主题强调色，普通操作用描边，刷新和退出等全局动作使用轻量按钮，危险操作用红色语义。复选框保持 16 × 16 px，标签保留可点击面积，键盘聚焦环不被移除。

顶部工作台工具区负责订阅切换、刷新与退出；页面标题右侧只放当前功能的主要动作。分区导航使用横向页签，手机允许局部滚动。桌面侧栏保持固定宽度，手机（≤768 px）使用抽屉，支持关闭按钮、遮罩、Escape、焦点约束和缩放恢复，背景在展开时不可交互。普通用户只见自己的订阅中心。

卡片使用 16–24 px 间距，表格有固定表头、独立滚动与选中行提示；长地址换行，操作按钮不再强制占一条无限长的行。服务器和订阅卡片将低频维护 / 复制 / 删除操作放在可展开区域。探针批量操作分成接入与失败恢复两行；设置页面按六类任务展示入口。

表单默认约 760 px，包含表格或代码的弹窗约 1080 px；均受视口宽高限制。数值输入框限制宽度，两列字段在手机变成一列。通知记录等历史使用统一表格容器。公开监控页同步字体、标题、卡片、数字与触屏操作尺寸。

## 验收范围

本地隔离数据验证全局导航、订阅创建与编辑、节点及多客户端下载、权限、探针批量流程；远端操作通过明确标注的模拟响应验收，不对生产节点执行测试安装或删除。扩展布局验收覆盖 17 个管理页面 × 6 种主题 × 320/390/768/1440 四种宽度，以及表单、复选框、抽屉键盘操作和用户门户。截图与测试脚本保存在本地 artifacts，不纳入仓库。
