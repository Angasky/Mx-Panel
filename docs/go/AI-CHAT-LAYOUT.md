# AI 浮窗布局调整

日期：2026-11-14。

## GitHub 参考

- 项目：https://github.com/assistant-ui/assistant-ui
- 已读取源码：https://github.com/assistant-ui/assistant-ui/blob/7d7427653f6ba47b0b954510eed9c594d64e74d5/apps/docs/components/pages/home/demo/thread.tsx
- 参考版本：`7d7427653f6ba47b0b954510eed9c594d64e74d5`。

参考其纵向聊天容器、独立滚动消息区、底部输入组件与空态建议的布局思路；本项目使用原生 HTML/CSS/JavaScript 自行实现，未引入 React 组件或复制其实现代码。

## 布局

顶部集中放置对话记录、接入设置和新对话；连接信息单独显示为辅助文字。历史记录按需展开。中间去除多层卡片边框，空态显示四个快捷问题。底部统一输入框、配置摘要入口、停止与发送按钮；摘要选择和预览按需展开，选择状态在入口显示。保留拖动、账号独立设置和现有对话接口。

## 验证

使用本地 Puppeteer 页面和模拟 API，未调用真实模型：

- 6 个主题 × 320、390、439、1360px 宽度：无横向溢出，发送按钮在浮窗内。
- 快捷问题填入、历史展开、摘要选择与预览、发送及回复、长消息滚动、新对话、收起重开通过。
- 667 × 375 短视口可以滚动访问输入操作。
- 浏览器无脚本异常。
- 原有 `tests/ui_navigation.cjs` 在当前改动和 HEAD 基线上均因导航数量 `24 !== 5` 失败，属于既有断言问题。

预览位于 `work/ai-layout-mobile.png` 与 `work/ai-layout-conversation.png`。随 v0.2.3 发布；部署状态以实际升级验收为准。
