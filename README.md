# LocalSub - 本地订阅转换器

一款完全本地化的代理订阅转换工具，支持将各类订阅链接转换为 Clash/Mihomo 配置文件。

## 特性

- 🔐 **本地转换** - 所有处理在本地完成，数据不上传
- 🌐 **多协议支持** - VLESS, VMess, SS, SSR, Trojan, Hysteria, Hysteria2, TUIC, WireGuard
- 📋 **规则集成** - 支持 ACL4SSR 等远程规则集
- 💎 **现代 UI** - 基于 Naive UI + UnoCSS

## 下载

前往 [Releases](https://github.com/Breeze-mi/v2ray-to-clash/releases) 下载最新版本。

## 使用

1. 输入订阅链接或粘贴订阅内容
2. 选择配置模板（可选）
3. 点击"转换"按钮
4. 复制生成的 YAML 配置

## 开发

```bash
# 安装依赖
pnpm install

# 开发模式
pnpm tauri dev

# 构建
pnpm tauri build
```

## 技术栈

- 前端：Vue 3 + TypeScript + Naive UI + UnoCSS
- 后端：Tauri v2 + Rust

## 协议

MIT License
