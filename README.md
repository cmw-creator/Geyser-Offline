<img src="https://geysermc.org/img/geyser-1760-860.png" alt="Geyser" width="600"/>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

# Geyser-Offline

**Fork of [GeyserMC/Geyser](https://github.com/GeyserMC/Geyser)** 支持基岩版客户端无需 Xbox Live 认证即可连接 Java 版服务器。

## ✨ 与上游的区别

| 功能 | GeyserMC (上游) | 本 fork |
|------|----------------|---------|
| 基岩版无 Xbox Live 登录 | ❌ 不支持（声明「不纵容盗版」） | ✅ **支持** |
| 离线基岩客户端自动注册 | ❌ | ✅ 自动分配随机 UUID/XUID |
| 常规 Xbox 认证 | ✅ | ✅ 保留，默认关闭离线模式 |

## 新增配置项

在 `config.yml` 中：

```yaml
advanced:
  bedrock:
    # 关闭 Xbox 证书验证（默认 true）
    validate-bedrock-login: false
    
    # 允许无 Xbox Live 认证的基岩客户端连接（默认 false）
    allow-offline-bedrock-clients: true
```

## ⚠️ 安全警告

此功能允许用户伪造用户名（类似于 Java 版的 `online-mode=false`）。**仅限局域网/离线环境使用，切勿在公网开启。**

Floodgate 功能（皮肤上传、账号关联）在离线模式下不可用。

## 下载

在 [Releases](https://github.com/cmw-creator/Geyser-Offline/releases) 页面下载最新构建。

支持平台: Standalone / Spigot / Fabric / NeoForge / BungeeCord / Velocity / ViaProxy

## 原版说明

### What is Geyser?
Geyser is a bridge between Minecraft: Bedrock Edition and Minecraft: Java Edition, closing the gap from those wanting to play true cross-platform.

Geyser is an [Open Collaboration](https://opencollaboration.dev/) project.

### Supported Versions

| Edition | Supported Versions                                                                                   |
|---------|------------------------------------------------------------------------------------------------------|
| Bedrock | 1.21.130 - 1.21.132, 26.0, 26.1, 26.2, 26.3, 26.10, 26.20, 26.21, 26.22, 26.23                       |
| Java    | 26.1 - 26.1.2 (For older versions, [see this guide](https://geysermc.org/wiki/geyser/supported-versions/)) |

### Links:
- Upstream Website: https://geysermc.org
- Upstream Docs: https://geysermc.org/wiki/geyser/
- Discord: https://discord.gg/geysermc

### Libraries Used:
- [Adventure Text Library](https://github.com/KyoriPowered/adventure)
- [CloudburstMC Bedrock Protocol Library](https://github.com/CloudburstMC/Protocol)
- [GeyserMC's Java Protocol Library](https://github.com/GeyserMC/MCProtocolLib)
- [TerminalConsoleAppender](https://github.com/Minecrell/TerminalConsoleAppender)
- [Simple Logging Facade for Java (slf4j)](https://github.com/qos-ch/slf4j)
