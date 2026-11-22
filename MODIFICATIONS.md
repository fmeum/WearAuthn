# 本仓库的改动说明（非官方修改版）

本仓库是 **WearAuthn** 的非官方中文修改版，从上游仓库 fork 而来，代码托管在 `zh-cn/wear-m3e` 分支上，`master` 保持与上游一致以便同步更新。

## 来源与许可

| 项 | 内容 |
|---|---|
| 上游项目 | [fmeum/WearAuthn](https://github.com/fmeum/WearAuthn) |
| 上游作者 | Fabian Henneke（© 2019） |
| 许可 | MIT License，见 [`LICENSE`](LICENSE)；AOSP 衍生部分为 Apache-2.0，见 [`NOTICE`](NOTICE) |
| 本仓库性质 | 非官方 fork，与上游作者、Google Play 上的官方版本无隶属关系 |

按 MIT 与 Apache-2.0 的要求，`LICENSE` 与 `NOTICE` 保持不变；本文件用于说明本仓库相对上游的改动（Apache-2.0 §4(b) 要求标注修改过的文件）。

## 改动清单

### 1. 全量简体中文本地化
- `authenticator/src/main/res/values-zh-rCN/strings.xml`（新增）
- `authenticator/src/main/res/values/strings.xml`、`values-de/strings.xml`（补充与对齐）
- `values-zh-rCN/` 覆盖界面字符串、状态文案、对话框与提示

### 2. 主界面按 Wear Material 3 Expressive 重构
- `ui/main/AuthenticatorActivity.kt`（重写为圆屏药丸列表：5.2% 侧边距、16.64% 顶边距、36dp 图标块、96dp 卡片）
- `res/layout/activity_authenticator_main.xml`、`item_main_row.xml`（新增布局结构）
- `res/drawable/bg_pill_*.xml`、`bg_chip_*.xml`、`bg_dialog.xml`、`bg_status_dot.xml`（新增）
- `res/values/colors.xml`（M3 深色令牌：`m3_primary #2962FF`、`m3_connected #3DDC84` 等）
- `res/values/themes.xml`（统一对话主题）

### 3. 磁贴与表盘复杂功能入口
- `tile/ShortcutTileService.kt`、`tile/ShortcutTarget.kt`、`tile/ShortcutLaunchActivity.kt`（新增，改用 `androidx.wear.tiles` + 中转 Activity，修复"点进去弹回主界面"）
- `complication/ShortcutComplicationProviderService.kt`（同步落点修复）
- `AndroidManifest.xml`（注册磁贴服务与中转 Activity）
- 依赖约束：`tiles:1.4.1` + `protolayout:1.2.0`（升级会撞 Kotlin 2.1 metadata 与 compileSdk 35，暂不升级）

### 4. 连接保活（返回主界面后仍保持 HID 会话）
- `bthid/HidDataSender.kt`：新增 `setIoListener(listener)`，只替换回调不动蓝牙链路
- `ui/main/HidScreenState.kt`（新增）：记录哪个界面在前台，判断是否还有人能处理 CTAP 请求
- `ui/main/AuthenticatorAttachedActivity.kt`：移除 onStop 里主动断开链路的定时器，改为移交 io 回调；新增 1.8s 宽限
- `ui/main/AuthenticatorActivity.kt`：主界面自建 `HidAuthenticatorContext` + `TransactionManager`，在 onResume 接管会话
- `bthid/Utils.kt`（配套调整）

### 5. 免密登录改为可开可关的双向开关
- `fido/context/Keystore.kt`：新增 `disarmUserVerificationFuse()`——UV 保险丝只回答"用户验证是否启用"，不加密凭据，因此可安全撤回；撤回时先删密钥再清标记
- `ui/main/PasswordlessModeActivity.kt`（新增）+ `res/layout/activity_passwordless.xml`、`bg_switch_track.xml`、`bg_switch_thumb.xml`
- `res/drawable/ic_btn_lock_open.xml`（新增，与 `ic_btn_lock` 同一几何，锁梁绕 (12,9) 旋转 −24° 表示"开"）
- 上游只能单向开启，本改动支持关闭后再开启

### 6. 图标配色
- `res/drawable/ic_launcher_background.xml`：底色改为 `@color/m3_primary`（`#2962FF`）
- `res/drawable/ic_launcher_foreground.xml`：保留上游云 + 钥匙的完整几何（path 与 group 变换逐字不动），云改白、钥匙改深蓝 `#06234F`，原 45° 长阴影替换为偏移 (3, 3.2) 的 32% 短硬阴影
- `ic_launcher_outline.xml` 未改动（对话框、表盘复杂功能用的单色描边版）

### 7. 其他
- `authenticator/build.gradle`：版本号后缀改为 `-r28`（`versionCode` 与上游一致）
- `sync/UnlockComplicationListenerService.kt`：本地构建放开原版的表盘复杂功能内购判断
- `ui/main/ResidentCredentialsList.kt`、`res/layout/activity_credential_list.xml`、`credential_list_header.xml`、`activity_about.xml`、`activity_authenticator_attached.xml`：随新设计语言调整

## 构建与签名说明

- 构建命令：`./gradlew :authenticator:assemblePlayStoreRelease`（JDK 17，Android SDK platform-34 / build-tools 34.0.0）
- 上游仓库内置的 `ci_keystore.jks` / `nightly_keystore.jks` 是**公开的持续集成测试密钥**，密码明文写在仓库中，**不可用于任何对外发布**。对外分发请使用自建 keystore。
- 本分支的 APK 与本仓库 master 分支的官方构建**同包名、不同签名**，安装前需先卸载官方版本。

## 风险提示

WearAuthn 是安全密钥类应用。注册时请务必同时配置其他 2FA 方式；丢失手表或重置应用都可能导致无法登录相关账号。
