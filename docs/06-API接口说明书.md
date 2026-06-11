# ShieldDome API 接口说明书

## 1. 通用规则

- 基础地址：`https://shielddome.example.internal`
- 鉴权：请求头 `X-API-Key`。管理 Token 与邮件接入 Token 应分离。
- API 自动文档：`/docs`；OpenAPI JSON：`/api/v1/openapi.json`。
- 文件上传使用 `multipart/form-data`，最大 EML 为 50 MB。

## 用户管理接口

以下接口仅允许系统管理员登录会话或管理员 API Key 调用：

- `GET /api/v1/users`：返回不含密码哈希的用户列表。
- `POST /api/v1/users`：创建用户，角色支持 `admin`、`analyst`、`auditor`。
- `PUT /api/v1/users/{user_id}`：修改显示名称、角色和启停状态。
- `POST /api/v1/users/{user_id}/reset-password`：重置密码并撤销该用户全部会话。
- `POST /api/v1/users/{user_id}/plugin-token`：签发或轮换用户插件 Token，明文仅在本次响应中返回。
- `DELETE /api/v1/users/{user_id}/plugin-token`：撤销用户插件 Token。

## 应用中心与浏览器探针接口

- `GET /api/v1/apps`：返回当前网站提供的应用版本、下载地址和 SHA-256。
- `GET /api/v1/apps/browser-extension/download`：动态打包并下载当前部署的最新版浏览器插件 ZIP。
- `GET /api/email/auth/me`：校验 `X-ShieldDome-Plugin-Token` 并返回绑定用户。
- `POST /api/email/analyze/quick`：浏览器探针快速检测接口，必须提供用户插件 Token。
- `GET /api/email/analyze/status/{analysis_id}`：查询本人提交的浏览器探针深度检测进度。

浏览器探针接口允许跨域调用，但强制使用与用户绑定的 `X-ShieldDome-Plugin-Token`，且禁止跨用户查询检测状态。

## 模型密钥配置接口

- `GET /api/v1/settings/providers`：返回接口、模型、密钥掩码、来源和加密方式，不返回明文 Key。
- `PUT /api/v1/settings/providers`：管理员更新模型配置；可提交 `api_key` 保存新 Key，或提交 `clear_api_key: true` 清除网页保存的 Key。
- `POST /api/v1/settings/providers/test`：管理员测试 Chat 与 Embedding API 连接。

`provider_secret` 被标记为敏感策略，禁止通过通用策略读取和修改接口访问。

## 2. 上传 EML

```bash
curl -X POST \
  -H "X-API-Key: $SHIELDDOME_INGEST_TOKEN" \
  -F "file=@sample.eml;type=message/rfc822" \
  https://shielddome.example.internal/api/v1/messages/analyze
```

成功返回 `202`：

```json
{"analysis_id":"uuid","status":"queued","quick_result":{"risk_level":"high"}}
```

## 3. 查询检测

```bash
curl -H "X-API-Key: $SHIELDDOME_ADMIN_TOKEN" \
  https://shielddome.example.internal/api/v1/analyses/{analysis_id}
```

状态包括 `queued`、`running`、`completed`、`degraded` 和 `failed`。

## 4. 导入与审核知识

```bash
curl -X POST -H "X-API-Key: $SHIELDDOME_ADMIN_TOKEN" \
  -F "source_type=phishing_case" -F "file=@case.eml" \
  https://shielddome.example.internal/api/v1/knowledge/import

curl -X POST -H "X-API-Key: $SHIELDDOME_ADMIN_TOKEN" \
  https://shielddome.example.internal/api/v1/knowledge/{id}/approve
```

支持类型：`trusted_email`、`phishing_case`、`security_rule`、`soc_review`。

## 5. 反馈

```bash
curl -X POST -H "X-API-Key: $SHIELDDOME_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"verdict":"confirmed_phishing","comment":"SOC confirmed"}' \
  https://shielddome.example.internal/api/v1/analyses/{id}/feedback
```

## 6. 错误码

- `400`：文件类型、大小或参数错误。
- `401`：API Token 无效。
- `404`：分析或知识不存在。
- `422`：请求字段校验失败。
- `500`：服务端故障；任务处理故障会进入重试和最终失败状态。
