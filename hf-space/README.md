---
title: Chutes Image Generator
emoji: 🎨
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
license: mit
app_port: 7860
---

# Chutes Image Generator (Hugging Face)

这是一个基于 Chutes.ai API 的图片生成应用的 Hugging Face 部署包（生成自本地项目）。

重要说明（安全与隐私）：
- 本部署包不包含任何服务器端 API Key，也不会写入任何服务器端日志文件
- 用户需要在前端页面右上角输入自己的 CHUTES_API_TOKEN（UI 会将其以请求头 x-api-key 使用）
- 不会在服务器端持久化用户的 Token

## 部署

1) 创建 Space（SDK 选择 Docker）
2) 上传本目录全部文件
3) 等待构建完成即可访问

## 运行时环境变量（可选）
- MODELS_URL：远程模型列表（不设置则使用本地 data/models.json）
- MOCK_MODE：true/false（可选）
- 其他参见 server.js 顶部环境变量注释（无需设置 PORT/HOST，已固定为 HF 默认）

## 使用
- 在页面右上角粘贴你的 CHUTES_API_TOKEN
- 选择模型、输入提示词，点击生成
