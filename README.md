---
title: Chutes Image Generator
emoji: 🎨
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
license: mit
---

# Chutes Image Generator

一个基于 Chutes.ai API 的图像生成应用，支持多种 AI 模型生成高质量图像。

## 功能特性

- 🎨 支持多种AI图像生成模型
- 🌓 深色/浅色主题切换
- 🔊 生成完成提示音
- 📱 响应式设计，支持移动端
- 💾 批量生成和下载
- 🎯 丰富的参数调节选项

## 使用方法

1. 在右上角输入你的 CHUTES_API_TOKEN
2. 选择想要使用的模型
3. 输入提示词描述你想要生成的图像
4. 调整参数（尺寸、步数、引导系数等）
5. 点击生成按钮

## 支持的模型

- JuggernautXL (免费)
- FLUX.1-dev
- FLUX.1-schnell
- Stable Diffusion XL
- 以及更多专业模型...

## 环境变量

如果你想部署自己的版本，可以设置以下环境变量：

- `CHUTES_API_TOKEN`: Chutes.ai API 密钥
- `PORT`: 服务端口 (默认: 7860)
- `HOST`: 服务主机 (默认: 0.0.0.0)

## 技术栈

- 后端: Node.js + Express
- 前端: 原生 HTML/CSS/JavaScript
- 部署: Docker

## 许可证

MIT License
