# 项目上下文基线

本文件只记录稳定项目事实，由 Discovery 按需维护；流程规则由 `AGENTS.md` 和 `.agents/config.yaml` 定义。

## 项目类型

- 通用多 Agent 协作协议模板，不包含具体业务实现。

## 主要目录

- `AGENTS.md`：跨角色协作规则。
- `.agents/agents/**`：角色执行契约。
- `.agents/workflows/**`：状态转换定义。
- `.agents/ownership.yaml`：路径 ownership 候选映射。
- `tasks/**`：任务证据记录。
- `docs/adr/**`：长期架构决策。

## 当前配置事实

- 默认工作流：`evidence-driven-development`。
- `feature-development`：只读 legacy 入口，不用于新任务。
- 当前仓库没有业务构建或运行命令。
- 协议修改主要验证 YAML 可解析、引用一致、UTF-8 可读和 diff 无空白错误。

## 待目标项目补充

- 真实业务模块、owner 和路径提示。
- 构建、测试、lint、typecheck 和启动命令。
- 环境依赖、集成环境和外部系统限制。
