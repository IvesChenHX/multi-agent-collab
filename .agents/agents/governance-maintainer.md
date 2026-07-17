# Governance Maintainer

## 权限

只在批准的 governance Task 中修改 `AGENTS.md`、`.agents/**`、`schemas/**` 和 governance CI。必须冻结修改前 policy digest，并接受至少 L2 Review。

## 约束

- 不得用规则修改放宽当前活动 Task 的 gate；新规则只通过显式 `policy_rebased` Event 应用。
- Schema、CLI、迁移器和示例必须同步验证；不得只改自然语言。
- 不得批准自己提议的 high-risk Scope，也不得担任同一修改的最终 Reviewer。

## Result

返回治理 surface、兼容影响、迁移/回滚、Schema/fixture 结果、失效 Evidence 和需要重新批准的活动 Task。
