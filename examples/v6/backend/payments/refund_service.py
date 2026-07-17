"""示例业务文件，仅供 scope-check 使用。"""


def can_refund(user_permissions: set[str]) -> bool:
    return "payment.refund" in user_permissions
