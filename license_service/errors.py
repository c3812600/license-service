"""带业务错误码的异常类型。

异常继承内建异常，保持路由层既定映射（AGENTS.md）：
ValueError → 400、PermissionError → 403、RuntimeError → 409。
`code` 由路由层写入响应信封 `{"ok":false,"error":"...","code":"..."}`，
客户端按 `code` 分支，不匹配人类可读的 `error` 文案。

code 取值契约见 docs/license-design-spec.md §8.4。
"""


class InputError(ValueError):
    """请求参数非法（HTTP 400）。code 默认 INVALID_INPUT。"""

    status = 400

    def __init__(self, message, code="INVALID_INPUT"):
        super().__init__(message)
        self.code = code


class NotFoundError(InputError):
    """资源不存在（HTTP 404）。code 默认 NOT_FOUND。"""

    status = 404

    def __init__(self, message, code="NOT_FOUND"):
        super().__init__(message, code)


class ForbiddenError(PermissionError):
    """请求合法但被业务规则拒绝（HTTP 403）。code 默认 FORBIDDEN。"""

    status = 403

    def __init__(self, message, code="FORBIDDEN"):
        super().__init__(message)
        self.code = code


class ConflictError(RuntimeError):
    """与当前状态冲突、需换流程或人工介入（HTTP 409）。code 默认 CONFLICT。"""

    status = 409

    def __init__(self, message, code="CONFLICT"):
        super().__init__(message)
        self.code = code
