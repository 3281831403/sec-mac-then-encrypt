把加密和完整性校验拼在一起之后，改掉密文尾部一个字节，解密仍然返回明文：加密键与认证键由同一派生路径得到，两键相同；附加认证数据不含版本，跨版本密文可互换；附加认证数据不含计数器，计数器可被替换；计数器允许零值，密钥流与初始块重复；先解密后验认证，篡改在解密阶段就被处理；认证范围只覆盖明文不覆盖头部，头部可被改写；去填充失败抛不同异常，可区分填充错误与认证错误；填充长度校验只看是否整数倍，不校验填充内容；认证比较用普通等号；批量封解复用计数器，第二个条目与第一个条目同流。envelope/seal.py 是核心，tests/unit/test_seal.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

仓库布局

sec-mac-then-encrypt/
  README.md
  conftest.py
  envelope/__init__.py
  envelope/seal.py
  tests/unit/test_seal.py
  tests/behaviour/test_seal_edge.py

运行方式

在仓库根目录执行 pytest tests -q。预期结果恰好 15 failed，且没有 error，所有失败都是 NotImplementedError。

字段表

领域 安全
方向 漏洞检测与攻防
类型 Bugfix
技术栈 Python 3, pytest
依赖 无外部依赖

测试拆分布局

tests/unit/test_seal.py 共 10 条契约测试，tests/behaviour/test_seal_edge.py 共 5 条边界测试，合计 15 条。该布局按缺陷与边界拆分，不改变题面要求的 15 个红。

测试不可修改

tests 目录不可修改，只允许实现 envelope/seal.py。实现只使用 Python 标准库，离线，不使用随机数、当前时间或外部服务。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

