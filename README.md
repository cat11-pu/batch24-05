# GSB Bugfix Task
## 题面
JWT 校验现在直接返回 payload：alg=none 放行、签名不验、过期不查、issuer/audience 不看。jwt_guard.py 是核心，tests/test_jwt_guard.py 15 个红。要修成只接受允许的算法、HS256 必须验签、过期和未生效时间要拒绝、issuer/audience 要匹配、空密钥和短密钥拒绝、畸形 token 统一报错。修完 15 个测试后，还要保证 1000 组随机 header/payload 没有绕过，32 线程并发校验同一 token 结果一致；不许改测试或写死 token。边界至少覆盖 alg=none、篡改 payload、过期、未来 nbf、issuer/audience 不匹配、空密钥。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
