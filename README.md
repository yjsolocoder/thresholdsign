# thresholdsign

有限域上的 Shamir 秘密共享。把一份秘密拆成 `share_count` 份，任意 `threshold` 份可重建，少于 `threshold` 份得不到关于秘密的信息。

## 环境

Python 3.10+，只依赖标准库（`secrets`）。

## 使用

```python
from thresholdsign import split_secret, reconstruct_secret

shares = split_secret(secret=0xC0FFEE, threshold=3, share_count=5)
print([(share.x, share.y) for share in shares])
print(reconstruct_secret(shares[:3]))      # 12648430
```

## 命令行演示

```bash
python3 -m thresholdsign
```

## 公开接口

- `Share(x, y)` — 不可变份额；`x` 是求值点，从 1 开始
- `DEFAULT_PRIME` — 默认模数 `2**127 - 1`（梅森素数）
- `evaluate_polynomial(coefficients, x, *, prime)` — Horner 求值
- `split_secret(secret, threshold, share_count, *, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 返回长度 `share_count` 的 `Share` 列表；多项式常数项为秘密，其余系数随机
- `reconstruct_secret(shares, *, prime=DEFAULT_PRIME)` — 在 `x = 0` 处做拉格朗日插值
- `FeldmanCommitment(values, field_prime, group_prime, generator)` — 不可变的 Feldman 承诺；`values[j] = generator**a_j mod group_prime`，从常数项起
- `split_secret_verifiable(secret, threshold, share_count, *, prime=DEFAULT_PRIME, group_prime, generator, randbelow=secrets.randbelow)`
  — 与 `split_secret` 相同的拆分，额外返回承诺，返回 `(shares, commitment)`
- `verify_share(share, commitment)` — 校验 `generator**y == ∏ C_j**(x**j) mod group_prime`（指数按 `field_prime` 约简）；匹配返回 `True`，合法但不匹配返回 `False`

Feldman 模式要求：`prime` 与 `group_prime` 均为素数，`prime` 整除 `group_prime - 1`，且 `generator` 是模 `group_prime` 乘法群中阶为 `prime` 的非 1 元素；违反抛 `ValueError`，非整数参数抛 `TypeError`。

## 限制

这是单方分发加单方重建的共享方案：分发者自己构造多项式并持有完整秘密。Feldman 承诺让接收者能确认份额落在分发者承诺的同一个多项式上，但无法防止分发者一开始就用错误秘密分发。没有分布式密钥生成的交互轮次，也没有门限签名、份额轮换或重共享能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
