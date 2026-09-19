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

## 限制

这是单方分发加单方重建的共享方案：分发者自己构造多项式并持有完整秘密。份额没有任何可验证性证明，接收者无法确认份额是否落在同一个多项式上，也无法识别分发者或某个参与者提交了错误份额。没有分布式密钥生成的交互轮次，也没有门限签名、份额轮换或重共享能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
