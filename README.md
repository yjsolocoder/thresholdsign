# thresholdsign

有限域上的 Shamir 秘密共享。把一份秘密拆成 `share_count` 份，任意 `threshold` 份可重建，少于 `threshold` 份得不到关于秘密的信息。支持 Feldman 与 Pedersen 可验证秘密共享（VSS）：接收者可凭承诺公开验证自己的份额是否落在分发多项式上，而无需信任分发者。

## 环境

Python 3.10+，只依赖标准库（`secrets`）。

## 使用

```python
from thresholdsign import split_secret, reconstruct_secret

shares = split_secret(secret=0xC0FFEE, threshold=3, share_count=5)
print([(share.x, share.y) for share in shares])
print(reconstruct_secret(shares[:3]))      # 12648430
```

### Feldman 可验证共享

需要一个素数阶乘法群：`group_prime` 为素数，`prime`（域模数）整除 `group_prime - 1`，`generator` 是该群中阶恰为 `prime` 的非 1 元素。

```python
from thresholdsign import split_secret_verifiable, verify_share

# group_prime = 4 * prime + 1 = 8069，16 在模 8069 乘法群中的阶为 2017
shares, commitment = split_secret_verifiable(
    0xC0, 3, 5, prime=2017, group_prime=8069, generator=16
)
assert all(verify_share(share, commitment) for share in shares)

# 篡改份额后验证返回 False（合法但不匹配），非法输入抛 TypeError/ValueError
```

### Pedersen 可验证共享

群约束与 Feldman 相同，另需第二个生成元 `blinding_generator`：与 `generator`
不同、非 1、且同为阶恰为 `prime` 的元素。分发者额外生成一个同次数的随机盲化
多项式，承诺 `C_j = g ** a_j * h ** b_j` 同时隐藏系数 `a_j`。

```python
from thresholdsign import split_secret_pedersen, verify_pedersen_share

shares, blinding_shares, commitment = split_secret_pedersen(
    0xC0, 3, 5, prime=2017, group_prime=8069, generator=16, blinding_generator=256
)
assert all(
    verify_pedersen_share(share, blinding, commitment)
    for share, blinding in zip(shares, blinding_shares)
)
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
- `FeldmanCommitment(values, field_prime, group_prime, generator)` — 冻结数据类；
  `values[j] = generator ** a_j mod group_prime` 是第 `j` 个系数（`j = 0` 为常数项）的
  Feldman 承诺，系数本身不出现在对象中
- `split_secret_verifiable(secret, threshold, share_count, *, group_prime, generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 接受 `split_secret` 的全部参数，外加必填的群参数；沿用同一系数规则，返回 `(shares, commitment)`
- `verify_share(share, commitment)` — 校验
  `generator ** y == ∏ C_j ** (x ** j) mod group_prime`（指数按 `field_prime` 约简）；
  匹配返回 `True`，份额合法但被篡改或来自另一多项式返回 `False`
- `PedersenCommitment(values, field_prime, group_prime, generator, blinding_generator)`
  — 冻结数据类；`values[j] = generator ** a_j * blinding_generator ** b_j mod group_prime`
  是第 `j` 个系数（`j = 0` 为常数项）的 Pedersen 承诺，系数与盲化因子都不出现在对象中
- `split_secret_pedersen(secret, threshold, share_count, *, group_prime, generator, blinding_generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 接受 `split_secret` 的全部参数，外加必填的群参数与第二个生成元；秘密多项式
  沿用同一系数规则，再用同一 `randbelow` 生成 `threshold` 个盲化系数构成盲化多项式，
  返回 `(shares, blinding_shares, commitment)`，两个份额列表的 `x` 坐标相同
- `verify_pedersen_share(share, blinding_share, commitment)` — 校验
  `generator ** y * blinding_generator ** by == ∏ C_j ** (x ** j) mod group_prime`
  （指数按 `field_prime` 约简）；匹配返回 `True`，份额被篡改、两个份额坐标不同或
  交叉组合自不同多项式返回 `False`
- `reconstruct_secret(shares, *, prime=DEFAULT_PRIME)` — 在 `x = 0` 处做拉格朗日插值

### 群参数约束

`prime` 与 `group_prime` 必须为素数，`prime` 必须整除 `group_prime - 1`，且
`generator` 必须是模 `group_prime` 乘法群中阶恰为 `prime` 的非 1 元素；否则
`split_secret_verifiable` 抛 `ValueError`，非整数参数抛 `TypeError`。
`split_secret_pedersen` 在此基础上要求 `blinding_generator` 同样非 1、阶恰为
`prime`，且与 `generator` 不同。`verify_share` 与 `verify_pedersen_share` 对类型
错误抛 `TypeError`，对空承诺、越界坐标或非法承诺抛 `ValueError`；结构合法但校验
不匹配仅返回 `False`。

## 限制

这是单方分发加单方重建的共享方案：分发者自己构造多项式并持有完整秘密。借助
Feldman 承诺，接收者可以验证自己的份额与公开多项式一致、识别被篡改的份额，但
Feldman 方案对秘密不保信息论安全（常数项承诺 `C_0 = generator ** secret` 可被离线
字典攻击）。Pedersen 承诺用随机盲化因子隐藏了常数项承诺
（`C_0 = g ** secret * h ** b_0`，在离散对数假设下信息论隐藏秘密），但验证的
绑定性依赖分发者不知道 `log_g(h)`，且仍不包含分布式密钥生成（DKG）的交互轮次，
也没有门限签名、份额轮换或重共享能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
