# thresholdsign

有限域上的 Shamir 秘密共享。把一份秘密拆成 `share_count` 份，任意 `threshold` 份可重建，少于 `threshold` 份得不到关于秘密的信息。支持 Feldman 与 Pedersen 可验证秘密共享（VSS）：接收者可凭承诺公开验证自己的份额是否落在分发多项式上，而无需信任分发者；Pedersen 承诺还对秘密本身信息论保密。

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

群参数与 Feldman 相同，另需第二个生成元 `blinding_generator`：与 `generator` 不同、非 1、阶同样恰为 `prime`。盲化系数使常数项承诺对秘密信息论保密（即使验证者算力无限也算不出秘密），这一隐藏性不依赖离散对数难题；若还需要承诺的绑定性（分发者不能用两种方式打开承诺），则要求无人知道 `h` 关于 `g` 的离散对数，实际部署须由可信设置产生 `h`。下例仅为便于验算的玩具参数，取 `h = g ** 2`。

```python
from thresholdsign import split_secret_pedersen, verify_pedersen_share

# group_prime = 4 * prime + 1 = 8069；16 与 256 = 16 ** 2 是阶为 2017 的两个不同生成元
shares, blinding_shares, commitment = split_secret_pedersen(
    0xC0, 3, 5,
    prime=2017, group_prime=8069, generator=16, blinding_generator=256,
)
assert all(
    verify_pedersen_share(share, blinding_share, commitment)
    for share, blinding_share in zip(shares, blinding_shares)
)
```

除秘密多项式 `f(x)` 外，分发者另选随机盲化多项式 `g(x)`（常数项也是随机的），
公开承诺 `C_j = generator ** a_j * blinding_generator ** b_j mod group_prime`。
每个接收者拿到一对同坐标份额 `(f(x), g(x))`；份额被篡改、两份额坐标不同或把
两套拆分交叉组合时，验证返回 `False`。

### 单轮 Pedersen DKG

已认证参与者可以执行单轮 Pedersen 分布式密钥生成：每名参与者用相同的参与者编号
集合、`threshold` 和群参数各自调用一次 `create_dkg_contribution`，把生成的贡献
分发给所有人；任何人都能用 `aggregate_dkg` 把恰好每人一份的贡献聚合成每个接收者
的最终双份额和联合承诺。联合秘密等于各参与者秘密贡献之和，没有任何一方（包括
协调者）知道完整秘密。本实现不含网络、广播、持久化或签名——发送者认证与传输由
调用方负责。

```python
from thresholdsign import create_dkg_contribution, aggregate_dkg

ids = (1, 2, 3)
contributions = [
    create_dkg_contribution(
        sender, ids, 2,
        prime=2017, group_prime=8069, generator=16, blinding_generator=256,
    )
    for sender in ids
]
results = aggregate_dkg(contributions)  # 有贡献未通过校验时返回 DKGRejection
# 每名接收者持有一对聚合双份额；任意 threshold 名接收者可重建联合秘密
```

聚合前每个接收者（或协调者）可用 `verify_dkg_received_share` 单独校验收到的
双份额；`aggregate_dkg` 内部会对所有贡献做同样的校验，失败时返回携带
`sender_id` 的 `DKGRejection` 而不是抛异常，结构性问题（缺失或重复参与者、
非法编号或承诺、参数不一致）仍抛 `ValueError`/`TypeError`。

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
  是第 `j` 个系数（`j = 0` 为常数项）的 Pedersen 承诺，秘密系数 `a_j` 与盲化系数 `b_j`
  均不出现在对象中；常数项承诺因此隐藏秘密
- `split_secret_pedersen(secret, threshold, share_count, *, group_prime, generator, blinding_generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 接受 `split_secret` 的全部参数，外加必填的群参数与第二个生成元；秘密多项式规则不变，
  同一个 `randbelow` 再抽取 `threshold` 个盲化系数，返回
  `(shares, blinding_shares, commitment)`；两个份额列表同位置坐标相同
- `verify_pedersen_share(share, blinding_share, commitment)` — 校验
  `generator ** y * blinding_generator ** y' == ∏ C_j ** (x ** j) mod group_prime`
  （指数按 `field_prime` 约简）；匹配返回 `True`，份额被篡改、两份额坐标不同或交叉组合
  返回 `False`
- `reconstruct_secret(shares, *, prime=DEFAULT_PRIME)` — 在 `x = 0` 处做拉格朗日插值
- `DKGReceivedShare(sender_id, receiver_id, share, blinding_share)` — 冻结数据类；
  一份贡献中发给某一接收者的双份额，含收发双方编号；诚实构造时
  `share.x == blinding_share.x == receiver_id`
- `DKGContribution(sender_id, participant_ids, shares, commitment)` — 冻结数据类；
  一名参与者的贡献：`participant_ids` 严格递增且唯一，`shares` 按同顺序每名
  参与者一份 `DKGReceivedShare`，`commitment` 是发送者双多项式的 Pedersen 承诺；
  多项式系数与秘密贡献不出现在对象中
- `DKGResult(receiver_id, share, blinding_share, commitment, participant_ids)` —
  冻结数据类；聚合成功后一名接收者的结果：聚合双份额（各贡献双份额按
  `field_prime` 相加）、联合承诺（各承诺按 `group_prime` 逐项相乘）与参与者
  编号；不含联合秘密或任何系数
- `DKGRejection(sender_id)` — 冻结数据类；聚合失败的结果，含未通过校验的贡献
  的发送者编号
- `create_dkg_contribution(sender_id, participant_ids, threshold, *, group_prime, generator, blinding_generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 为 `participant_ids` 中的每个编号生成双份额并返回贡献；编号与发送者编号限
  `1..prime-1` 且编号唯一（存储为严格递增）；秘密贡献与全部系数都由
  `randbelow` 抽取，确定性随机源产生全零贡献也是合法输入
- `verify_dkg_received_share(received_share, contribution)` — 沿用
  `verify_pedersen_share` 的 Pedersen 校验，并要求收发编号与坐标一致；匹配返回
  `True`，合法篡改或坐标错配返回 `False`，非法输入抛 `TypeError`/`ValueError`
- `aggregate_dkg(contributions)` — 要求每名参与者恰有一份参数一致的贡献并逐一
  校验；成功时返回按参与者编号排序的 `DKGResult` 列表（与输入顺序无关），有贡献
  未通过校验时返回 `DKGRejection`；类型错误抛 `TypeError`，缺失或重复参与者、
  非法编号或承诺、参数不一致抛 `ValueError`

### 群参数约束

`prime` 与 `group_prime` 必须为素数，`prime` 必须整除 `group_prime - 1`，且
`generator` 必须是模 `group_prime` 乘法群中阶恰为 `prime` 的非 1 元素；Pedersen 的
`blinding_generator` 还必须与 `generator` 不同且同为阶恰为 `prime` 的非 1 元素。否则
`split_secret_verifiable` / `split_secret_pedersen` 抛 `ValueError`，非整数参数抛
`TypeError`。`verify_share` / `verify_pedersen_share` 对类型错误抛 `TypeError`，对
空承诺、越界坐标或非法承诺抛 `ValueError`；结构合法但校验不匹配仅返回 `False`。

## 限制

这是单方分发加单方重建的共享方案：分发者自己构造多项式并持有完整秘密。借助
Feldman 承诺，接收者可以验证自己的份额与公开多项式一致、识别被篡改的份额，但
Feldman 方案对秘密不保信息论安全（常数项承诺 `C_0 = generator ** secret` 可被离线
字典攻击），也不能识别分发者在重建阶段提交的错误份额以外的恶意行为。Pedersen 方案
在同一验证能力之上额外隐藏常数项：`C_0 = g ** secret * h ** b_0` 对秘密信息论保密，
可抵抗离线字典攻击，但代价是每个接收者要保存一对份额，且分发者仍知道完整秘密。
DKG 流程让每名参与者各贡献一份随机性、无人知道完整的联合秘密，但它是单轮协议：
只覆盖贡献的生成、校验与聚合，不含网络传输、广播信道、持久化或签名，发送者认证
需由调用方保证；也没有门限签名、份额轮换或重共享能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
