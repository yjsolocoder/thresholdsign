# thresholdsign

有限域上的 Shamir 秘密共享。把一份秘密拆成 `share_count` 份，任意 `threshold` 份可重建，少于 `threshold` 份得不到关于秘密的信息。支持 Feldman 与 Pedersen 可验证秘密共享（VSS）：接收者可凭承诺公开验证自己的份额是否落在分发多项式上，而无需信任分发者；Pedersen 承诺还对秘密本身信息论保密。在此之上还提供单轮 Pedersen 分布式密钥生成（DKG）：多名参与者各自贡献随机性，联合生成无人知晓完整秘密的共享密钥；以及构建在 DKG 之上的两轮门限 Schnorr 签名：任意不少于 `threshold` 名参与者可联合对消息签名，签名可用联合公钥验证。

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

在 Pedersen VSS 之上，多名已认证参与者可以各自贡献随机性，联合生成无人知晓
完整秘密的共享密钥（不含网络、广播、持久化或签名，传输与认证由调用方保证）。
每名参与者用相同的参与者编号集合、`threshold` 和群参数各创建一份贡献，向每个
编号分发一对双份额并公开 Pedersen 承诺；随后任何人都可以聚合所有贡献：

```python
from thresholdsign import (
    DKGResult, aggregate_dkg, create_dkg_contribution, reconstruct_secret,
)

participant_ids = (1, 2, 3)
contributions = [
    create_dkg_contribution(
        pid, participant_ids, 2,
        prime=2017, group_prime=8069, generator=16, blinding_generator=256,
    )
    for pid in participant_ids
]
outcome = aggregate_dkg(contributions)
if isinstance(outcome, DKGResult):
    # 联合秘密 = 各参与者随机常数项之和，任何一方都无从得知；
    # 任意 2 名接收者可用各自的聚合份额重建它
    assert reconstruct_secret(outcome.shares[:2], prime=2017) == \
        reconstruct_secret(outcome.shares[1:], prime=2017)
else:
    # 验证失败的贡献：list[DKGRejection]，可按 sender_id 定位
    ...
```

聚合时双份额按 `field_prime` 逐项相加、承诺按 `group_prime` 逐项相乘，输入顺序
不影响结果；每名参与者必须恰好贡献一份且参数一致，缺失、重复或参数不一致抛
`ValueError`，验证不通过的贡献以 `DKGRejection` 逐个列出，不会被静默忽略。

### 两轮门限 Schnorr 签名

在 DKG 之上，任意不少于 `threshold` 名参与者可以两轮交互对一条消息联合签名：
密钥生成阶段每人创建签名贡献（原 Pedersen 贡献外加对**同一**秘密多项式的
Feldman 承诺），聚合后得到联合公钥 `Y` 与每人的验证份额 `Y_i`；签名阶段第一轮
每人抽取一次性非零随机数 `r_i` 并发布 `R_i = g ** r_i`，第二轮各自计算并发布
签名份额 `z_i = r_i + c * λ_i * s_i mod q`（`λ_i` 为签名者集合在 `x = 0` 处的
拉格朗日权重），任何人可公开验证每份份额并聚合成签名 `(R, z)`，最终用联合公钥
验签 `g ** z == R * Y ** c`。

```python
from thresholdsign import (
    Signature, SigningDKGResult,
    aggregate_signatures, aggregate_signing_dkg,
    create_nonce_commitment, create_signature_share, create_signing_contribution,
    verify_signature,
)

participant_ids = (1, 2, 3)
contributions = [
    create_signing_contribution(
        pid, participant_ids, 2,
        prime=2017, group_prime=8069, generator=16, blinding_generator=256,
    )
    for pid in participant_ids
]
outcome = aggregate_signing_dkg(contributions)
assert isinstance(outcome, SigningDKGResult)
Y = outcome.public_key                      # 联合公钥
# outcome.verification_shares[i] 是 participant_ids[i] 的验证份额 Y_i

message = b"hello"
signer_ids = (1, 3)                         # 任意不少于 threshold 名参与者
# 第一轮：各自抽取一次性随机数并公开承诺（随机数绝不复用）
nonces, commitments = {}, []
for sid in signer_ids:
    r_i, R_i = create_nonce_commitment(
        sid, prime=2017, group_prime=8069, generator=16
    )
    nonces[sid] = r_i                       # r_i 保密，仅用于第二轮
    commitments.append(R_i)                 # R_i 公开
# 第二轮：各自用聚合秘密份额计算签名份额
shares = [
    create_signature_share(
        sid, message, nonce=nonces[sid],
        share=outcome.dkg_result.shares[outcome.dkg_result.participant_ids.index(sid)],
        nonce_commitments=commitments, result=outcome,
    )
    for sid in signer_ids
]
signature = aggregate_signatures(
    shares, message, nonce_commitments=commitments, result=outcome
)
if isinstance(signature, Signature):
    assert verify_signature(
        signature, message, public_key=Y,
        prime=2017, group_prime=8069, generator=16,
    )
else:
    # 验证失败的签名份额：list[SigningRejection]，按 signer_id 定位
    ...
```

挑战值 `c` 由标签 `b"thresholdsign/schnorr/v1"`、消息的 SHA-256 摘要以及 `Y`、`R`、
各签名者编号的 `L` 字节无符号大端编码（`L = ceil(group_prime.bit_length() / 8)`）
依次连接后再取 SHA-256，摘要按大端转整数模 `field_prime` 得到。每份签名份额按
`g ** z_i == R_i * Y_i ** (c * λ_i)` 校验，篡改、跨消息/跨轮次或承诺错配的份额在
聚合时按 `signer_id` 排序逐个拒绝，绝不忽略且与输入顺序无关；最终验签对结构合法
但不匹配的签名返回 `False`。`threshold = 1` 时即退化为单人 Schnorr 签名。

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
- `DKGContribution(sender_id, participant_ids, shares, blinding_shares, commitment)`
  — 冻结数据类；一名参与者的 DKG 贡献：`participant_ids` 严格递增且无重复，
  `shares[i]` / `blinding_shares[i]` 是发给 `participant_ids[i]` 的双份额，
  `commitment` 是对发送者随机共享多项式与盲化多项式的 Pedersen 承诺，系数不出现
- `DKGReceivedShare(sender_id, receiver_id, share, blinding_share)` — 冻结数据类；
  接收者从贡献中取出的双份额，含收发双方编号
- `DKGResult(participant_ids, shares, blinding_shares, commitment)` — 冻结数据类；
  聚合成功结果：每名接收者的聚合双份额、联合承诺与参与者编号，不含联合秘密或系数
- `DKGRejection(sender_id)` — 冻结数据类；验证失败的贡献，按发送者编号定位
- `create_dkg_contribution(sender_id, participant_ids, threshold, *, group_prime, generator, blinding_generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 为每名参与者编号生成双份额并返回贡献；编号限 `1..prime-1` 且唯一，发送者必须是
  参与者之一；共享与盲化多项式的全部系数（各 `threshold` 个）都由 `randbelow` 抽取，
  确定性随机源产生全零贡献也是合法的
- `verify_dkg_received_share(received, commitment)` — 沿用 Pedersen 校验接收份额：
  匹配返回 `True`，合法篡改或坐标与 `receiver_id` 错配返回 `False`；非法编号、坐标或
  承诺抛 `TypeError`/`ValueError`
- `aggregate_dkg(contributions)` — 聚合每名参与者恰好一份且参数一致的贡献：双份额按
  `field_prime` 相加、承诺按 `group_prime` 逐项相乘，输入顺序不影响结果；全部验证通过
  返回 `DKGResult`，否则返回 `list[DKGRejection]`（每个验证失败的发送者一条，绝不静默
  忽略）；类型错误抛 `TypeError`，缺失或重复参与者、非法编号或承诺、参数不一致抛
  `ValueError`；任意 `threshold` 名接收者可用聚合份额经 `reconstruct_secret` 重建联合
  秘密
- `SigningContribution(dkg_contribution, feldman_commitment)` — 冻结数据类；签名用途的
  DKG 贡献：`dkg_contribution` 是原 Pedersen 贡献，`feldman_commitment` 是对**同一**
  秘密多项式的 Feldman 承诺，秘密与系数均不出现
- `SigningDKGResult(dkg_result, public_key, verification_shares)` — 冻结数据类；签名
  DKG 聚合结果：原 `DKGResult`、联合公钥 `Y`（各贡献 Feldman 常数项承诺之积）与每个
  参与者编号的验证份额 `Y_i`（各 Feldman 承诺在该编号处的求值之积），不含联合秘密
- `create_signing_contribution(sender_id, participant_ids, threshold, *, group_prime, generator, blinding_generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 参数与校验同 `create_dkg_contribution`，返回原 Pedersen 贡献及对同一秘密多项式的
  Feldman 承诺
- `aggregate_signing_dkg(contributions)` — 沿用 `aggregate_dkg` 的全部校验，并额外校验
  每份 Feldman 承诺的参数、门限一致性及其与份额的匹配；全部通过返回
  `SigningDKGResult`，否则返回 `list[DKGRejection]`（按 `sender_id` 排序，与输入顺序
  无关）
- `NonceCommitment(signer_id, value)` — 冻结数据类；签名第一轮的随机数承诺
  `value = R_i = generator ** r_i mod group_prime`，随机数 `r_i` 本身不在对象中
- `create_nonce_commitment(signer_id, *, group_prime, generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 返回 `(r_i, NonceCommitment)`：`r_i` 由可注入的 `randbelow` 抽取的一次性非零随机数
  （均匀分布于 `1..prime-1`），务必保密且绝不跨消息/跨会话复用；`R_i` 公开发布
- `SignatureShare(signer_id, value)` — 冻结数据类；签名第二轮的签名份额 `z_i`
- `create_signature_share(signer_id, message, *, nonce, share, nonce_commitments, result)`
  — 用自己的一次性随机数 `nonce`、聚合秘密份额 `share`（其 `x` 必须等于 `signer_id`）
  和本轮全部随机数承诺计算 `z_i = r_i + c * λ_i * s_i mod field_prime`；签名者编号必须
  唯一、为 DKG 参与者且不少于 `threshold`，否则抛 `ValueError`
- `verify_signature_share(share, message, *, nonce_commitments, result)` — 校验
  `g ** z_i == R_i * Y_i ** (c * λ_i) mod group_prime`；匹配返回 `True`，合法但被篡改
  或跨消息/轮次的份额返回 `False`；非法输入抛 `TypeError`/`ValueError`
- `SigningRejection(signer_id)` — 冻结数据类；验证失败的签名份额，按签名者编号定位
- `Signature(signer_ids, nonce, value)` — 冻结数据类；聚合签名：`signer_ids` 严格递增，
  `nonce` 为组合承诺 `R = ∏ R_i`，`value` 为组合响应 `z = Σ z_i mod field_prime`
- `aggregate_signatures(shares, message, *, nonce_commitments, result)` — 校验并聚合本轮
  全部签名份额：每名签名者必须恰好提交一份，重复或缺失抛 `ValueError`；全部验证通过
  返回 `Signature`，否则返回 `list[SigningRejection]`（按 `signer_id` 排序，绝不静默
  忽略）；同一签名会话中随机数承诺重复（随机数复用）或为单位元（零随机数）抛
  `ValueError`
- `verify_signature(signature, message, *, public_key, group_prime, generator, prime=DEFAULT_PRIME)`
  — 重算挑战 `c` 并校验 `g ** z == R * Y ** c mod group_prime`；匹配返回 `True`，结构
  合法但不匹配返回 `False`，非法输入抛 `TypeError`/`ValueError`

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
单轮 Pedersen DKG 消除了"分发者知道完整秘密"这一点：联合秘密是各参与者随机常数
项之和，任何一方都无从得知。但 DKG 只覆盖密钥生成的一轮计算——贡献的网络传输、
广播信道的可靠性与一致性、参与者身份认证（签名）、状态持久化都不在此实现，需要
调用方在已认证的通道上交换贡献；它也没有份额轮换或重共享能力。两轮门限 Schnorr
签名在 DKG 之上提供联合签名能力，但同样不含网络、认证、存储与重放防护：随机数
`r_i` 的一次性由调用方保证（复用同一随机数会泄露秘密份额，本实现只能在同一会话
内检出重复的承诺值），签名会话与消息、轮次的绑定完全依赖挑战值中的哈希，跨会话
的重放需要调用方自行防护。

## 测试

```bash
python3 -m unittest discover -s tests
```
