# thresholdsign

有限域上的 Shamir 秘密共享。把一份秘密拆成 `share_count` 份，任意 `threshold` 份可重建，少于 `threshold` 份得不到关于秘密的信息。支持 Feldman 与 Pedersen 可验证秘密共享（VSS）：接收者可凭承诺公开验证自己的份额是否落在分发多项式上，而无需信任分发者；Pedersen 承诺还对秘密本身信息论保密。在此之上还提供单轮 Pedersen 分布式密钥生成（DKG）：多名参与者各自贡献随机性，联合生成无人知晓完整秘密的共享密钥。DKG 之上还提供两轮门限 Schnorr 签名：每个签名者独立发布一次性随机数承诺，再各自产出可公开验证的签名份额，聚合后任何人都可凭联合公钥验签。

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

### 门限 Schnorr 签名

签名用的 DKG 在普通贡献之外，再对**同一条共享多项式**附带一个 Feldman 承诺；
聚合后除原封不动的 `DKGResult` 外，还得到联合公钥 `Y = g^s` 和每名参与者的
验证份额 `Y_i = g^{s_i}`（`s_i` 是该参与者的聚合秘密份额，`s` 是无人知晓的联合
秘密）。签名分两轮：

```python
from thresholdsign import (
    aggregate_signature, aggregate_signing_dkg, create_signature_share,
    create_signing_contribution, create_signing_nonce_commitment,
    create_signing_round, verify_signature,
)

participant_ids = (1, 2, 3)
contributions = [
    create_signing_contribution(
        pid, participant_ids, 2,
        prime=2017, group_prime=8069, generator=16, blinding_generator=256,
    )
    for pid in participant_ids
]
key = aggregate_signing_dkg(contributions)          # SigningDKGResult
# key.result 即原 DKGResult；key.public_key 为 Y；key.verification_shares 为各 Y_i

message = b"pay Alice 5"
signer_ids = (2, 3)                                  # 严格递增、唯一、不少于 threshold
# 第一轮：每人一次性非零随机数 r_i，公开 R_i = g^r_i
commitments, nonces = [], {}
for pid in signer_ids:
    commitment_i, r_i = create_signing_nonce_commitment(
        pid, prime=2017, group_prime=8069, generator=16,
    )
    commitments.append(commitment_i)
    nonces[pid] = r_i                                 # 仅本人持有，用后即弃，禁止复用
round_info = create_signing_round(message, signer_ids, commitments, key)
# R = ∏ R_i；挑战 c 已固定在轮次对象中

# 第二轮：每人以零点拉格朗日权重 λ_i 计算 z_i = r_i + c·λ_i·s_i mod q
shares = [
    create_signature_share(
        pid, key.result.shares[key.result.participant_ids.index(pid)].y,
        nonces[pid], round_info, key,
    )
    for pid in signer_ids
]
assert all(verify_signature_share(share, round_info, key) for share in shares)

signature = aggregate_signature(shares, round_info, key)   # AggregateSignature(R, z, ids)
assert verify_signature(
    message, signature, key.public_key,
    prime=2017, group_prime=8069, generator=16,
)                                                        # g^z = R·Y^c
```

挑战采用 Fiat-Shamir：令 `L = ceil(group_prime.bit_length() / 8)`，依次连接标签
`b"thresholdsign/schnorr/v1"`、消息的 SHA-256 摘要、`Y`、`R` 及各签名者编号，
每个整数占 `L` 字节无符号大端，连接结果再取 SHA-256，摘要按大端转整数后模
`field_prime`。轮次对象因此绑定消息、签名者集合与全部 `R_i`：换消息、换签名者、
换轮次或篡改份额都会使份额验证返回 `False`。`aggregate_signature` 要求轮次中的
每名签名者恰好提交一份份额（重复或缺失抛 `ValueError`），异常份额按 `signer_id`
排序以 `SignatureShareRejection` 逐个拒绝，与输入顺序无关，绝不静默忽略。
支持 `threshold = 1`。一次性随机数由可注入的 `randbelow` 在 `prime - 1` 个值上
抽取并自动排除零（返回值加一），复用防护需要调用方保证——本实现不保存任何状态。


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
- `SigningContribution(contribution, feldman_commitment)` — 冻结数据类；面向签名的 DKG
  贡献：`contribution` 是原封不动的 `DKGContribution`（Pedersen 双份额与承诺），
  `feldman_commitment` 是对**同一条**共享多项式（不含盲化多项式）的
  `FeldmanCommitment`，系数不出现在对象中
- `create_signing_contribution(sender_id, participant_ids, threshold, *, group_prime, generator, blinding_generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 参数与校验和 `create_dkg_contribution` 完全一致；返回 `SigningContribution`，
  Pedersen 与 Feldman 承诺来自同一次抽取的共享多项式
- `SigningDKGResult(result, public_key, verification_shares)` — 冻结数据类；签名 DKG
  聚合成功结果：`result` 是原 `DKGResult`，`public_key` 是联合公钥
  `Y = g^s`，`verification_shares` 是每名参与者一份的验证份额元组
  `Y_i = g^{s_i}`（与 `result.participant_ids` 对齐）；不含联合秘密、秘密份额或系数
- `aggregate_signing_dkg(contributions)` — 沿用 `aggregate_dkg` 的全部既有校验（双份额
  仍按各发送者的 Pedersen 承诺验证；失败返回按 `sender_id` 排序的
  `list[DKGRejection]`，顺序无关），另校验各 Feldman 承诺与 Pedersen 承诺同群、同
  threshold 且绑定同一条共享多项式（不一致为非法输入，抛 `ValueError`）；成功返回
  `SigningDKGResult`，其中 `Y` 为各常数项 Feldman 承诺之积、`Y_i` 为各承诺在 `i` 处
  求值之积
- `SigningNonceCommitment(signer_id, commitment)` — 冻结数据类；第一轮随机数承诺
  `R_i = g^r_i mod group_prime`，非数本身不出现
- `create_signing_nonce_commitment(signer_id, *, group_prime, generator, prime=DEFAULT_PRIME, randbelow=secrets.randbelow)`
  — 以注入的 `randbelow` 在 `prime - 1` 个值（`0..prime-2`）上抽取并加一，保证非数
  `1 <= r_i <= prime-1` 非零；返回 `(SigningNonceCommitment, r_i)`，非数只交给本人，
  禁止跨消息/轮次复用
- `SigningRound(message, signer_ids, nonce_commitments, R, challenge)` — 冻结数据类；
  固定一次签名实例的第一轮材料：`signer_ids` 严格递增、唯一、均为 DKG 参与者且不少于
  `threshold`，`nonce_commitments` 与编号一一对应且 `R_i` 互异、属于阶 `field_prime`
  子群；`R` 为各 `R_i` 之积，`challenge` 为下述 Fiat-Shamir 挑战
- `create_signing_round(message, signer_ids, nonce_commitments, dkg_result)` — 校验并
  组装轮次：编号重复/未递增/不足 `threshold`/非参与者、承诺缺失多余/编号错配/重复/
  不在子群内抛 `ValueError`，类型错误抛 `TypeError`；输入顺序不影响结果
- `schnorr_challenge(message, public_key, R, signer_ids, *, field_prime, group_prime)` —
  计算挑战：`L = ceil(group_prime.bit_length()/8)`，把标签
  `b"thresholdsign/schnorr/v1"`、`SHA256(message)`、`Y`、`R` 及各签名者编号的 `L` 字节
  无符号大端编码依次连接后再取 SHA-256，摘要按大端转整数模 `field_prime`
- `SignatureShare(signer_id, nonce_commitment, z)` — 冻结数据类；第二轮份额：
  `z_i = r_i + c·λ_i·s_i mod field_prime`，`λ_i` 为该签名者在当前签名集合上的零点
  拉格朗日权重；不含非数与秘密份额
- `create_signature_share(signer_id, secret_share, nonce, round_info, dkg_result)` —
  产出本人的签名份额；签名者不在轮次/ DKG 中、份额或非数越界、非数与公布的 `R_i`
  不匹配抛 `ValueError`，类型错误抛 `TypeError`
- `verify_signature_share(share, round_info, dkg_result)` — 校验
  `g^z_i = R_i·Y_i^(c·λ_i) mod group_prime`，并重新推导 `R` 与 `c`；匹配返回 `True`，
  份额被篡改、随机数承诺错配、来自另一消息/轮次/签名者集合返回 `False`，非法输入抛
  `TypeError`/`ValueError`
- `SignatureShareRejection(signer_id)` — 冻结数据类；验证失败的签名份额，按签名者
  编号定位
- `AggregateSignature(R, z, signer_ids)` — 冻结数据类；门限 Schnorr 聚合签名，
  `signer_ids` 记录挑战所绑定的签名者集合
- `aggregate_signature(shares, round_info, dkg_result)` — 校验并求和：轮次中每名签名者
  必须恰好提交一份（重复/缺失抛 `ValueError`），每个份额经 `verify_signature_share`
  校验，异常份额按 `signer_id` 排序返回 `list[SignatureShareRejection]`（顺序无关、
  绝不忽略）；全部通过时 `z = Σ z_i mod field_prime`，返回
  `AggregateSignature(R, z, signer_ids)`
- `verify_signature(message, signature, public_key, *, group_prime, generator, prime=DEFAULT_PRIME)`
  — 用 `signature.signer_ids` 重建挑战并校验 `g^z = R·Y^c`；合法签名返回 `True`，
  签名被篡改或与消息/公钥/签名者集合不匹配返回 `False`，非法参数抛
  `TypeError`/`ValueError`

### 门限 Schnorr 群参数与边界

签名复用 DKG 的群参数：`prime`（即阶 `q`）整除 `group_prime - 1`，`generator` 是阶恰为
`prime` 的生成元，Pedersen 设置另需不同的 `blinding_generator`。各接口沿用既有
`TypeError`/`ValueError` 边界：类型错误抛 `TypeError`，结构非法（编号越界/重复/缺失、
承诺不在子群、threshold 越界等）抛 `ValueError`，结构合法但密码学不匹配一律返回
`False` 或进入拒绝列表。

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
调用方在已认证的通道上交换贡献；它也没有份额轮换或重共享能力。门限 Schnorr 签名
在 DKG 之上增加两轮计算：第一轮的随机数承诺交换与第二轮的签名份额聚合同样不含
网络、认证、存储；轮次对象不做重放防护，跨消息/轮次的复用由挑战绑定与份额校验
识别，但是否为同一消息启用新一轮由调用方决定。一次性非数 `r_i` 的复用防护也不在
实现内（库不保存任何状态）：复用会导致秘密份额泄露，调用方必须保证每次签名都用
新抽取的非数。

## 测试

```bash
python3 -m unittest discover -s tests
```
