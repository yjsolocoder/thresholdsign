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

### 主动份额刷新

签名密钥长期使用时，可用主动份额刷新（proactive refresh）在不改变联合秘密与
联合公钥的前提下重新随机化每个人持有的份额：每名参与者针对**当前**的
`SigningDKGResult` 各创建一份常数项固定为 0 的刷新贡献（共享多项式常数项不抽样，
其余 `threshold - 1` 个共享系数与全部 `threshold` 个盲化系数的抽取顺序、规则与
`create_signing_contribution` 相同），再把这些贡献聚合进旧密钥：

```python
from thresholdsign import SigningDKGResult, create_refresh, refresh

# key 是 aggregate_signing_dkg 的成功结果
contributions = [create_refresh(pid, key) for pid in key.result.participant_ids]
outcome = refresh(contributions, key)
if isinstance(outcome, SigningDKGResult):
    key = outcome          # 调用方必须销毁旧份额，改用新份额
else:
    ...                    # list[DKGRejection]，按 sender_id 定位失败贡献
```

刷新贡献的 Feldman 常数项承诺恒为 `g^0 = 1`，因此聚合时双份额按域相加、两类承诺
按群相乘后：联合秘密不变、`public_key` 不变（旧签名依旧有效），但各人的秘密份额
与 `verification_shares`（由新份额重算为 `g^{s_i}`）全部改变，结果与贡献顺序无关。
每名参与者必须恰好提交一份同参（编号集合、threshold、群参数）贡献；类型错误抛
`TypeError`，缺失、重复、参数不一致或结构非法抛 `ValueError`，而 Feldman 常数项
承诺不为 1、双份额与两类承诺不匹配等密码学校验失败按 `sender_id` 升序返回
`DKGRejection`。支持 `threshold = 1`。库不保存任何隐藏状态，旧份额的销毁与替换由
调用方负责。

### 成员重共享

刷新只能原班人马、原 threshold；要**更换成员集合或 threshold**（如 2-of-3 改为
3-of-5、剔除离任成员），用成员重共享（resharing）：旧参与者中达到旧 threshold 的
一个 quorum 作为 dealers，每人把自己的旧份额 `s_i` 乘以零点拉格朗日权重 `λ_i`
（对 dealers 集合求值）作为新共享多项式的常数项，向**新**成员集合重新分发。各
dealer 常数项之和 `Σ λ_i·s_i` 正是旧联合秘密，因此新份额重建的是同一个秘密、
`public_key` 不变、旧签名依旧有效：

```python
from thresholdsign import SigningDKGResult, create_reshare, reshare

# key 是旧 SigningDKGResult（参与者 (1,2,3)，threshold 2）
dealers = (1, 3)                 # 严格递增、唯一、不少于旧 threshold，
                                 # 且都属于旧 key 与新 members
members = (1, 3, 4, 5)           # 新成员集合
contributions = [
    create_reshare(
        dealer,
        key.result.shares[key.result.participant_ids.index(dealer)].y,  # 本人旧份额
        dealers, members, 3,     # 新 threshold
        key,
    )
    for dealer in dealers
]
outcome = reshare(contributions, dealers, key)
if isinstance(outcome, SigningDKGResult):
    new_key = outcome            # public_key 不变；新份额立即可签名
else:
    ...                          # list[DKGRejection]，按 sender_id 定位失败贡献
```

`create_reshare` 会校验提交的份额与旧验证份额 `Y_i` 匹配（不匹配抛 `ValueError`）；
新共享多项式的常数项 `λ_i·share mod q` 不抽样，随后从新 `threshold` 个系数位中依次
抽取 `t - 1` 个秘密系数和 `t` 个盲化系数（与 `create_signing_contribution` 同一
`randbelow` 约定）。聚合时双份额按域相加、Pedersen/Feldman 两类承诺按群相乘，结果与
贡献顺序无关；每份贡献的 Feldman 常数项承诺必须等于 `Y_i ** λ_i`、双份额必须与两类
承诺匹配，失败按 `sender_id` 升序返回 `DKGRejection`，类型错误抛 `TypeError`，
dealer 缺失/重复/非法或参数不一致抛 `ValueError`。新份额的分配与旧份额的销毁由
调用方负责，库不保存任何状态。

### 密钥轮换授权

重共享保持公钥不变；要**换一把全新的密钥**（新成员跑一次新的签名 DKG，得到新
`public_key`），需要让旧密钥的阈值签名公开授权这次切换。`rotation_payload` 生成
由旧密钥签署的规范消息，`Rotation` 证书把新旧公钥、新成员集合、新 threshold 与
群参数连同旧密钥的聚合签名捆在一起，`verify_rotation` 让任何持有旧公钥的人都能
核验授权——证书本身不含新旧秘密份额、nonce 或系数：

```python
from thresholdsign import Rotation, rotation_payload, verify_rotation

# old_key / new_key 均为 SigningDKGResult；new_key 由新成员重新跑签名 DKG 得到
payload = rotation_payload(
    old_key.public_key, new_key.public_key,
    new_key.result.participant_ids,      # 新成员编号（严格递增）
    len(new_key.result.commitment.values),  # 新 threshold
    q, p, g,                             # 共享的域素数、群素数、生成元
)
# payload 作为 SigningRound.message，由旧密钥的阈值 quorum 走两轮协议签署
round_info = create_signing_round(payload, signer_ids, nonce_commitments, old_key)
sig = aggregate_signature(shares, round_info, old_key)
cert = Rotation(
    old_key.public_key, new_key.public_key,
    new_key.result.participant_ids, len(new_key.result.commitment.values),
    q, p, g, sig,
)
assert verify_rotation(cert)             # 任何人都能核验
```

payload 依次拼接标签 `b"thresholdsign/rotation/v1"`、`q`、`p`、`g`、`old`、`new`、
4 字节无符号大端成员数、`t`、升序成员编号；除成员数外每个整数都是
`L = ceil(p.bit_length()/8)` 字节无符号大端，无分隔符或长度前缀，编号仅由成员数
定界，payload 不含签名。`rotation_payload` 对类型错误抛 `TypeError`，对非法群
参数、公钥（不在 q 阶子群）、编号（越界/重复/未递增）或 threshold 抛
`ValueError`；`verify_rotation` 重建 payload 并以 `old` 验签，一致返回 `True`，
合法但不匹配返回 `False`，类型错误抛 `TypeError`，证书结构非法（含签名结构）
抛 `ValueError`。新密钥的 DKG 执行与份额交接由调用方负责，库不保存任何状态。

要跨实现传输或持久化证书，用 `encode_rotation` / `decode_rotation` 的公开规范
编码。编码以标签 `b"thresholdsign/rotation-cert/v1"` 开头，随后依次写 `old`、
`new`、`ids`、`t`、`q`、`p`、`g`，最后写签名的 `R`、`z`、`signer_ids`，无额外
分隔符。每个整数都是 4 字节无符号大端长度前缀加该整数的最短无符号大端值：零
编码为单字节 `00`，正数禁止前导零；`ids` 与 `signer_ids` 均先写 4 字节元素数
再逐项编码：

```python
from thresholdsign import encode_rotation, decode_rotation, verify_rotation

blob = encode_rotation(cert)          # bytes，可自由传输/落盘，无隐藏状态
restored = decode_rotation(blob)      # Rotation
assert encode_rotation(restored) == blob   # 成功解码必可逐字节复现
assert verify_rotation(restored)            # 授权仍由 verify_rotation 核验
```

`encode_rotation` 只接受结构合法的 `Rotation`（不要求签名匹配，输出唯一）；
`decode_rotation` 拒绝非规范整数、截断、尾随字节、标签错误或计数不符，且不
验签——结构合法但签名不匹配的证书照常返回，由 `verify_rotation` 返回 `False`。
类型错误（含嵌套字段）抛 `TypeError`，负数、长度溢出、空编号、编号未递增/重复、
群参数、公钥或签名结构非法抛 `ValueError`。

### 可持久化的轮换授权链

单张证书只覆盖一次轮换；`RotationChain` 把多张 `Rotation` 按链序组成授权链，
使观察者从受信旧公钥 `anchor` 出发逐跳核验多次密钥轮换。冻结数据类
`RotationChain(anchor, certificates)` 可按位置构造、按值相等，
`certificates` 为非空且保序的证书元组。`verify_rotation_chain` 要求
`anchor == certificates[0].old`、相邻证书满足 `cert.new == next_cert.old`，
并对每张证书调用 `verify_rotation`，返回以上全部结果的逻辑与：

```python
from thresholdsign import RotationChain, verify_rotation_chain

# cert0/cert1/... 依次由上一把密钥签署，cert_i.new == cert_{i+1}.old
chain = RotationChain(old_key.public_key, (cert0, cert1))
assert verify_rotation_chain(chain)        # 从 anchor 逐跳核验
```

链的规范传输/持久化编码以标签 `b"thresholdsign/rotation-chain/v1"` 开头，
其后依次是 4 字节无符号大端的证书数、anchor 帧、链序证书帧；两类帧均为
4 字节无符号大端长度加内容，anchor 内容为其最短无符号大端整数（零为单字节
`00`），证书内容为 `encode_rotation(cert)`：

```python
from thresholdsign import encode_rotation_chain, decode_rotation_chain

blob = encode_rotation_chain(chain)            # bytes，无隐藏状态
restored = decode_rotation_chain(blob)         # RotationChain，不验签
assert encode_rotation_chain(restored) == blob
assert verify_rotation_chain(restored)
```

`decode_rotation_chain` 不验签、不校验衔接：结构合法但签名不匹配或
anchor/`old` 对不上的链照常返回，由 `verify_rotation_chain` 返回 `False`。
非 `RotationChain` 入参、非整数 anchor（含布尔）、非元组证书序列、元组中含
非 `Rotation` 元素抛 `TypeError`；空链、负数 anchor、长度溢出、空/零长帧、
非规范 anchor、证书数与帧数不符、截断、尾随字节或帧内证书非法抛
`ValueError`；非 `bytes` 的解码入参抛 `TypeError`。链本身不含任何网络、
存储或隐藏状态。

### 门限 Schnorr 认证的无状态审计链

`SigningAudit` 回执各自独立；`AuditChain` 把一批成功或失败回执按给定顺序
封装，并用一把门限密钥的 Schnorr 聚合签名封口。冻结数据类
`AuditChain(records, signature)` 可按位置构造、按值相等，`records` 为非空且
保序的 `(message, SigningAudit)` 元组。链消息
`audit_chain_payload(records, public_key)` 按

```text
b"ts/ac/v1" || H(BE(public_key)) || U64(len(records))
            || Σ_i ( H(message_i) || H(audit_i.payload) )
```

拼接（`H = SHA256`，`BE` 为最短无符号大端，`U64` 为 8 字节无符号大端），
作为旧密钥 `SigningRound.message` 走两轮协议签署：

```python
from thresholdsign import AuditChain, audit_chain_payload, verify_audit_chain

# records = ((message, audit), ...)，audit 由 create_audit 生成，成功/失败回执均可
payload = audit_chain_payload(records, key.public_key)
signature = sign_threshold(key, payload)   # 门限 quorum 两轮签署该 payload
chain = AuditChain(records, signature)
assert verify_audit_chain(chain, key)      # 任何人持 key 即可核验
```

`verify_audit_chain` 先按链序对每个记录调用 `check_audit` 逐项复核，再对链
消息调用 `verify_signature`。链消息同时绑定公钥、记录数、每条消息与每张回执
的摘要，因此删除、插入、重排记录，跨密钥替换回执，调换消息或篡改任一字节都
会使签名失效而返回 `False`；逐回执复核则保证封装的确实是该密钥下真实成功或
如实记录失败的回执。类型错误（非元组记录、记录非 `(bytes, SigningAudit)`、
非整数/布尔公钥等）抛 `TypeError`；空链、非正公钥、计数溢出（超过 2^64-1）
或回执、签名结构非法抛 `ValueError`。链不含任何网络、存储或隐藏状态。

`encode_audit_chain(chain)` / `decode_audit_chain(payload)` 为链提供可跨实现
传输与持久化的自定界规范编码，逐字节唯一、与链消息标签 `b"ts/ac/v1"` 无关：

```text
b"thresholdsign/audit-chain/v1" || U32(len(records))
|| Σ_i ( U32(len(message_i)) || message_i
         || U32(len(audit_i.payload)) || audit_i.payload )
|| VARINT(R) || VARINT(z) || U32(len(signer_ids)) || Σ_j VARINT(signer_id_j)
```

其中 `U32` 为 4 字节无符号大端，`VARINT` 为 4 字节无符号大端长度加最短无符号
大端值（零为单字节 `00`，正数禁前导零），记录顺序严格跟随 `records` 元组、
签名者编号严格升序。空消息允许、空回执不允许，链至少一条记录；签名的 `R` 必须
为正（与 `verify_signature` 对群元素的要求一致），`z` 可为零并编码为单字节
`00`。入口仅校验字段类型与结构（不要求回执或签名匹配）；解码只恢复结构，不解析
回执、不验签、不引入隐藏状态，结构合法但签名不匹配的链照常返回，由
`verify_audit_chain` 报告 `False`。非 `bytes` 或字段类型错误抛 `TypeError`；
标签错误、空链、零长回执、`R` 为零、记录或签名者计数超过 2^32-1、截断、尾随
字节、计数不符及非规范整数抛 `ValueError`；成功解码后重编码必得到原字节。

### 审计链记录的 Merkle 包含证明

需要向第三方证明某一条记录确实位于链所封的记录序列中，而又不必公开整批记录时，
可用 SHA256 Merkle 包含证明。冻结数据类 `AuditProof(i, n, m, a, p)` 字段依次为
叶下标 `int`、记录总数 `int`、该记录的消息 `bytes`、回执 `SigningAudit` 与自叶
至根的兄弟摘要元组 `tuple[bytes, ...]`（每项恰为 32 字节；单记录树时为空元组），
可按位置构造、按值相等。叶与内部节点按域分离前缀构造（`H = SHA256`，`U64` 为
8 字节无符号大端）：

```text
leaf_i = H(b"am/l" || U64(i) || H(message_i) || H(audit_i.payload))
node   = H(b"am/n" || left || right)      # 每层奇数尾节点复制自身配对
```

`make_proof(records, i) -> tuple[bytes, AuditProof]` 沿用
`AuditChain.records` 的非空保序结构构建整棵树，返回第 `i` 叶的证明与待签消息

```text
b"am/r" || U64(n) || root
```

该消息作为普通门限 Schnorr 消息由 quorum 两轮签署：

```python
from thresholdsign import make_proof, check_proof

message, proof = make_proof(records, i)
signature = sign_threshold(key, message)   # 门限 quorum 签署 b"am/r"||U64(n)||root
assert check_proof(proof, signature, key)  # 持 key 即可核验单条记录
```

`check_proof(proof, signature, key) -> bool` 先由 `proof` 的叶与 `p` 自叶至根重建
根：逐层维护当前层宽度，偶位置节点在左、奇位置在右；当某层宽度为奇数且当前节点恰
为最后一个时它没有同伴，以自身作兄弟（`H(node, node)`），该层所给兄弟随即无关，
宽度按 `(width+1)//2` 上收。再对该记录调用
`check_audit(m, a, key)` 复核回执，并对 `b"am/r"||U64(n)||root` 调用
`verify_signature`；三者一致返回 `True`，合法但不匹配（篡改消息、回执、下标、
非奇数尾层的路径兄弟或签名，换密钥核验等）返回 `False`。待签消息只绑定 `(n, root)`，故同一
棵树的一个根签名即可支撑任意叶的包含证明。非 `AuditProof`/`AggregateSignature`
入参或字段类型错误抛 `TypeError`；`n` 非正或超过 2^64-1、`i` 越界、空回执、`p` 长度与
`n` 不符（恰为 `(n-1).bit_length()`）或某项非 32 字节、回执或签名结构非法抛 `ValueError`。

要跨实现传输或持久化证明，用 `encode_audit_proof` / `decode_audit_proof` 的公开规范
编码，它只还原结构、不解析回执、不验签、不留状态：

```python
from thresholdsign import encode_audit_proof, decode_audit_proof

blob = encode_audit_proof(proof)             # bytes，可自由传输/落盘，无隐藏状态
restored = decode_audit_proof(blob)          # AuditProof
assert encode_audit_proof(restored) == blob  # 成功解码必可逐字节复现
```

编码依次直拼标签 `b"thresholdsign/audit-proof/v1"`、`VARINT(i)`、`VARINT(n)`、
消息帧、回执帧、4 字节路径数及逐字的 32 字节路径项。`VARINT` 为 4 字节无符号大端
长度 + 最短无符号大端值（零是单字节 `00`，正数禁前导零）；消息/回执帧均为 4 字节
无符号大端长度 + 原字节，消息可空、回执非空。约束 `0 < n < 2^64`、`0 <= i < n`、
路径数恰为 `(n-1).bit_length()`。

### 追加一致性证明

要向第三方证明一条旧记录序列是某条更长新序列的前缀，而不必公开任何消息或回执时，
可用同一棵 Merkle 树的追加一致性（extension）证明。冻结数据类
`AuditExtensionProof(old_n, leaves)` 字段依次为旧记录数 `int` 与新序列全部叶摘要
的保序元组 `tuple[bytes, ...]`（每项恰为 32 字节，即
`H(b"am/l" || U64(i) || H(message) || H(audit.payload))`），可按位置构造、按值相等。

`make_extension(records, old_n) -> tuple[bytes, bytes, AuditExtensionProof]` 沿用
`make_proof` 的树规则，返回旧、新两条待签消息（均为
`b"am/r" || U64(n) || root`，`n` 分别为旧记录数与总记录数）与携带全部叶摘要的证明；
两条消息各自由门限 quorum 签署后：

```python
from thresholdsign import make_extension, check_extension

old_message, new_message, proof = make_extension(records, old_n)
old_sig = sign_threshold(key, old_message)
new_sig = sign_threshold(key, new_message)
assert check_extension(proof, old_sig, new_sig, key)  # 观察者仅凭两个签名核验前缀关系
```

`check_extension(proof, old_sig, new_sig, key) -> bool` 由前 `old_n` 个叶重建旧根、
由全部叶重建新根，再对两条 `b"am/r"||U64(n)||root` 消息分别调用
`verify_signature`；两者皆验返回 `True`，合法但不匹配（篡改叶或 `old_n`、签名
对调或错配、换密钥核验等）返回 `False`。约束 `0 < old_n < n < 2^64`，叶元组非空
且每项恰为 32 字节；类型错误抛 `TypeError`，越界、空叶、叶宽错误等抛 `ValueError`。

要跨实现传输或持久化一致性证明，用 `encode_extension` / `decode_extension` 的公开
规范编码，它只还原结构、不解析叶摘要、不验签、不留状态：

```python
from thresholdsign import encode_extension, decode_extension

blob = encode_extension(proof)             # bytes，可自由传输/落盘，无隐藏状态
restored = decode_extension(blob)          # AuditExtensionProof
assert encode_extension(restored) == blob  # 成功解码必可逐字节复现
```

编码依次直拼标签 `b"thresholdsign/audit-extension/v1"`、8 字节无符号大端 `old_n`、
8 字节无符号大端叶数 `n`，再按原顺序直拼全部 32 字节叶摘要，不含额外分隔符；
约束 `0 < old_n < n < 2^64`，故总长度由标签与 `n` 唯一确定。`encode_extension`
只接受结构合法的证明（不调用 `check_extension`，不要求签名）；`decode_extension`
拒绝非 `bytes` 入参（`TypeError`）与坏标签、截断、尾随字节、计数不符、空叶、
越界或叶宽错误（`ValueError`）。

### 紧凑多记录包含证明

要以同一个根签名一次证明若干公开记录同属一条有序记录集（而非逐叶各取一个单叶
证明），可用多记录（multi）Merkle 包含证明。冻结数据类
`AuditMultiProof(indices, n, records, siblings)` 字段依次为严格递增的叶下标
元组 `tuple[int, ...]`、记录总数 `int`、与下标逐项等长对应的
`(message, SigningAudit)` 记录元组，以及重建根所需的 32 字节兄弟摘要元组
`tuple[bytes, ...]`（单记录树或全部叶均已公开时为空元组），可按位置构造、
按值相等。

`make_multi_proof(records, indices) -> tuple[bytes, AuditMultiProof]` 沿用
`make_proof` 的树规则（叶、节点、奇数尾复制均相同），由非空保序的
`AuditChain.records` 记录结构与非空、严格递增且在 `0..n-1` 内的下标构建；兄弟
按层自叶向根收集，每层内按位置升序：兄弟已随所选记录公开（同伴本身也被选中）
或当前节点为奇数尾（以自身配对）时省略，否则追加该兄弟摘要。返回待签消息

```text
b"am/r" || U64(n) || root
```

与多记录证明，待签消息仍是与单叶证明完全相同的根消息，无隐藏状态：

```python
from thresholdsign import make_multi_proof, check_multi_proof

message, proof = make_multi_proof(records, (0, 2, 4))
signature = sign_threshold(key, message)          # 门限 quorum 签署同一个根消息
assert check_multi_proof(proof, signature, key)   # 一个根签名覆盖多条记录
```

`check_multi_proof(proof, signature, key) -> bool` 按 `proof.siblings` 的层序与
层内升序消费兄弟重建根：奇数尾节点与自身配对，两个同伴均已公开时直接配对，其余
已知节点按位置奇偶（偶在左、奇在右）与下一个兄弟配对，宽度按 `(width+1)//2`
上收；再逐条对 `(message, SigningAudit)` 调用
`check_audit(m, a, key)` 复核全部公开记录，并对
`b"am/r"||U64(n)||root` 调用 `verify_signature`。三者一致返回 `True`，合法但
不匹配（记录在下标间互换或改动、兄弟或签名不符、换密钥核验等）返回 `False`。
非 `AuditMultiProof`/`AggregateSignature` 入参或字段类型错误抛 `TypeError`；
空索引、`n` 非正或超过 2^64-1、下标越界或非严格递增、`records` 与 `indices`
数量不同、空回执、兄弟项非 32 字节、兄弟缺失/多余或结构非法、回执或签名结构
非法抛 `ValueError`。单下标的多记录证明语义与单叶证明一致（奇数尾那条自配对
兄弟按省略规则不再携带），旧接口 `AuditProof`/`make_proof`/`check_proof` 保持
不变。


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
- `create_refresh(sender_id, key, *, randbelow=secrets.randbelow)` — 用既有
  `SigningDKGResult` `key` 的群参数、参与者编号与 threshold 创建一份主动刷新贡献
  `SigningContribution`；共享多项式常数项固定为 0 且不抽样（Feldman 常数项承诺为
  `g^0 = 1`），其余系数的抽取顺序与规则完全沿用 `create_signing_contribution`；
  支持 `threshold = 1`（此时没有非常数系数抽取）
- `refresh(contributions, key)` — 用每名参与者恰好一份的同参零常数贡献刷新 `key`：
  双份额按域相加、Pedersen/Feldman 两类承诺按群相乘，并重算 `verification_shares`；
  联合秘密与 `public_key` 不变（旧签名仍有效），结果与贡献顺序无关。全部通过返回
  新的 `SigningDKGResult`，否则返回按 `sender_id` 升序的 `list[DKGRejection]`（Feldman
  常数项承诺不为 1、双份额不匹配两类承诺者各一条）；类型错误抛 `TypeError`，缺失、
  重复、参数不一致或结构非法抛 `ValueError`。库不保存隐藏状态，调用方须销毁旧份额、
  改用返回份额
- `create_reshare(sender, share, dealers, members, threshold, key, *, rng=secrets.randbelow)`
  — 旧参与者 `sender` 为成员重共享创建一份 `SigningContribution`：`dealers` 是严格
  递增、唯一、人数不少于旧 threshold 的旧参与者 quorum，且每人同时属于旧 `key` 与新
  `members`；`share` 是 sender 的旧秘密份额，必须与旧验证份额 `Y_i` 匹配（不匹配抛
  `ValueError`）。新共享多项式（对新成员集合、新 `threshold`）常数项固定为
  `λ_i·share mod q`（`λ_i` 是 sender 在 dealers 上的零点拉格朗日权重，不抽样），
  随后依次抽取 `threshold - 1` 个秘密系数与 `threshold` 个盲化系数
- `reshare(contributions, dealers, key)` — 聚合每名 dealer 恰好一份的重共享贡献：
  双份额按域相加、Pedersen/Feldman 两类承诺按群相乘，结果与贡献顺序无关；每份贡献
  的 Feldman 常数项承诺必须等于 `Y_i ** λ_i` 且双份额匹配两类承诺，失败按
  `sender_id` 升序返回 `list[DKGRejection]`；类型错误抛 `TypeError`，dealer 缺失、
  重复、非法或参数不一致抛 `ValueError`。成功返回新成员集合与新 threshold 下的
  `SigningDKGResult`：新常数项之和即旧联合秘密，`public_key` 不变（旧签名仍有效），
  新份额立即可用于签名，`verification_shares` 由新份额重算为 `g^{s_i}`。库不保存
  隐藏状态，新份额分发与旧份额销毁由调用方负责
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
- `SigningAudit(payload)` — 冻结数据类，仅含 `payload` 一个字段；一次签名轮次第
  二轮校验的审计回执，自包含的字节编码中不含 nonce、秘密份额或系数
- `create_audit(message, shares, round_info, dkg_result)` — `message` 必须与轮次
  消息一致（不一致抛 `ValueError`）；轮次中每名签名者必须
  恰好提交一份份额（重复/缺失抛 `ValueError`，类型错误抛 `TypeError`），按
  `signer_id` 升序以 `verify_signature_share` 重验后生成 `SigningAudit`：payload
  依次拼接标签 `b"thresholdsign/audit/v1"`、32 字节 `SHA256(message)`、`Y`、`R`、
  `c`（均为 Schnorr 宽度 `L` 字节无符号大端）、4 字节无符号大端行数 `n`、按
  `signer_id` 升序的 `n` 行（每行 `id`、`R_i`、`z_i` 各 `L` 字节）、1 字节
  status 与 1 字节 present；行内原样记录提交的 `nonce_commitment` 与 `z`，
  承诺错配或份额方程失败不改写行值；全部份额通过时 status=1、present=1 并追加
  聚合 `z = Σ z_i mod q`（`L` 字节），否则 status=0、present=0 且不追加 `z`
- `check_audit(message, receipt, dkg_result)` — 解码回执（结构或解码非法抛
  `ValueError`，类型错误抛 `TypeError`；行数少于 threshold、编号非参与者或不
  递增、`R_i` 不是 q 阶子群非单位元同属非法）并以头部 `R`、`c` 重算消息摘要、
  公钥、Fiat-Shamir 挑战、逐行份额校验 `g^z_i = R_i·Y_i^(c·λ_i)` 以及 status
  为 1 时的聚合 `z` 与聚合签名 `g^z = R·Y^c`；各行 `R_i` 之积异于头部 `R`
  或份额方程失败都计入重算 status=0，与记录的 status 对比而非直接判负，因此
  原样生成的失败回执复核为 `True`；重算结论与回执一致返回 `True`，合法篡改
  或消息/密钥不匹配返回 `False`
- `NonceReuse(signer_id, nonce_commitment, receipts)` — 冻结数据类，可按位置
  构造、按值相等；同一签名者重复使用同一轮次一承诺 `R_i` 的证据：`receipts`
  为含该 `(signer_id, R_i)` 行的 status=1 审计回执，按 `payload` 字节序去重
  排列
- `find_nonce_reuse(records, dkg_result) -> tuple[NonceReuse, ...]` — 无状态
  随机数复用审计：`records` 各项为 `(message, receipt)`（消息在前），逐项先以
  `check_audit` 复核（结构非法抛 `ValueError`，类型错误抛 `TypeError`，合法
  回执但消息或密钥不匹配同样抛 `ValueError`），仅 status=1 的回执参与；按
  解码行的 `(signer_id, R_i)` 分组，同一对不同 payload 至少出现两次才报告
  复用（重复提交同一回执不制造告警）；结果按 `signer_id`、`nonce_commitment`
  升序，与输入顺序无关；函数只检查本批输入，不留历史
- `Rotation(old, new, ids, t, q, p, g, sig)` — 冻结数据类，可按位置构造、按值
  相等；公开可验证的密钥轮换授权证书：`old`/`new` 为新旧联合公钥，`ids` 为严格
  递增的新成员编号元组，`t` 为新 threshold，`q`/`p`/`g` 为域素数、群素数与
  生成元，`sig` 为旧密钥对 `rotation_payload` 规范消息的 `AggregateSignature`；
  不含新旧秘密份额、nonce 或系数
- `rotation_payload(old, new, ids, t, q, p, g) -> bytes` — 生成由旧密钥签署的
  规范消息（作为 `SigningRound.message`）：依次拼接标签
  `b"thresholdsign/rotation/v1"`、`q`、`p`、`g`、`old`、`new`、4 字节无符号大端
  成员数、`t`、升序成员编号；除成员数外每个整数均为
  `L = ceil(p.bit_length()/8)` 字节无符号大端，无分隔符或长度前缀，编号仅由
  成员数定界，payload 不含签名。类型错误抛 `TypeError`，非法群参数、公钥、
  编号或 threshold 抛 `ValueError`
- `verify_rotation(cert) -> bool` — 由证书字段重建 payload 并以 `old` 验签：
  一致返回 `True`，结构合法但签名/字段不匹配返回 `False`；类型错误抛
  `TypeError`，证书结构非法（群参数、公钥、编号、threshold 或签名结构）抛
  `ValueError`。新密钥的生成与份额交接由调用方负责
- `encode_rotation(cert) -> bytes` — 证书的规范传输/持久化编码：以标签
  `b"thresholdsign/rotation-cert/v1"` 开头，依次写 `old`、`new`、`ids`、`t`、
  `q`、`p`、`g` 及签名的 `R`、`z`、`signer_ids`，无额外分隔符；每个整数为
  4 字节无符号大端长度前缀 + 最短无符号大端值（零为单字节 `00`，正数禁前导
  零），`ids`/`signer_ids` 均先写 4 字节元素数再逐项编码。只校验结构、不要求
  签名匹配且输出唯一；类型错误抛 `TypeError`，负数、长度溢出或结构非法抛
  `ValueError`
- `decode_rotation(payload) -> Rotation` — `encode_rotation` 的逆操作：拒绝
  错误/缺失标签、非规范整数、截断、尾随字节或计数不符，成功后重编码必得到原
  字节；不验签，结构合法但签名不匹配由 `verify_rotation` 返回 `False`。
  非 `bytes` 入参抛 `TypeError`，其余非法情形抛 `ValueError`
- `RotationChain(anchor, certificates)` — 冻结数据类，可按位置构造、按值
  相等；`anchor` 为受信旧公钥整数，`certificates` 为非空且保序的
  `Rotation` 元组，链序相邻证书须满足前一张 `new` 等于下一张 `old`
- `verify_rotation_chain(chain) -> bool` — 要求 `anchor` 等于首张证书的
  `old`、相邻证书 `new == next.old`，并逐张调用 `verify_rotation`，返回
  上述结果的逻辑与；结构合法但衔接断裂或签名不匹配返回 `False`；非
  `RotationChain` 入参、anchor/证书元素类型错误抛 `TypeError`，空链或证书
  结构非法抛 `ValueError`
- `encode_rotation_chain(chain) -> bytes` — 授权链的规范编码：以标签
  `b"thresholdsign/rotation-chain/v1"` 开头，其后为 4 字节无符号大端证书数、
  anchor 帧、链序证书帧；两类帧均为 4 字节无符号大端长度加内容，anchor
  内容为最短无符号大端整数（零为单字节 `00`），证书内容为
  `encode_rotation(cert)`；输出唯一、不验签。类型错误抛 `TypeError`，空链、
  负数/溢出 anchor 或非法证书抛 `ValueError`
- `decode_rotation_chain(payload) -> RotationChain` —
  `encode_rotation_chain` 的逆操作，不验签：拒绝错误/缺失标签、空链、负数或
  非规范 anchor、帧内非法证书、计数不符、溢出、截断、尾随字节，成功后重编码
  必得到原字节；签名不匹配或衔接断裂由 `verify_rotation_chain` 返回 `False`。
  非 `bytes` 入参抛 `TypeError`，其余非法情形抛 `ValueError`
- `AuditChain(records, signature)` — 冻结数据类，可按位置构造、按值相等；
  由门限 Schnorr 签名认证的无状态审计链：`records` 为非空且保序的
  `(message, SigningAudit)` 元组，链序即回执封装顺序，`signature` 为对
  `audit_chain_payload(records, public_key)` 的 `AggregateSignature`；构造时不
  校验，核验由 `verify_audit_chain` 负责
- `audit_chain_payload(records, public_key) -> bytes` — 生成由门限密钥签署的
  规范链消息（作为 `SigningRound.message`）：依次拼接标签 `b"ts/ac/v1"`、
  `H(BE(public_key))`（`H = SHA256`，`BE` 为最短无符号大端，零为单字节 `00`）、
  8 字节无符号大端记录数 `U64(len(records))`，并按元组顺序逐项追加
  `H(message) || H(audit.payload)`；payload 不含签名。`records` 各项须为
  `(bytes, SigningAudit)` 二元组，类型错误（含非元组序列、非整数/布尔公钥）
  抛 `TypeError`；空链、非正公钥或计数超过 2^64-1 抛 `ValueError`
- `verify_audit_chain(chain, key) -> bool` — 先按链序对每个记录调用
  `check_audit(message, audit, key)` 逐项复核（成功回执与如实记录的失败回执
  均可通过），再以 `key` 的群参数与 `key.public_key` 对
  `audit_chain_payload` 的链消息调用 `verify_signature`；全部一致返回 `True`。
  删除、插入、重排记录，跨密钥替换回执，调换消息，篡改回执或签名，或换一把
  密钥核验均返回 `False`；非 `AuditChain`/`AggregateSignature` 入参或记录、
  密钥字段类型错误抛 `TypeError`，空链、回执或签名结构非法抛 `ValueError`
- `encode_audit_chain(chain) -> bytes` — 审计链的规范传输/持久化编码：以标签
  `b"thresholdsign/audit-chain/v1"` 开头，其后为 4 字节无符号大端记录数，再按
  `records` 元组顺序逐条写记录帧与最后的签名帧。每条记录先写 4 字节无符号
  大端消息长度及原始 `message`（允许空），再写 4 字节无符号大端回执长度及
  `SigningAudit.payload`（不允许空）；签名帧依次写 `VARINT(R)`、`VARINT(z)`、
  4 字节无符号大端 `signer_ids` 数量及升序编号，`VARINT` 为 4 字节无符号大端
  长度加最短无符号大端值（`R` 必须为正；`z` 可为零，零为单字节 `00`，正数禁
  前导零）。输出唯一，只校验字段类型与结构、不要求回执或签名匹配；类型错误抛
  `TypeError`，空链、空回执、非正 `R`、负 `z`、计数超过 2^32-1、溢出或编号非
  升序等结构非法抛 `ValueError`
- `decode_audit_chain(payload) -> AuditChain` — `encode_audit_chain` 的逆操作，
  只恢复结构：回执不解析、签名不核验且不引入任何网络、存储或隐藏状态。拒绝
  错误/缺失标签、空链、零长回执、`R` 为零、截断、尾随字节、计数不符、
  空/零/重复/非升序签名者编号及非规范整数（前导零或零长整数帧）；成功后重编码
  必得到原字节。非 `bytes` 入参抛 `TypeError`，其余非法情形抛 `ValueError`；
  结构合法但签名不匹配由 `verify_audit_chain` 返回 `False`
- `AuditProof(i, n, m, a, p)` — 冻结数据类，字段依次为叶下标 `int`、记录总数
  `int`、记录消息 `bytes`、`SigningAudit` 回执、自叶至根的 32 字节兄弟摘要
  `tuple[bytes, ...]`（单记录树为空元组）；可按位置构造、按值相等；构造时不
  校验，核验由 `check_proof` 负责
- `make_proof(records, i) -> tuple[bytes, AuditProof]` — 对沿用
  `AuditChain.records` 的非空保序 `(message, SigningAudit)` 元组建 SHA256
  Merkle 树：叶为 `H(b"am/l"||U64(i)||H(message)||H(audit.payload))`，父节点为
  `H(b"am/n"||left||right)`，每层奇数尾节点复制自身配对；返回待签消息
  `b"am/r"||U64(n)||root` 与第 `i` 叶证明。索引非整数（含布尔）或记录类型错误
  抛 `TypeError`；空记录、计数超过 2^64-1 或 `i` 越界抛 `ValueError`
- `check_proof(proof, signature, key) -> bool` — 逐层维护宽度并按
  `proof.p` 自叶至根重建根（奇数尾无同伴时以自身作兄弟），对
  `(proof.m, proof.a)` 调用 `check_audit` 并对
  `b"am/r"||U64(n)||root` 调用 `verify_signature`；全部一致返回 `True`，结构
  合法但不匹配返回 `False`。非 `AuditProof`/`AggregateSignature` 入参或字段类型
  错误抛 `TypeError`，`n` 非正或超 2^64-1、`i` 越界、空回执、路径长度不符
  （恰为 `(n-1).bit_length()`）或兄弟非 32 字节、回执/签名结构非法抛 `ValueError`
- `encode_audit_proof(proof) -> bytes` — 证明的规范传输/持久化编码：依次直拼
  标签 `b"thresholdsign/audit-proof/v1"`、`VARINT(i)`、`VARINT(n)`、消息帧、
  回执帧、4 字节路径数及逐字 32 字节路径项；`VARINT` 为 4 字节长度 + 最短无符号
  大端值（零为 `00`，正数禁前导零），消息可空、回执非空。只接受结构合法的
  `AuditProof`（`0 < n < 2^64`、`0 <= i < n`、路径数恰为
  `(n-1).bit_length()`），不解析回执、不验签；输出唯一、无状态。字段类型错误抛
  `TypeError`，空回执、越界/溢出、路径不符或超长帧抛 `ValueError`
- `decode_audit_proof(payload) -> AuditProof` — `encode_audit_proof` 的逆操作，
  仅还原结构、不解析回执、不验签、不留状态：拒绝非 `bytes`、坏/缺标签、空回执、
  越界或超 2^64-1 的 `n`、非规范整数（前导零或超长）、截断/尾随字节及计数/路径
  不符；成功后重编码必逐字节等于输入。非 `bytes` 入参抛 `TypeError`，其余非法
  情形抛 `ValueError`；结构合法但回执或签名不匹配由 `check_proof` 返回 `False`
- `AuditExtensionProof(old_n, leaves)` — 冻结数据类；追加一致性证明：`old_n` 为
  旧记录数，`leaves` 为新序列全部 32 字节叶摘要的保序元组，可按位置构造、按值相等
- `make_extension(records, old_n) -> (old_message, new_message, proof)` — 沿用
  `make_proof` 的树规则，返回旧、新两条待签消息（均为
  `b"am/r"||U64(n)||root`）与携带全部叶摘要的 `AuditExtensionProof`。`old_n`
  非整数（含布尔）或记录类型错误抛 `TypeError`；空记录、计数超过 2^64-1 或
  `old_n` 不在 `0 < old_n < n` 抛 `ValueError`
- `check_extension(proof, old_sig, new_sig, key) -> bool` — 由前 `old_n` 个叶与
  全部叶分别重建旧、新根，对两条 `b"am/r"||U64(n)||root` 消息各调用
  `verify_signature`；皆验返回 `True`，结构合法但不匹配返回 `False`。非
  `AuditExtensionProof`/`AggregateSignature` 入参或字段类型错误抛 `TypeError`，
  空叶、叶非 32 字节、总数超 2^64-1、`old_n` 越界或签名/密钥结构非法抛
  `ValueError`
- `encode_extension(proof) -> bytes` — 一致性证明的规范传输/持久化编码：依次直拼
  标签 `b"thresholdsign/audit-extension/v1"`、8 字节无符号大端 `old_n`、8 字节
  无符号大端叶数 `n` 及按原顺序的全部 32 字节叶摘要，不含额外分隔符；总长度由
  标签与 `n` 唯一确定。只接受结构合法的 `AuditExtensionProof`
  （`0 < old_n < n < 2^64`），不调用 `check_extension`、不要求签名；输出唯一、
  无状态。字段类型错误抛 `TypeError`，空叶、越界或叶宽错误抛 `ValueError`
- `decode_extension(payload) -> AuditExtensionProof` — `encode_extension` 的逆
  操作，仅还原结构、不解析叶摘要、不验签、不留状态：拒绝非 `bytes`、坏/缺标签、
  空叶、越界、截断、尾随字节及计数不符；成功后重编码必逐字节等于输入。非
  `bytes` 入参抛 `TypeError`，其余非法情形抛 `ValueError`；结构合法但签名不匹配
  由 `check_extension` 返回 `False`
- `AuditMultiProof(indices, n, records, siblings)` — 冻结数据类，字段依次为
  非空严格递增叶下标元组 `tuple[int, ...]`、记录总数 `int`、与下标逐项等长对应
  的 `(message, SigningAudit)` 记录元组，以及自叶向根、层内按位置升序的 32 字节
  兄弟摘要 `tuple[bytes, ...]`（单记录树或全部叶公开时为空）；可按位置构造、
  按值相等；构造时不校验，核验由 `check_multi_proof` 负责
- `make_multi_proof(records, indices) -> tuple[bytes, AuditMultiProof]` — 对
  沿用 `AuditChain.records` 的非空保序记录元组建与 `make_proof` 相同的 SHA256
  Merkle 树，为非空、严格递增且在 `0..n-1` 内的下标集生成紧凑证明：每层升序，
  兄弟已随所选记录公开或当前节点为奇数尾（自身配对）时省略，否则追加该兄弟
  摘要；返回与单叶证明相同的待签消息 `b"am/r"||U64(n)||root` 与多记录证明。
  `indices` 非元组、下标非整数（含布尔）或记录类型错误抛 `TypeError`；空记录、
  空索引、计数超过 2^64-1、下标越界或非严格递增抛 `ValueError`
- `check_multi_proof(proof, signature, key) -> bool` — 按层序与层内升序消费
  `proof.siblings` 重建根（奇数尾自配对、同伴均公开时直接配对、偶位置在左奇位置
  在右），逐条对 `proof.records` 调用 `check_audit` 并对
  `b"am/r"||U64(n)||root` 调用 `verify_signature`；全部一致返回 `True`，结构
  合法但不匹配（记录互换/改动、摘要或签名不符、换密钥等）返回 `False`。非
  `AuditMultiProof`/`AggregateSignature` 入参或字段类型错误抛 `TypeError`，空
  索引、`n` 非正或超 2^64-1、下标越界或非严格递增、`records` 与 `indices` 数量
  不同、空回执、兄弟非 32 字节、兄弟缺失/多余或结构非法、回执/签名结构非法抛
  `ValueError`

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
调用方在已认证的通道上交换贡献。`create_refresh` / `refresh` 在参与者集合、
threshold 与群参数都不变的前提下提供主动份额刷新（旧份额须由调用方销毁替换）；
`create_reshare` / `reshare` 在此基础上支持更换成员集合与 threshold 的重共享：
达到旧 threshold 的旧参与者 quorum 把旧秘密重新分发给新成员集合，联合秘密与
`public_key` 不变，但重共享同样不含网络、认证与持久化，且不能识别伪装成合法
dealer 的敌对方——dealer 集合的协商与成员身份的认证由调用方保证。门限 Schnorr 签名
在 DKG 之上增加两轮计算：第一轮的随机数承诺交换与第二轮的签名份额聚合同样不含
网络、认证、存储；轮次对象不做重放防护，跨消息/轮次的复用由挑战绑定与份额校验
识别，但是否为同一消息启用新一轮由调用方决定。一次性非数 `r_i` 的复用防护也不在
实现内（库不保存任何状态）：复用会导致秘密份额泄露，调用方必须保证每次签名都用
新抽取的非数。

## 测试

```bash
python3 -m unittest discover -s tests
```
