"""认证封套的确定性实现契约。

令牌是 bytes，所有整数都使用大端序，布局固定为：

    version    1 字节，当前唯一合法值是 1
    counter    8 字节，取值范围是 1 到 2 的 64 次方减 1
    ciphertext 填充后的密文，长度必须是 16 的整数倍
    tag        32 字节，HMAC-SHA256 认证标签

认证标签覆盖 build_aad(version, aad, counter) 与整个头部和密文，因此 open
必须先校验标签，再解密和去填充。版本与计数器既在头部中，也在附加认证数据
中。unpad 与 open 的任何失败都必须抛 ValueError，消息统一为
invalid envelope，不得暴露失败原因。

实现只使用 Python 标准库 hashlib、hmac，不使用随机数、当前时间或外部服务。
明文、密文与附加数据都是 bytes。所有比较容差为 0。
"""

import hashlib
import hmac

VERSION = 1
BLOCK_SIZE = 16
TAG_SIZE = 32
HEADER_SIZE = 9
COUNTER_MAX = (1 << 64) - 1
INVALID_MESSAGE = "invalid envelope"


def _fail() -> ValueError:
    return ValueError(INVALID_MESSAGE)


def _require_bytes(value, name: str, allow_empty: bool) -> bytes:
    if not isinstance(value, bytes):
        raise _fail()
    if not allow_empty and not value:
        raise _fail()
    return value


def _require_int(value, name: str, low: int, high: int) -> int:
    # bool 是 int 的子类，但不是一个合法的版本号、计数器或长度。
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail()
    if value < low or value > high:
        raise _fail()
    return value


def _require_key(key) -> dict:
    if not isinstance(key, dict):
        raise _fail()
    try:
        enc = key["enc"]
        mac = key["mac"]
    except (KeyError, TypeError):
        raise _fail() from None
    if not isinstance(enc, bytes) or len(enc) != 32:
        raise _fail()
    if not isinstance(mac, bytes) or len(mac) != 32:
        raise _fail()
    return key


def derive_keys(master: bytes, context: bytes) -> dict:
    """从主密钥与上下文派生加密键和认证键。

    契约：
    - master 必须是非空 bytes，context 必须是非空 bytes，否则抛 ValueError。
    - 返回恰好包含 enc 与 mac 两个键的 dict，两个值都是 32 字节。
    - 必须做域分离，按下面两式精确派生：
      enc 等于 HMAC-SHA256(master, b"MTE-ENC" 与 context 的拼接)
      mac 等于 HMAC-SHA256(master, b"MTE-MAC" 与 context 的拼接)
    - 两个键必须不同，同一 master 下不同 context 的键也必须不同。
    """
    _require_bytes(master, "master", allow_empty=False)
    _require_bytes(context, "context", allow_empty=False)

    enc = hmac.new(master, b"MTE-ENC" + context, hashlib.sha256).digest()
    mac = hmac.new(master, b"MTE-MAC" + context, hashlib.sha256).digest()
    return {"enc": enc, "mac": mac}


def build_aad(version: int, context: bytes, counter: int) -> bytes:
    """构造参与认证的附加数据。

    契约：
    - version 必须是 1 到 255 的整数，context 必须是非空 bytes，counter
      必须是 1 到 2 的 64 次方减 1 的整数，否则抛 ValueError。
    - 返回值精确为：
      b"MTE-AAD" 加 version 的单字节 加 counter 的 8 字节大端 加 context
      长度的 4 字节大端 加 context
    - 版本与计数器都必须实际出现在结果中，改变任一值都必须改变结果。
    """
    _require_int(version, "version", 1, 255)
    _require_bytes(context, "context", allow_empty=False)
    _require_int(counter, "counter", 1, COUNTER_MAX)

    return (
        b"MTE-AAD"
        + bytes([version])
        + counter.to_bytes(8, "big")
        + len(context).to_bytes(4, "big")
        + context
    )


def xor_stream(key: bytes, counter: int, length: int) -> bytes:
    """用计数器模式生成密钥流。

    契约：
    - key 必须是恰好 32 字节的 bytes，counter 必须是 1 到 2 的 64 次方减 1
      的整数，length 必须是非负整数，否则抛 ValueError。
    - 计数器零值一律拒绝，即使 length 为零也必须抛 ValueError。
    - 第 i 个密钥流块为：
      HMAC-SHA256(key, b"MTE-STREAM" 加 counter 的 8 字节大端 加 i 的
      8 字节大端)，i 从 0 开始。
    - 返回按块拼接后的前 length 字节；相同输入必须得到相同结果，不同计数器
      的前 16 字节必须不同。
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise _fail()
    _require_int(counter, "counter", 1, COUNTER_MAX)
    _require_int(length, "length", 0, (1 << 63) - 1)

    blocks = []
    produced = 0
    index = 0
    while produced < length:
        block = hmac.new(
            key,
            b"MTE-STREAM" + counter.to_bytes(8, "big") + index.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        blocks.append(block)
        produced += len(block)
        index += 1
    return b"".join(blocks)[:length]


def pad(data: bytes, block: int) -> bytes:
    """按 PKCS#7 规则填充，返回块整数倍长度。

    契约：
    - data 必须是 bytes，block 必须是 2 到 255 的整数，否则抛 ValueError。
    - 填充字节数为 block 减去 data 长度对 block 取余，结果范围 1 到 block；
      每字节的值都等于填充字节数，因此整块对齐时也要追加一个完整块。
    - 空 data 合法，返回恰好一个 block 的填充。
    """
    _require_bytes(data, "data", allow_empty=True)
    _require_int(block, "block", 2, 255)

    amount = block - len(data) % block
    return data + bytes([amount]) * amount


def unpad(data: bytes, block: int) -> bytes:
    """去除并严格校验 PKCS#7 填充。

    契约：
    - data 必须是非空 bytes 且长度是 block 的整数倍，block 必须是 2 到 255
      的整数，否则抛 ValueError，消息必须为 invalid envelope。
    - 末字节 n 必须在 1 到 block 之间，末尾 n 个字节必须全部等于 n；不能只
      检查总长度是 block 的整数倍，也不能只读取末字节。
    - 填充内容非法时抛 ValueError，消息必须为 invalid envelope，不得暴露
      填充错误细节。
    - 校验通过后返回去掉末尾 n 字节的前缀。
    """
    _require_bytes(data, "data", allow_empty=False)
    _require_int(block, "block", 2, 255)
    if len(data) % block != 0:
        raise _fail()

    amount = data[-1]
    if amount < 1 or amount > block or amount > len(data):
        raise _fail()
    if data[-amount:] != bytes([amount]) * amount:
        raise _fail()
    return data[:-amount]


def seal(key: dict, plaintext: bytes, aad: bytes) -> bytes:
    """封装明文，返回包含版本、计数器、密文和标签的字节令牌。

    契约：
    - key 必须是 derive_keys 返回的映射，恰好提供 32 字节的 enc 与 mac；
      plaintext 必须是 bytes，aad 必须是非空 bytes，否则抛 ValueError。
    - 版本固定写为 1。计数器必须非零，按下面公式确定性派生，不使用随机数：
      seed 等于 HMAC-SHA256(mac, b"MTE-CTR" 加 aad 长度的 4 字节大端 加
      aad 加 plaintext)
      counter 等于 1 加 seed 前 8 字节的大端整数对 2 的 64 次方减 1 取余
    - 头部为版本单字节加计数器 8 字节大端。
    - 先固定版本、计数器与附加数据，再对 16 字节分组做填充和计数器模式加密，
      最后生成覆盖附加数据、头部和密文的 HMAC-SHA256 标签；不得只认证明文
      而漏掉头部。
    - 返回头部加密文加 32 字节标签。相同输入必须得到完全相同的令牌。
    """
    _require_key(key)
    _require_bytes(plaintext, "plaintext", allow_empty=True)
    _require_bytes(aad, "aad", allow_empty=False)

    mac = key["mac"]
    enc = key["enc"]

    seed = hmac.new(
        mac,
        b"MTE-CTR" + len(aad).to_bytes(4, "big") + aad + plaintext,
        hashlib.sha256,
    ).digest()
    counter = 1 + int.from_bytes(seed[:8], "big") % COUNTER_MAX

    header = bytes([VERSION]) + counter.to_bytes(8, "big")
    padded = pad(plaintext, BLOCK_SIZE)
    stream = xor_stream(enc, counter, len(padded))
    ciphertext = bytes(left ^ right for left, right in zip(padded, stream))
    tag = hmac.new(
        mac,
        build_aad(VERSION, aad, counter) + header + ciphertext,
        hashlib.sha256,
    ).digest()

    return header + ciphertext + tag


def open(key: dict, token: bytes, aad: bytes) -> bytes:
    """先验认证再解密，返回原始明文。

    契约：
    - key 与 aad 的校验同 seal；token 必须是 bytes，否则抛 ValueError。
    - 解析头部后，版本必须精确等于 1，计数器必须非零，密文长度必须是 16 的
      整数倍，标签长度必须是 32 字节。
    - 必须用 hmac.compare_digest 比较重新计算的标签与令牌标签，禁止使用普通
      等号。标签校验通过前不得调用 xor_stream 或 unpad，也不得解密。
    - 标签校验失败、头部被改写、附加数据不符、去填充失败或结构非法时，统一
      抛 ValueError，消息必须为 invalid envelope，不得区分失败原因。
    - 校验通过后解密并去填充，返回明文；任何情况下都不得返回未经认证的明文。
    """
    _require_key(key)
    _require_bytes(aad, "aad", allow_empty=False)
    _require_bytes(token, "token", allow_empty=True)

    if len(token) < HEADER_SIZE + TAG_SIZE:
        raise _fail()

    version = token[0]
    counter = int.from_bytes(token[1:HEADER_SIZE], "big")
    ciphertext = token[HEADER_SIZE:-TAG_SIZE]
    tag = token[-TAG_SIZE:]

    if version != VERSION:
        raise _fail()
    if counter < 1 or counter > COUNTER_MAX:
        raise _fail()
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise _fail()
    if len(tag) != TAG_SIZE:
        raise _fail()

    expected_tag = hmac.new(
        key["mac"],
        build_aad(version, aad, counter) + token[:HEADER_SIZE] + ciphertext,
        hashlib.sha256,
    ).digest()

    # 认证必须在任何解密或去填充之前完成，且必须使用常量时间比较。
    if not hmac.compare_digest(expected_tag, tag):
        raise _fail()

    stream = xor_stream(key["enc"], counter, len(ciphertext))
    padded = bytes(left ^ right for left, right in zip(ciphertext, stream))
    return unpad(padded, BLOCK_SIZE)


def envelope_batch(items, policy: dict) -> dict:
    """批量封装并立即解封，各条目完全独立。

    items 是 list[dict]，每项包含 context、aad、plaintext，三者都是 bytes，
    且 context 与 aad 非空。policy 是 dict，包含非空 bytes 的 master。

    处理规则：
    - 对每一项独立调用 derive_keys(policy["master"], item["context"])，再调用
      seal 与 open，禁止复用上一条的键、计数器、附加数据或中间状态。
    - 同一 context 下的不同条目也必须使用不同计数器，第二条不得沿用第一条
      的密钥流；批量结果必须与逐条单独封装完全一致。
    - 单项失败只影响该项，后续项继续处理；不得原地修改 items 或 policy。
    - 返回 {"tokens": list, "plaintexts": list, "problems": dict}。两个列表
      与 items 等长，失败位置为 None；problems 以失败下标为键，值为
      invalid envelope。成功项不写入 problems。
    """
    if not isinstance(policy, dict) or "master" not in policy:
        raise _fail()
    master = _require_bytes(policy["master"], "master", allow_empty=False)
    if not isinstance(items, list):
        raise _fail()

    tokens = []
    plaintexts = []
    problems = {}

    for index, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise _fail()
            context = _require_bytes(item["context"], "context", allow_empty=False)
            aad = _require_bytes(item["aad"], "aad", allow_empty=False)
            plaintext = _require_bytes(
                item["plaintext"], "plaintext", allow_empty=True
            )

            # 每条独立派生键并独立封解，绝不沿用上一条的键、计数器或状态。
            keys = derive_keys(master, context)
            token = seal(keys, plaintext, aad)
            recovered = open(keys, token, aad)
        except (ValueError, KeyError, TypeError):
            tokens.append(None)
            plaintexts.append(None)
            problems[index] = INVALID_MESSAGE
            continue

        tokens.append(token)
        plaintexts.append(recovered)

    return {"tokens": tokens, "plaintexts": plaintexts, "problems": problems}
