import json
import os
from typing import Dict, Literal, Tuple, List

token_price_config_file = os.path.join(os.path.dirname(__file__), 'token_price_config.json')
with open(token_price_config_file, 'r') as f:
    token_price_config = json.load(f)

TOKEN_USED_TABLE: Dict[Tuple[int, int], float] = {
    tuple(map(lambda x: int(x, 16), k.split(':'))): v
    for k, v in token_price_config.get("token_used_table", {}).items()
}

UNEXCEPT_CHAR: float = token_price_config.get("unexcept_char", 0.06)

# 快速查找表：索引为 Unicode 码点（0 ~ 0xFFFF），值为对应价格
# 用空间换时间，长内容计算速度提升数十倍
CHAR_PRICE_LOOKUP: List[float] = [UNEXCEPT_CHAR] * 0x10000
for (start, end), price in TOKEN_USED_TABLE.items():
    start = max(0, min(start, 0xFFFF))
    end = max(0, min(end, 0xFFFF))
    for code in range(start, end + 1):
        CHAR_PRICE_LOOKUP[code] = price

MONEY_PER_MILLION_TOKENS: Dict[str, Dict[Literal["input", "output"], float]] = token_price_config.get(
    "money_per_million_tokens",
    {}
)

UNEXCEPT_MODEL: Dict[Literal["input", "output"], float] = token_price_config.get(
    "unexcept_model",
    {"input": 2, "output": 4}
)


# ========== 超支配置 ==========
# 允许用户最多超支多少元（因为实际 token 以模型返回为准，可能超出预估）
MAX_OVERDRAFT = 0.01  # 最多允许超支 0.01 元
