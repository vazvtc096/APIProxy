from openai import OpenAI
import json
from typing import Literal
from .apikey import APIKey
from .configs import BASEURL, APIKEY, DB_PATH
from .constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL

client = OpenAI(
    api_key=APIKEY,
    base_url=BASEURL,
    timeout=300  # 5分钟超时，支持长内容生成
)


def _lookup_model_price(model: str, type: Literal["input", "output"]):
    """查 model_prices 表返回该模型的单价（元/百万 tokens）。

    仅当 priced=1（管理员已定价）才返回精确价；否则返回 None 交给兜底价。
    """
    try:
        from . import db
        conn = db.get_conn()
        try:
            row = conn.execute(
                "SELECT input, output, priced FROM model_prices WHERE model = ?", (model,)
            ).fetchone()
        finally:
            conn.close()
        if row and row[2] == 1:
            return float(row[0] if type == "input" else row[1])
    except Exception:
        pass
    return None


class InsufficientBalanceError(Exception):
    def __init__(self, balence, required):
        self.balence = balence
        self.required = required
        super().__init__(f"Insufficient balence. Required: {required}, Available: {balence}")


class APICaller:
    def __init__(self, apikey: APIKey):
        self.apikey = apikey
    
    @staticmethod
    def _calculate_cost(content: str, model: str, type: Literal["input", "output"] = "input") -> float:
        total = 0.0
        lookup = CHAR_PRICE_LOOKUP
        unexcept = UNEXCEPT_CHAR
        for ch in content:
            code = ord(ch)
            if code < 0x10000:
                total += lookup[code]
            else:
                total += unexcept
        million_total = total / 1_000_000
        price = _lookup_model_price(model, type)
        money_per_million_tokens = price if price is not None else UNEXCEPT_MODEL[type]
        
        return round(million_total * money_per_million_tokens, 2)

    def call_api(self, model: str, messages: dict = {}, **kwargs):
        if self.apikey is None:
            raise ValueError("API key is not set")
        
        try:
            str_data = json.dumps(messages) if messages else ''
        except Exception as e:
            str_data = ''
        
        # 预检查：输入费用不能超过余额（用户必须有足够的钱才能调用）
        input_cost = self._calculate_cost(str_data, model, "input")
        if input_cost > self.apikey.balence:
            raise InsufficientBalanceError(self.apikey.balence, input_cost)
        
        # 调用 API
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            **kwargs
        )
        result = response.choices[0].message.content
        
        # 计算总费用（实际以模型返回为准）
        total_cost = input_cost + self._calculate_cost(result, model, "output")
        
        # 扣除费用（支持超支限额，实际以模型返回为准）
        self.apikey.deduct_balence(total_cost)
        
        return result
