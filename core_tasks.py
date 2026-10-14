"""用户任务管理器：每个用户独立的队列与 Worker。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import asyncio
import json
import logging
import time
from typing import Dict

from . import upstreams
from . import routing
from . import modality
from . import tokenpolicy
from . import budget
from . import balance_alert
from . import configs
from .constants import MAX_OVERDRAFT


def _accrue_token_usage(apikey_obj, total_cost: float):
    """令牌额度累计（独立于余额的第二层管控）。OAuth key 无 apikey 属性时跳过。"""
    try:
        raw = getattr(apikey_obj, 'apikey', None)
        if raw and total_cost:
            from .apikey import _hash_apikey
            tokenpolicy.accrue_usage(_hash_apikey(raw), total_cost)
    except Exception as e:
        logging.error(f"accrue token usage failed: {e}")
    # 用户级月度消费预算累计（OAuth key 也参与，不受令牌有无影响）
    try:
        budget.accrue_usage(getattr(apikey_obj, 'owner', None), total_cost)
    except Exception as e:
        logging.error(f"accrue monthly budget failed: {e}")


def _extract_usage_extra(_up_usage):
    """从上游 usage 深挖扩展字段 -> (reasoning_tokens, cache_hit_tokens)。

    - reasoning: completion_tokens_details.reasoning_tokens（推理思考量，
      已含在 completion_tokens 内，单独落库用于观察推理成本占比）
    - cache hit: prompt_cache_hit_tokens（DeepSeek 扁平字段）优先，
      回退 prompt_tokens_details.cached_tokens（OpenAI 风格）
    任一缺失返回 None。
    """
    if _up_usage is None:
        return None, None

    def _int(v):
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    reasoning = _int(getattr(getattr(_up_usage, 'completion_tokens_details', None),
                             'reasoning_tokens', None))
    cache = _int(getattr(_up_usage, 'prompt_cache_hit_tokens', None))
    if cache is None:
        cache = _int(getattr(getattr(_up_usage, 'prompt_tokens_details', None),
                             'cached_tokens', None))
    return reasoning, cache


async def _reconcile_and_accrue(apikey_obj, model, upstream_name, real_in, real_out,
                          real_cache, total_cost, _mult, key_hash, tpm_chars):
    """真实 token 计费对账 + 累计（响应完成后统一收口）。

    TOKEN_BILLING.enabled 时按真实 usage（缓存命中输入折扣）多退少补，
    返回 (生效成本, 调整后余额或 None)；额度/预算/TPM 累计一律用生效成本。
    失败回退字符口径，任何异常不外抛。
    """
    _tb = await asyncio.to_thread(reconcile_token_billing, apikey_obj.owner, model,
                                  upstream_name, real_in, real_out, real_cache,
                                  total_cost, _mult)
    effective = _tb['effective_cost'] if _tb else total_cost
    await asyncio.to_thread(tokenpolicy.accrue_tpm, key_hash, tpm_chars)
    await asyncio.to_thread(_accrue_token_usage, apikey_obj, effective)
    return effective, (_tb['balance'] if _tb else None)
from .core_billing import (_calculate_cost, _atomic_pre_deduct_balence,
                           _atomic_add_balence, _atomic_force_deduct_balence,
                           _record_usage_log, reconcile_token_billing)
from .hooks import fire_event
from .utils.metrics import (UPSTREAM_DURATION, TOKENS_TOTAL, COST_TOTAL,
                            UPSTREAM_ERRORS)


class UserTaskManager:
    """管理每个用户的队列和 Worker"""

    def __init__(self):
        self._queues: Dict[str, asyncio.Queue] = {}   # user -> Queue
        self._workers: Dict[str, asyncio.Task] = {}   # user -> Task
        self._lock = asyncio.Lock()

    async def get_queue(self, user: str) -> asyncio.Queue:
        """获取或创建用户队列，并确保 Worker 已启动"""
        async with self._lock:
            if user not in self._queues:
                q = asyncio.Queue()
                self._queues[user] = q
                # 启动该用户的专用 Worker
                worker = asyncio.create_task(self._user_worker(user, q))
                self._workers[user] = worker
                logging.info(f"Started worker for user {user}")
            return self._queues[user]

    async def _user_worker(self, user: str, queue: asyncio.Queue):
        while True:
            task_data = await queue.get()
            is_stream = task_data.get('stream', False)
            kind = task_data.get('kind', 'chat')
            try:
                if is_stream:
                    # 流式任务：通过 chunk_queue 传输数据块
                    chunk_queue = task_data['chunk_queue']
                    await self._process_stream_task(task_data, chunk_queue)
                elif kind == 'chat':
                    # 非流式任务：通过 Future 返回结果
                    future = task_data['future']
                    result = await self._process_task(task_data)
                    if not future.done():
                        future.set_result(result)
                    else:
                        logging.warning(f"Future already done for user {user}, result discarded")
                else:
                    # 其他 OpenAI 兼容端点（completions/embeddings/images/audio）
                    future = task_data['future']
                    result = await self._process_raw_task(task_data)
                    if not future.done():
                        future.set_result(result)
                    else:
                        logging.warning(f"Future already done for user {user}, result discarded")
            except ValueError as e:
                # 业务错误（余额不足等）返回具体信息
                error_msg = str(e)
                if is_stream:
                    chunk_queue = task_data.get('chunk_queue')
                    if chunk_queue:
                        await chunk_queue.put(('error', error_msg))
                else:
                    future = task_data.get('future')
                    if future and not future.done():
                        future.set_exception(e)
                logging.warning(f"Worker business error for user {user}: {e}")
            except Exception as e:
                # 系统错误脱敏，只记日志
                error_msg = "Service temporarily unavailable, please try again later"
                if is_stream:
                    chunk_queue = task_data.get('chunk_queue')
                    if chunk_queue:
                        await chunk_queue.put(('error', error_msg))
                else:
                    future = task_data.get('future')
                    if future and not future.done():
                        future.set_exception(RuntimeError(error_msg))
                logging.error(f"Worker system error for user {user}: {e}")
            finally:
                queue.task_done()

    async def _process_task(self, task_data: dict) -> dict:
        """处理非流式 API 调用任务"""
        apikey_obj = task_data['apikey_obj']
        req_data = task_data['req_data']
        # 服务端工具接地（WebSearch 等）：请求携带服务端工具时，由网关先检索并把
        # 结果注入上下文，再剥离该工具转发上游。正常请求无服务端工具，零影响。
        try:
            from .tools.grounding import ground_server_tools
            req_data = await ground_server_tools(req_data)
        except Exception as _gte:  # 接地失败绝不阻断主请求
            logging.warning("websearch grounding skipped: %s", _gte)
        model = req_data.get('model')
        messages = req_data.get('messages')
        kwargs = {k: v for k, v in req_data.items() if k not in ['model', 'messages', 'stream']}

        if not model:
            raise ValueError("model is required")

        # 模型映射 + 负载均衡候选链（健康优先，逐个故障转移）
        chain = routing.build_chain(model)
        if not chain:
            raise ValueError(f"No available upstream for model '{model}'")

        # 多模态预检测：候选链上没有任何声明 vision 的上游时，
        # 在预扣费之前直接拒绝（避免预扣→上游报错→退款的无效循环）
        _mod = modality.scan_modalities(messages)
        if modality.has_non_text(_mod) and not any(
                upstreams.upstream_supports_vision(n) for _c, n, _m in chain):
            raise ValueError(
                f"Model '{model}' does not support multimodal input "
                f"(image/audio/file parts detected: {_mod})")

        # 计算输入费用（base64 大对象替换为占位符，仅文本部分按字符计价）
        input_text = modality.billing_text(messages)
        input_cost = _calculate_cost(input_text, model, 'input', chain[0][1])
        # 用户组价格倍率
        _mult = float(task_data.get('price_multiplier') or 1.0)
        if _mult != 1.0:
            input_cost = round(input_cost * _mult, 6)

        # 用户级月度消费预算预检（超限抛业务错误 -> 客户端 400）
        await asyncio.to_thread(budget.check_or_raise, apikey_obj.owner)
        # 原子预扣费（事务锁定，防止并发竞态超支）
        success, balence, msg = await asyncio.to_thread(_atomic_pre_deduct_balence, apikey_obj.owner, input_cost)
        if not success:
            raise ValueError(f"Insufficient balence: {msg}")

        # 逐候选故障转移调用上游
        response = None
        upstream_name = None
        last_err = None
        for client, cand_name, mapped_model in chain:
            t0 = time.perf_counter()
            try:
                response = await client.chat.completions.create(
                    model=mapped_model,
                    messages=messages,
                    timeout=300,  # 5分钟超时
                    **kwargs
                )
                upstream_name = cand_name
                upstreams.report_upstream_ok(client)
                routing.record_success(cand_name, (time.perf_counter() - t0) * 1000)
                break
            except Exception as e:
                UPSTREAM_ERRORS.labels(model, cand_name).inc()
                routing.record_failure(cand_name)
                upstreams.report_upstream_error(client, e)
                last_err = e
                continue
            finally:
                UPSTREAM_DURATION.labels(model, cand_name).observe(time.perf_counter() - t0)
        if response is None:
            # 全部候选失败：回退预扣的输入费用
            try:
                await asyncio.to_thread(_atomic_add_balence, apikey_obj.owner, input_cost)
            except Exception:
                pass
            raise RuntimeError(f"Upstream API error: {last_err}")

        result_text = response.choices[0].message.content

        # 捕获上游真实 usage token + 扩展字段（reasoning / 缓存命中）
        _up_usage = getattr(response, 'usage', None)
        real_in = getattr(_up_usage, 'prompt_tokens', None) if _up_usage else None
        real_out = getattr(_up_usage, 'completion_tokens', None) if _up_usage else None
        real_reason, real_cache = _extract_usage_extra(_up_usage)

        # 计算输出费用并原子扣费（输出已产生，必须扣）
        output_cost = _calculate_cost(result_text, model, 'output', upstream_name)
        if _mult != 1.0:
            output_cost = round(output_cost * _mult, 6)
        total_cost = input_cost + output_cost
        # 业务指标：令牌与费用
        TOKENS_TOTAL.labels(model, 'input').inc(len(input_text or ''))
        TOKENS_TOTAL.labels(model, 'output').inc(len(result_text or ''))
        new_balence = await asyncio.to_thread(_atomic_force_deduct_balence, apikey_obj.owner, output_cost)
        # 真实 token 计费对账（多退少补）+ TPM/额度/预算累计（按生效成本）
        total_cost, _rbal = await _reconcile_and_accrue(
            apikey_obj, model, upstream_name, real_in, real_out, real_cache,
            total_cost, _mult, task_data.get('key_hash'),
            len(input_text or '') + len(result_text or ''))
        COST_TOTAL.labels(model).inc(total_cost)
        if _rbal is not None:
            new_balence = _rbal
        # 余额预警（低于阈值 -> 站内通知 + 邮件，冷却期去重；内部自吞异常）
        await balance_alert.maybe_alert(apikey_obj.owner, new_balence)

        # 检查是否超支
        if new_balence < 0:
            overdraft_amount = abs(new_balence)
            if overdraft_amount > MAX_OVERDRAFT:
                logging.warning(f"User {apikey_obj.owner} exceeded overdraft limit: used {total_cost}, new balence {new_balence}, overdraft {overdraft_amount}, limit {MAX_OVERDRAFT}")
            else:
                logging.info(f"User {apikey_obj.owner} minor overdraft: used {total_cost}, new balence {new_balence}, overdraft {overdraft_amount}")
        else:
            logging.info(f"User {apikey_obj.owner} used model {model} (upstream={upstream_name}), cost {total_cost}, new balence {new_balence}")

        # 记录用量明细（统计图数据源）
        await _record_usage_log(apikey_obj.owner, model, input_text, result_text or '',
                                total_cost, False, upstream_name,
                                real_prompt_tokens=real_in, real_completion_tokens=real_out,
                                real_reasoning_tokens=real_reason,
                                real_cache_hit_tokens=real_cache)
        # 触发 API_CALL 钩子事件
        await fire_event('API_CALL', trigger_user=apikey_obj.owner, model=model,
                         tokens=len(input_text or '') + len(result_text or ''),
                         cost=total_cost)

        # 响应侧泄露防护（出口扫描）：critical 命中在 redact 模式下脱敏后返回
        out = response.model_dump()
        try:
            from . import leak_guard as _lg
            _content = str(out.get('choices', [{}])[0].get('message', {}).get('content') or '')
            _lgres = _lg.check_outbound(_content, user=apikey_obj.owner,
                                        model=model, stream=False)
            if _lgres['redacted']:
                out['choices'][0]['message']['content'] = _lgres['text']
        except Exception as e:
            logging.error(f"leak guard failed: {e}")
        return out

    async def _process_stream_task(self, task_data: dict, chunk_queue: asyncio.Queue):
        """处理流式 API 调用任务，将每个 chunk 放入 chunk_queue"""
        apikey_obj = task_data['apikey_obj']
        req_data = task_data['req_data']
        # 服务端工具接地（同 _process_task）：WebSearch 等由网关检索后注入上下文
        try:
            from .tools.grounding import ground_server_tools
            req_data = await ground_server_tools(req_data)
        except Exception as _gte:
            logging.warning("websearch grounding skipped: %s", _gte)
        model = req_data.get('model')
        messages = req_data.get('messages')
        kwargs = {k: v for k, v in req_data.items() if k not in ['model', 'messages', 'stream']}

        if not model:
            raise ValueError("model is required")

        # 模型映射 + 负载均衡候选链
        chain = routing.build_chain(model)
        if not chain:
            raise ValueError(f"No available upstream for model '{model}'")

        # 多模态预检测（预扣费前拒绝）
        _mod = modality.scan_modalities(messages)
        if modality.has_non_text(_mod) and not any(
                upstreams.upstream_supports_vision(n) for _c, n, _m in chain):
            raise ValueError(
                f"Model '{model}' does not support multimodal input "
                f"(image/audio/file parts detected: {_mod})")

        # 计算输入费用（base64 净化后按字符计价）
        input_text = modality.billing_text(messages)
        input_cost = _calculate_cost(input_text, model, 'input', chain[0][1])
        # 用户组价格倍率
        _mult = float(task_data.get('price_multiplier') or 1.0)
        if _mult != 1.0:
            input_cost = round(input_cost * _mult, 6)

        # 用户级月度消费预算预检（超限抛业务错误 -> 客户端 400）
        await asyncio.to_thread(budget.check_or_raise, apikey_obj.owner)
        # 原子预扣费（事务锁定，防止并发竞态超支）
        success, balence, msg = await asyncio.to_thread(_atomic_pre_deduct_balence, apikey_obj.owner, input_cost)
        if not success:
            raise ValueError(f"Insufficient balence: {msg}")

        # 逐候选故障转移：流创建阶段失败可切换下一个候选（尚无数据流出，切换安全）
        stream = None
        upstream_name = None
        last_err = None
        for client, cand_name, mapped_model in chain:
            t0 = time.perf_counter()
            try:
                # 请求上游在最后一个 chunk 携带 usage（真实 token 校准用）；
                # 少数上游不认识 stream_options 时回退为不带该参数重试一次。
                try:
                    if 'stream_options' in kwargs:
                        raise TypeError('caller provided stream_options')
                    stream = await client.chat.completions.create(
                        model=mapped_model,
                        messages=messages,
                        stream=True,
                        timeout=300,
                        stream_options={'include_usage': True},
                        **kwargs
                    )
                except Exception as _se:
                    if 'stream_options' not in str(_se) and not isinstance(_se, TypeError):
                        raise
                    stream = await client.chat.completions.create(
                        model=mapped_model,
                        messages=messages,
                        stream=True,
                        timeout=300,
                        **kwargs
                    )
                upstream_name = cand_name
                upstreams.report_upstream_ok(client)
                routing.record_success(cand_name, (time.perf_counter() - t0) * 1000)
                break
            except Exception as e:
                UPSTREAM_ERRORS.labels(model, cand_name).inc()
                routing.record_failure(cand_name)
                upstreams.report_upstream_error(client, e)
                last_err = e
                continue
            finally:
                UPSTREAM_DURATION.labels(model, cand_name).observe(time.perf_counter() - t0)
        if stream is None:
            # 全部候选失败：回退预扣的输入费用
            try:
                await asyncio.to_thread(_atomic_add_balence, apikey_obj.owner, input_cost)
            except Exception:
                pass
            raise RuntimeError(f"Upstream API error: {last_err}")

        # 调用上游流式 API 成功

        # 收集输出内容用于计费
        output_text = ""
        # 上游真实 usage（include_usage 的最后一个 chunk 携带；未携带为 None）
        real_in = None
        real_out = None
        real_reason = None
        real_cache = None

        # 响应侧泄露防护：流式按 delta 扫描（跨块拼接缓冲，见 leak_guard.py）。
        # 计费仍按上游原始输出（output_text 收集不经过脱敏），与用量一致。
        try:
            from . import leak_guard as _lg
            _lgfeed = _lg.make_stream_scanner(user=apikey_obj.owner, model=model)
        except Exception as e:
            logging.error(f"leak guard stream init failed: {e}")
            _lgfeed = None

        async for chunk in stream:
            # 将原始 chunk 转发给客户端（delta 先过泄露扫描）
            data = chunk.model_dump()
            if _lgfeed is not None:
                try:
                    _delta = ((data.get('choices') or [{}])[0] or {}).get('delta') or {}
                    _d = _delta.get('content')
                    if _d:
                        _delta['content'] = _lgfeed(_d)
                except Exception as e:
                    logging.error(f"leak guard stream feed failed: {e}")
            await chunk_queue.put(('data', data))
            # 收集输出内容
            if chunk.choices and len(chunk.choices) > 0:
                delta = chunk.choices[0].delta
                if delta.content:
                    output_text += delta.content
            # 最后一个 chunk 的 usage（choices 为空，仅带 usage）
            _cu = getattr(chunk, 'usage', None)
            if _cu is not None:
                _pi = getattr(_cu, 'prompt_tokens', None)
                _po = getattr(_cu, 'completion_tokens', None)
                if _pi is not None:
                    real_in = int(_pi)
                if _po is not None:
                    real_out = int(_po)
                _rr, _rc = _extract_usage_extra(_cu)
                if _rr is not None:
                    real_reason = _rr
                if _rc is not None:
                    real_cache = _rc

        # 流式结束标记
        await chunk_queue.put(('done', None))

        # 计算输出费用并原子扣费（输出已产生，必须扣）
        output_cost = _calculate_cost(output_text, model, 'output')
        if _mult != 1.0:
            output_cost = round(output_cost * _mult, 6)
        total_cost = input_cost + output_cost
        # 业务指标：令牌与费用
        TOKENS_TOTAL.labels(model, 'input').inc(len(input_text or ''))
        TOKENS_TOTAL.labels(model, 'output').inc(len(output_text or ''))
        new_balence = await asyncio.to_thread(_atomic_force_deduct_balence, apikey_obj.owner, output_cost)
        # 真实 token 计费对账（多退少补）+ TPM/额度/预算累计（按生效成本）
        total_cost, _rbal = await _reconcile_and_accrue(
            apikey_obj, model, upstream_name, real_in, real_out, real_cache,
            total_cost, _mult, task_data.get('key_hash'),
            len(input_text or '') + len(output_text or ''))
        COST_TOTAL.labels(model).inc(total_cost)
        if _rbal is not None:
            new_balence = _rbal
        # 余额预警（低于阈值 -> 站内通知 + 邮件，冷却期去重；内部自吞异常）
        await balance_alert.maybe_alert(apikey_obj.owner, new_balence)

        # 检查是否超支
        if new_balence < 0:
            overdraft_amount = abs(new_balence)
            if overdraft_amount > MAX_OVERDRAFT:
                logging.warning(f"User {apikey_obj.owner} stream exceeded overdraft limit: used {total_cost}, new balence {new_balence}, overdraft {overdraft_amount}, limit {MAX_OVERDRAFT}")
            else:
                logging.info(f"User {apikey_obj.owner} stream minor overdraft: used {total_cost}, balence {balence}, new balence {new_balence}, overdraft {overdraft_amount}")
        else:
            logging.info(f"User {apikey_obj.owner} stream used model {model}, cost {total_cost}, new balence {new_balence}")

        # 记录用量明细（统计图数据源）
        await _record_usage_log(apikey_obj.owner, model, input_text, output_text or '',
                                total_cost, True, upstream_name,
                                real_prompt_tokens=real_in, real_completion_tokens=real_out,
                                real_reasoning_tokens=real_reason,
                                real_cache_hit_tokens=real_cache)
        # 触发 API_CALL 钩子事件
        await fire_event('API_CALL', trigger_user=apikey_obj.owner, model=model,
                         tokens=len(input_text or '') + len(output_text or ''),
                         cost=total_cost)

    async def _process_raw_task(self, task_data: dict) -> dict:
        """通用 OpenAI 兼容端点处理（completions / embeddings / images / audio）。

        统一链路：模型映射+候选链 → 输入计费（文本按字符；images/audio 按
        configs.MEDIA_PRICING 按张/按 KB）→ 预扣费 → 逐候选故障转移 →
        输出计费（completions/transcriptions 有文本输出；speech 按输入计）→ 用量日志。
        """
        kind = task_data['kind']
        apikey_obj = task_data['apikey_obj']
        payload = dict(task_data['payload'])
        model = payload.get('model')
        if not model:
            raise ValueError("model is required")

        chain = routing.build_chain(model)
        if not chain:
            raise ValueError(f"No available upstream for model '{model}'")

        media = configs.MEDIA_PRICING
        # ---- 输入计费 ----
        if kind == 'completions':
            prompt = payload.get('prompt')
            prompts = prompt if isinstance(prompt, list) else [prompt or '']
            input_text = '\n'.join(str(p) for p in prompts)
            input_cost = _calculate_cost(input_text, model, 'input', chain[0][1])
        elif kind == 'embeddings':
            inp = payload.get('input')
            if isinstance(inp, list):
                input_text = '\n'.join(x if isinstance(x, str) else json.dumps(x, ensure_ascii=False) for x in inp)
            else:
                input_text = str(inp or '')
            input_cost = _calculate_cost(input_text, model, 'input', chain[0][1])
        elif kind == 'images':
            input_text = f"[image-gen:{model}]"
            input_cost = round(media['image_per_unit'] * int(payload.get('n') or 1), 6)
        elif kind == 'videos':
            input_text = f"[video-gen:{model}]"
            input_cost = round(media['video_per_unit'] * int(payload.get('n') or 1), 6)
        elif kind == 'audio_transcriptions':
            nbytes = len(task_data.get('file_bytes') or b'')
            input_text = f"[audio-transcribe:{model},{max(1, nbytes // 1024)}KB]"
            input_cost = round(media['audio_per_kb'] * max(1, nbytes // 1024), 6)
        elif kind == 'audio_speech':
            nbytes = len(str(payload.get('input') or '').encode('utf-8'))
            input_text = f"[tts:{model},{max(1, nbytes // 1024)}KB]"
            input_cost = round(media['audio_per_kb'] * max(1, nbytes // 1024), 6)
        elif kind == 'rerank':
            docs = payload.get('documents') or []
            n_docs = len(docs) if isinstance(docs, list) else 1
            input_text = f"[rerank:{model},{n_docs}docs]"
            input_cost = round(media['rerank_per_doc'] * n_docs, 6)
        else:
            raise ValueError(f"unknown task kind: {kind}")
        TOKENS_TOTAL.labels(model, 'input').inc(len(input_text or ''))
        # 用户组价格倍率
        _mult = float(task_data.get('price_multiplier') or 1.0)
        if _mult != 1.0:
            input_cost = round(input_cost * _mult, 6)

        # ---- 预扣费 ----
        # 用户级月度消费预算预检（超限抛业务错误 -> 客户端 400）
        await asyncio.to_thread(budget.check_or_raise, apikey_obj.owner)
        success, balence, msg = await asyncio.to_thread(
            _atomic_pre_deduct_balence, apikey_obj.owner, input_cost)
        if not success:
            raise ValueError(f"Insufficient balence: {msg}")

        # ---- 逐候选故障转移 ----
        response = None
        upstream_name = None
        last_err = None
        for client, cand_name, mapped_model in chain:
            t0 = time.perf_counter()
            try:
                response = await self._call_raw(client, kind, task_data, payload, mapped_model)
                upstream_name = cand_name
                upstreams.report_upstream_ok(client)
                routing.record_success(cand_name, (time.perf_counter() - t0) * 1000)
                break
            except Exception as e:
                UPSTREAM_ERRORS.labels(model, cand_name).inc()
                routing.record_failure(cand_name)
                upstreams.report_upstream_error(client, e)
                last_err = e
                continue
            finally:
                UPSTREAM_DURATION.labels(model, cand_name).observe(time.perf_counter() - t0)
        if response is None:
            # 全部候选失败：回退预扣的输入费用
            try:
                await asyncio.to_thread(_atomic_add_balence, apikey_obj.owner, input_cost)
            except Exception:
                pass
            raise RuntimeError(f"Upstream API error: {last_err}")

        # ---- 输出计费 ----
        # 上游真实 usage token（completions/embeddings 有；媒体端点无，None 落库）
        _up_usage = getattr(response, 'usage', None)
        real_in = getattr(_up_usage, 'prompt_tokens', None) if _up_usage else None
        real_out = getattr(_up_usage, 'completion_tokens', None) if _up_usage else None
        real_reason, real_cache = _extract_usage_extra(_up_usage)
        output_text = ''
        if kind == 'rerank':
            # rerank 上游直接返回 JSON dict（无文本输出计费），原样回传
            total_cost = input_cost
            COST_TOTAL.labels(model).inc(total_cost)
            await asyncio.to_thread(tokenpolicy.accrue_tpm, task_data.get('key_hash'),
                                    len(input_text or ''))
            await asyncio.to_thread(_accrue_token_usage, apikey_obj, total_cost)
            await _record_usage_log(apikey_obj.owner, model, input_text, '',
                                    total_cost, False, upstream_name, endpoint='rerank')
            await fire_event('API_CALL', trigger_user=apikey_obj.owner, model=model,
                             tokens=len(input_text or ''), cost=total_cost)
            return response
        if kind == 'completions':
            for ch in (getattr(response, 'choices', None) or []):
                output_text += getattr(ch, 'text', '') or ''
        elif kind == 'audio_transcriptions':
            output_text = getattr(response, 'text', '') or ''
        output_cost = _calculate_cost(output_text, model, 'output', upstream_name) if output_text else 0.0
        if _mult != 1.0:
            output_cost = round(output_cost * _mult, 6)
        total_cost = input_cost + output_cost
        if output_text:
            TOKENS_TOTAL.labels(model, 'output').inc(len(output_text))
        new_balence = await asyncio.to_thread(_atomic_force_deduct_balence, apikey_obj.owner, output_cost)
        # 真实 token 计费对账（多退少补）+ TPM/额度/预算累计（按生效成本）
        total_cost, _rbal = await _reconcile_and_accrue(
            apikey_obj, model, upstream_name, real_in, real_out, real_cache,
            total_cost, _mult, task_data.get('key_hash'),
            len(input_text or '') + len(output_text or ''))
        COST_TOTAL.labels(model).inc(total_cost)
        if _rbal is not None:
            new_balence = _rbal
        # 余额预警（低于阈值 -> 站内通知 + 邮件，冷却期去重；内部自吞异常）
        await balance_alert.maybe_alert(apikey_obj.owner, new_balence)

        # ---- 用量日志 ----
        await _record_usage_log(apikey_obj.owner, model, input_text, output_text or '',
                                total_cost, False, upstream_name,
                                endpoint={'completions': 'completions',
                                          'embeddings': 'embeddings',
                                          'images': 'images.generations',
                                          'videos': 'videos.generations',
                                          'audio_transcriptions': 'audio.transcriptions',
                                          'audio_speech': 'audio.speech'}.get(kind, kind),
                                real_prompt_tokens=real_in, real_completion_tokens=real_out,
                                real_reasoning_tokens=real_reason,
                                real_cache_hit_tokens=real_cache)
        await fire_event('API_CALL', trigger_user=apikey_obj.owner, model=model,
                         tokens=len(input_text or '') + len(output_text or ''),
                         cost=total_cost)

        # ---- 响应规格化 ----
        if kind == 'audio_speech':
            # SDK 返回二进制音频；交给路由层以原始字节响应
            data = getattr(response, 'content', None) or b''
            return {'_binary': True, 'media_type': 'audio/mpeg', 'data_len': len(data),
                    '_bytes': data}
        try:
            return response.model_dump()
        except Exception:
            return {'raw': str(response)}

    @staticmethod
    async def _call_raw(client, kind: str, task_data: dict, payload: dict, mapped_model: str):
        """按 kind 调用对应 SDK 资源"""
        if kind == 'completions':
            return await client.completions.create(model=mapped_model, **payload)
        if kind == 'embeddings':
            return await client.embeddings.create(model=mapped_model, **payload)
        if kind == 'images':
            return await client.images.generate(model=mapped_model, **payload)
        if kind == 'videos':
            # 视频生成无标准 OpenAI SDK 资源，按 rerank 方式自定义转发到上游 /videos/generations
            return await self._call_video(client, payload, mapped_model)
        if kind == 'audio_transcriptions':
            fobj = task_data['file']
            return await client.audio.transcriptions.create(model=mapped_model, file=fobj, **payload)
        if kind == 'audio_speech':
            return await client.audio.speech.create(model=mapped_model, **payload)
        if kind == 'rerank':
            # OpenAI SDK 无 rerank 资源；用其底层配置直连上游 /rerank（Jina/Cohere 兼容格式）
            import httpx as _httpx
            _key = client.api_key
            if hasattr(_key, 'get_secret_value'):
                _key = _key.get_secret_value()
            _base = str(client.base_url).rstrip('/')
            _headers = {'Authorization': f'Bearer {_key}',
                        'Content-Type': 'application/json'}
        async with _httpx.AsyncClient(timeout=120) as _hc:
            _resp = await _hc.post(_base + '/rerank', json=payload, headers=_headers)
            _resp.raise_for_status()
            return _resp.json()
        raise ValueError(f"unknown kind: {kind}")

    @staticmethod
    async def _call_video(client, payload: dict, mapped_model: str):
        """视频生成：OpenAI SDK 无 videos 资源，直连上游 /videos/generations（OpenAI 风格）。

        兼容 Seedance / Runway 类代理。响应格式按各上游返回原样透传（通常为
        {data:[{url|b64_json|task_id}]} 或任务轮询结构），由调用方决定如何呈现。
        """
        import httpx as _httpx
        _key = client.api_key
        if hasattr(_key, 'get_secret_value'):
            _key = _key.get_secret_value()
        _base = str(client.base_url).rstrip('/')
        _headers = {'Authorization': f'Bearer {_key}', 'Content-Type': 'application/json'}
        _payload = dict(payload)
        _payload['model'] = mapped_model
        async with _httpx.AsyncClient(timeout=600) as _hc:
            _resp = await _hc.post(_base + '/videos/generations', json=_payload, headers=_headers)
            _resp.raise_for_status()
            try:
                return _resp.json()
            except Exception:
                return {'raw': _resp.text}


task_manager = UserTaskManager()
