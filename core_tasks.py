"""用户任务管理器：每个用户独立的队列与 Worker。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import asyncio
import json
import logging
import time
from typing import Dict

from . import upstreams
from .constants import MAX_OVERDRAFT
from .core_billing import (_calculate_cost, _atomic_pre_deduct_balence,
                           _atomic_add_balence, _atomic_force_deduct_balence,
                           _record_usage_log)
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
            try:
                if is_stream:
                    # 流式任务：通过 chunk_queue 传输数据块
                    chunk_queue = task_data['chunk_queue']
                    await self._process_stream_task(task_data, chunk_queue)
                else:
                    # 非流式任务：通过 Future 返回结果
                    future = task_data['future']
                    result = await self._process_task(task_data)
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
        model = req_data.get('model')
        messages = req_data.get('messages')
        kwargs = {k: v for k, v in req_data.items() if k not in ['model', 'messages', 'stream']}

        if not model:
            raise ValueError("model is required")

        # 选择上游 Key（按启用 / 禁用模型 / 优先级）
        sel = upstreams.select_upstream(model)
        if sel is None:
            raise ValueError(f"No available upstream for model '{model}'")
        client, upstream_name = sel

        # 计算输入费用
        input_text = json.dumps(messages)
        input_cost = _calculate_cost(input_text, model, 'input', upstream_name)

        # 原子预扣费（事务锁定，防止并发竞态超支）
        success, balence, msg = await asyncio.to_thread(_atomic_pre_deduct_balence, apikey_obj.owner, input_cost)
        if not success:
            raise ValueError(f"Insufficient balence: {msg}")

        # 调用上游 API
        t0 = time.perf_counter()
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                timeout=300,  # 5分钟超时
                **kwargs
            )
        except Exception as e:
            UPSTREAM_ERRORS.labels(model, upstream_name).inc()
            # API 调用失败，回退预扣的输入费用
            try:
                await asyncio.to_thread(_atomic_add_balence, apikey_obj.owner, input_cost)
            except Exception:
                pass
            raise RuntimeError(f"Upstream API error: {e}")
        finally:
            UPSTREAM_DURATION.labels(model, upstream_name).observe(time.perf_counter() - t0)

        result_text = response.choices[0].message.content

        # 计算输出费用并原子扣费（输出已产生，必须扣）
        output_cost = _calculate_cost(result_text, model, 'output', upstream_name)
        total_cost = input_cost + output_cost
        # 业务指标：令牌与费用
        TOKENS_TOTAL.labels(model, 'input').inc(len(input_text or ''))
        TOKENS_TOTAL.labels(model, 'output').inc(len(result_text or ''))
        COST_TOTAL.labels(model).inc(total_cost)
        new_balence = await asyncio.to_thread(_atomic_force_deduct_balence, apikey_obj.owner, output_cost)

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
                                total_cost, False, upstream_name)
        # 触发 API_CALL 钩子事件
        await fire_event('API_CALL', trigger_user=apikey_obj.owner, model=model,
                         tokens=len(input_text or '') + len(result_text or ''),
                         cost=total_cost)

        return response.model_dump()

    async def _process_stream_task(self, task_data: dict, chunk_queue: asyncio.Queue):
        """处理流式 API 调用任务，将每个 chunk 放入 chunk_queue"""
        apikey_obj = task_data['apikey_obj']
        req_data = task_data['req_data']
        model = req_data.get('model')
        messages = req_data.get('messages')
        kwargs = {k: v for k, v in req_data.items() if k not in ['model', 'messages', 'stream']}

        if not model:
            raise ValueError("model is required")

        # 选择上游 Key
        sel = upstreams.select_upstream(model)
        if sel is None:
            raise ValueError(f"No available upstream for model '{model}'")
        client, upstream_name = sel

        # 计算输入费用
        input_text = json.dumps(messages)
        input_cost = _calculate_cost(input_text, model, 'input', upstream_name)

        # 原子预扣费（事务锁定，防止并发竞态超支）
        success, balence, msg = await asyncio.to_thread(_atomic_pre_deduct_balence, apikey_obj.owner, input_cost)
        if not success:
            raise ValueError(f"Insufficient balence: {msg}")

        # 调用上游流式 API
        t0 = time.perf_counter()
        try:
            stream = await client.chat.completions.create(
                model=model,
                messages=messages,
                stream=True,
                timeout=300,
                **kwargs
            )
        except Exception as e:
            UPSTREAM_ERRORS.labels(model, upstream_name).inc()
            # API 调用失败，回退预扣的输入费用
            try:
                await asyncio.to_thread(_atomic_add_balence, apikey_obj.owner, input_cost)
            except Exception:
                pass
            raise RuntimeError(f"Upstream API error: {e}")
        finally:
            UPSTREAM_DURATION.labels(model, upstream_name).observe(time.perf_counter() - t0)

        # 收集输出内容用于计费
        output_text = ""

        async for chunk in stream:
            # 将原始 chunk 转发给客户端
            await chunk_queue.put(('data', chunk.model_dump()))
            # 收集输出内容
            if chunk.choices and len(chunk.choices) > 0:
                delta = chunk.choices[0].delta
                if delta.content:
                    output_text += delta.content

        # 流式结束标记
        await chunk_queue.put(('done', None))

        # 计算输出费用并原子扣费（输出已产生，必须扣）
        output_cost = _calculate_cost(output_text, model, 'output')
        total_cost = input_cost + output_cost
        # 业务指标：令牌与费用
        TOKENS_TOTAL.labels(model, 'input').inc(len(input_text or ''))
        TOKENS_TOTAL.labels(model, 'output').inc(len(output_text or ''))
        COST_TOTAL.labels(model).inc(total_cost)
        new_balence = await asyncio.to_thread(_atomic_force_deduct_balence, apikey_obj.owner, output_cost)

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
                                total_cost, True, upstream_name)
        # 触发 API_CALL 钩子事件
        await fire_event('API_CALL', trigger_user=apikey_obj.owner, model=model,
                         tokens=len(input_text or '') + len(output_text or ''),
                         cost=total_cost)


task_manager = UserTaskManager()
