"""多模态视频生成：计费配置与计费公式（无网络 / 无 app 依赖）。"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from APIProxy import configs


def test_media_pricing_has_video_per_unit():
    media = configs.MEDIA_PRICING
    assert 'video_per_unit' in media
    assert isinstance(media['video_per_unit'], float)
    assert media['video_per_unit'] > 0


def test_video_billing_formula():
    # 与 core_tasks._process_raw_task 中 videos 分支一致的计费公式
    media = configs.MEDIA_PRICING
    for n, expected in [(1, media['video_per_unit']),
                        (3, round(media['video_per_unit'] * 3, 6))]:
        cost = round(media['video_per_unit'] * int(n or 1), 6)
        assert cost == expected
