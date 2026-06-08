"""
群组 E2EE 方案复杂度对比：Pairwise / Sender Key / TreeKEM

用于大作业实验：量化成员规模增长时的密钥更新成本。
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List

from .group import MLSGroup
from .tree_math import TreeIndex


@dataclass
class SchemeMetrics:
    scheme: str
    member_count: int
    key_pairs_stored: int
    messages_per_update: int
    ciphertexts_per_update: int
    tree_height: int


def pairwise_metrics(n: int) -> SchemeMetrics:
    """双人会话方案：每对成员独立密钥，成员变更需 O(n) 次新会话"""
    return SchemeMetrics(
        scheme="Pairwise E2EE",
        member_count=n,
        key_pairs_stored=n * (n - 1) // 2,
        messages_per_update=n - 1,
        ciphertexts_per_update=n - 1,
        tree_height=0,
    )


def sender_key_metrics(n: int) -> SchemeMetrics:
    """发送者密钥：每成员维护 n-1 把发送密钥，变更时需广播 n-1 把新密钥"""
    return SchemeMetrics(
        scheme="Sender Key",
        member_count=n,
        key_pairs_stored=n * (n - 1),
        messages_per_update=1,
        ciphertexts_per_update=n - 1,
        tree_height=0,
    )


def treekem_theoretical_metrics(n: int) -> SchemeMetrics:
    """TreeKEM 理论值：O(log n) 路径节点与 copath 加密"""
    padded = TreeIndex.pad_to_power_of_two(n)
    h = int(math.ceil(math.log2(padded))) if padded > 1 else 0
    return SchemeMetrics(
        scheme="TreeKEM (理论)",
        member_count=n,
        key_pairs_stored=h + 1,
        messages_per_update=1,
        ciphertexts_per_update=h,
        tree_height=h,
    )


def treekem_measured_metrics(n: int) -> SchemeMetrics:
    """实测一次自更新 Commit 的加密次数"""
    ids = [f"M{i}" for i in range(n)]
    group = MLSGroup(ids)
    metrics = group.broadcast_commit(ids[0], action="measure")
    h = int(math.ceil(math.log2(group.num_leaves))) if group.num_leaves > 1 else 0
    return SchemeMetrics(
        scheme="TreeKEM (实测)",
        member_count=n,
        key_pairs_stored=h + 1,
        messages_per_update=1,
        ciphertexts_per_update=metrics.encryptions_sent,
        tree_height=h,
    )


def run_scaling_experiment(sizes: List[int] | None = None) -> List[dict]:
    sizes = sizes or [2, 4, 8, 16, 32, 64]
    rows = []
    for n in sizes:
        pw = pairwise_metrics(n)
        sk = sender_key_metrics(n)
        tk_theory = treekem_theoretical_metrics(n)
        tk_meas = treekem_measured_metrics(n)
        rows.append({
            "members": n,
            "pairwise_keys": pw.key_pairs_stored,
            "pairwise_ciphertexts": pw.ciphertexts_per_update,
            "sender_key_keys": sk.key_pairs_stored,
            "sender_key_ciphertexts": sk.ciphertexts_per_update,
            "treekem_theory_ciphertexts": tk_theory.ciphertexts_per_update,
            "treekem_measured_ciphertexts": tk_meas.ciphertexts_per_update,
            "treekem_height": tk_meas.tree_height,
        })
    return rows


def print_comparison_table(rows: List[dict]) -> None:
    header = (
        f"{'成员数':>6} | {'Pairwise密钥':>12} | {'Pairwise密文':>12} | "
        f"{'SenderKey密钥':>14} | {'SenderKey密文':>14} | "
        f"{'TreeKEM理论':>10} | {'TreeKEM实测':>10}"
    )
    print("=" * len(header))
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['members']:>6} | {r['pairwise_keys']:>12} | {r['pairwise_ciphertexts']:>12} | "
            f"{r['sender_key_keys']:>14} | {r['sender_key_ciphertexts']:>14} | "
            f"{r['treekem_theory_ciphertexts']:>10} | {r['treekem_measured_ciphertexts']:>10}"
        )
    print("=" * len(header))
