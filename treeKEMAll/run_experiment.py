#!/usr/bin/env python3
"""
TreeKEM 完整场景实验入口 — 群组端到端加密大作业

运行：python run_experiment.py
"""

from __future__ import annotations

import sys

from treekem.benchmark import print_comparison_table, run_scaling_experiment
from treekem.group import MLSGroup
from treekem.tree_math import TreeIndex


def demo_full_scenario() -> None:
    print("\n" + "=" * 60)
    print("【场景 1】4 人群组：初始化 → 自更新 → 加人 → 踢人")
    print("=" * 60)

    group = MLSGroup(["Alice", "Bob", "Carol", "Dave"])
    print(f"  初始成员: {list(group.members.keys())}")
    print(f"  树叶子数(padded): {group.num_leaves}")
    print(f"  树一致性: {group.verify_tree_consistency()}")

    m = group.broadcast_commit("Alice", action="self-update")
    print(f"\n  Alice 自更新 → 路径节点={m.path_nodes_updated}, 加密数={m.encryptions_sent}")
    print(f"  树一致性: {group.verify_tree_consistency()}")

    new_member, m_add = group.add_member("Eve")
    print(f"\n  加入 Eve (叶索引={new_member.leaf_index})")
    print(f"  加人 Commit → 路径节点={m_add.path_nodes_updated}, 加密数={m_add.encryptions_sent}")
    print(f"  当前成员: {list(group.members.keys())}")
    print(f"  树一致性: {group.verify_tree_consistency()}")

    m_rm = group.remove_member("Bob", committer_id="Carol")
    print(f"\n  移除 Bob (Carol 发起 Commit)")
    print(f"  踢人 Commit → 路径节点={m_rm.path_nodes_updated}, 加密数={m_rm.encryptions_sent}")
    print(f"  当前成员: {list(group.members.keys())}")
    print(f"  树一致性: {group.verify_tree_consistency()}")

    stats = group.get_complexity_stats()
    print(f"\n  累计 epoch={stats['epochs']}, 总加密={stats['total_encryptions']}, "
          f"平均每次 Commit 加密={stats['avg_encryptions_per_commit']:.1f}")


def demo_tree_geometry() -> None:
    print("\n" + "=" * 60)
    print("【场景 2】RFC 9420 树几何：direct path / copath / resolution")
    print("=" * 60)

    for n in [4, 8]:
        idx = TreeIndex(n)
        print(f"\n  {n} 人群组 (root={idx.root_idx}):")
        for leaf in range(n):
            dp = idx.direct_path(leaf)
            cp = idx.copath(leaf)
            fdp = idx.filtered_direct_path(leaf, set())
            print(f"    叶{leaf}(节点{idx.leaf_node(leaf)}): "
                  f"direct_path={dp}, copath={cp}, filtered={fdp}")


def demo_scaling() -> None:
    print("\n" + "=" * 60)
    print("【场景 3】扩展性对比：Pairwise vs Sender Key vs TreeKEM")
    print("=" * 60 + "\n")
    rows = run_scaling_experiment([2, 4, 8, 16, 32])
    print_comparison_table(rows)

    print("\n  结论要点:")
    print("  - Pairwise: 密钥存储 O(n^2)，成员变更需 O(n) 次新握手")
    print("  - Sender Key: 存储 O(n^2)，单次发送 O(1)，但成员变更需 O(n) 密钥分发")
    print("  - TreeKEM: 每成员仅存 O(log n) 节点密钥，Commit 仅需 O(log n) 次加密")


def main() -> int:
    print("TreeKEM 群组密钥管理 — 完整实验")
    demo_tree_geometry()
    demo_full_scenario()
    demo_scaling()
    print("\n实验完成。\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
