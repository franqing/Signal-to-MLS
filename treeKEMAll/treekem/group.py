"""
MLS 群组状态：成员加入 / 退出 / 自更新 完整场景模拟。
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .ratchet_tree import RatchetTree, UpdateMetrics, UpdatePath
from .tree_math import TreeIndex


@dataclass
class GroupMember:
    member_id: str
    leaf_index: int
    tree: RatchetTree

    def create_commit(self) -> tuple[UpdatePath, UpdateMetrics]:
        return self.tree.create_update_path(self.leaf_index)

    def process_commit(self, update: UpdatePath) -> bool:
        return self.tree.apply_update_path(update)

    @property
    def root_public_key(self) -> Optional[bytes]:
        return self.tree.root_public_key()


@dataclass
class CommitRecord:
    epoch: int
    sender: str
    action: str
    metrics: UpdateMetrics


class MLSGroup:
    """简化 MLS 群组：串行 epoch，广播 Commit"""

    def __init__(self, member_ids: List[str]):
        if not member_ids:
            raise ValueError("至少一名成员")
        self.member_ids_order = list(member_ids)
        self.num_leaves = TreeIndex.pad_to_power_of_two(len(member_ids))
        self.group_context = hashlib.sha256(
            b"mls-group-" + ",".join(member_ids).encode()
        ).digest()
        self.members: Dict[str, GroupMember] = {}
        self.active_leaves: List[Optional[str]] = [None] * self.num_leaves
        self.epoch = 0
        self.history: List[CommitRecord] = []

        self._bootstrap_members(member_ids)

    def _bootstrap_members(self, member_ids: List[str]) -> None:
        """顺序加入：每名新成员克隆公钥树、初始化叶密钥并广播 Commit"""
        for i, mid in enumerate(member_ids):
            if i == 0:
                tree = RatchetTree(self.num_leaves, self.group_context)
                tree.init_member_keys(0)
            else:
                ref_tree = self.members[member_ids[0]].tree
                tree = ref_tree.clone_public_view()
                tree.init_member_keys(i)

            self.members[mid] = GroupMember(mid, i, tree)
            self.active_leaves[i] = mid

            if i > 0:
                self._broadcast_from(mid, action="bootstrap")

    def _broadcast_from(self, sender_id: str, action: str) -> UpdateMetrics:
        sender = self.members[sender_id]
        update, metrics = sender.create_commit()
        self.epoch += 1
        for mid, member in self.members.items():
            if mid == sender_id:
                continue
            if not member.process_commit(update):
                raise RuntimeError(f"成员 {mid} 处理 Commit 失败 (epoch={self.epoch})")
        self.history.append(CommitRecord(self.epoch, sender_id, action, metrics))
        return metrics

    def broadcast_commit(self, sender_id: str, action: str = "update") -> UpdateMetrics:
        return self._broadcast_from(sender_id, action)

    def _extend_tree(self) -> None:
        """树容量翻倍：将所有成员的 ratchet 树扩展到 2 倍叶子数"""
        new_size = self.num_leaves * 2
        self.active_leaves.extend([None] * self.num_leaves)
        for m in self.members.values():
            new_tree = RatchetTree(new_size, self.group_context)
            old_idx = m.tree.index
            for node_i, node in m.tree.nodes.items():
                if node_i < old_idx.width and not node.blank:
                    new_tree.nodes[node_i] = node
            m.tree = new_tree
        self.num_leaves = new_size

    def add_member(self, member_id: str) -> tuple[GroupMember, UpdateMetrics]:
        if member_id in self.members:
            raise ValueError(f"{member_id} 已存在")
        if None not in self.active_leaves:
            self._extend_tree()

        leaf_index = self.active_leaves.index(None)

        ref_tree = next(iter(self.members.values())).tree
        tree = ref_tree.clone_public_view()
        tree.init_member_keys(leaf_index)

        member = GroupMember(member_id, leaf_index, tree)
        self.members[member_id] = member
        self.active_leaves[leaf_index] = member_id

        metrics = self._broadcast_from(member_id, action="add")
        return member, metrics

    def remove_member(self, member_id: str, committer_id: str) -> UpdateMetrics:
        if member_id not in self.members:
            raise ValueError(f"{member_id} 不存在")
        if committer_id not in self.members:
            raise ValueError(f"{committer_id} 不存在")

        leaf_index = self.members[member_id].leaf_index
        leaf_ni = self.members[committer_id].tree.index.leaf_node(leaf_index)

        for m in self.members.values():
            m.tree.blank_path(leaf_index)
            m.tree.nodes[leaf_ni].blank = True

        del self.members[member_id]
        self.active_leaves[leaf_index] = None

        return self._broadcast_from(committer_id, action="remove")

    def verify_tree_consistency(self) -> bool:
        roots = {m.root_public_key for m in self.members.values()}
        return len(roots) == 1 and None not in roots

    def get_complexity_stats(self) -> dict:
        if not self.history:
            return {}
        total_enc = sum(r.metrics.encryptions_sent for r in self.history)
        total_nodes = sum(r.metrics.path_nodes_updated for r in self.history)
        return {
            "epochs": self.epoch,
            "total_encryptions": total_enc,
            "total_path_nodes": total_nodes,
            "avg_encryptions_per_commit": total_enc / len(self.history),
            "member_count": len(self.members),
            "tree_height": int(math.ceil(math.log2(self.num_leaves))) if self.num_leaves > 1 else 0,
        }
