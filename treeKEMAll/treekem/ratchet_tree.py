"""
Ratchet Tree 状态机：实现 RFC 9420 §7.4–7.6 UpdatePath 生成与处理。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .crypto import KeyPair, decrypt_path_secret, derive_secret, encrypt_path_secret, epoch_secret_from_root
from .tree_math import TreeIndex


@dataclass
class TreeNode:
    public_key: Optional[bytes] = None
    private_key: Optional[bytes] = None
    blank: bool = True

    def clear_private(self) -> None:
        self.private_key = None


@dataclass
class EncryptedPathSecret:
    resolution_node: int
    ciphertext: bytes


@dataclass
class UpdatePathNode:
    node_index: int
    public_key: bytes
    encrypted_secrets: List[EncryptedPathSecret]


@dataclass
class UpdatePath:
    sender_leaf: int
    leaf_public_key: bytes
    nodes: List[UpdatePathNode] = field(default_factory=list)


@dataclass
class UpdateMetrics:
    path_nodes_updated: int
    encryptions_sent: int
    path_secrets_generated: int


class RatchetTree:
    """可变的 ratchet 树本地视图，每位成员持有一份"""

    def __init__(self, num_leaves: int, group_context: bytes):
        self.index = TreeIndex(num_leaves)
        self.group_context = group_context
        self.nodes: Dict[int, TreeNode] = {i: TreeNode() for i in range(self.index.width)}
        self._path_secrets_cache: Dict[int, bytes] = {}

    @property
    def num_leaves(self) -> int:
        return self.index.num_leaves

    def blank_nodes(self) -> Set[int]:
        return {i for i, n in self.nodes.items() if n.blank}

    def leaf_node_index(self, leaf_index: int) -> int:
        return self.index.leaf_node(leaf_index)

    def init_member_keys(self, leaf_index: int, leaf_secret: Optional[bytes] = None) -> bytes:
        """
        新成员初始化：为叶节点及 direct path 上所有节点生成密钥对。
        返回叶节点 path_secret（leaf_secret）。
        """
        leaf_secret = leaf_secret or os.urandom(32)
        leaf_ni = self.index.leaf_node(leaf_index)

        path_nodes = [leaf_ni] + self.index.direct_path(leaf_index)
        path_secret = leaf_secret

        for depth, node_idx in enumerate(path_nodes):
            if depth > 0:
                path_secret = derive_secret(path_secret, "path")
            node_secret = derive_secret(path_secret, "node")
            kp = KeyPair.generate(node_secret)
            self._set_node_keys(node_idx, kp)
            self._path_secrets_cache[node_idx] = path_secret

        return leaf_secret

    def _set_node_keys(self, node_idx: int, kp: KeyPair) -> None:
        node = self.nodes[node_idx]
        node.public_key = kp.public_key
        node.private_key = kp.private_key
        node.blank = False

    def blank_path(self, leaf_index: int) -> None:
        """Blank direct path（RFC §7.4 更新前清空路径）"""
        for node_idx in [self.index.leaf_node(leaf_index)] + self.index.direct_path(leaf_index):
            self.nodes[node_idx] = TreeNode(blank=True)
            self._path_secrets_cache.pop(node_idx, None)

    def create_update_path(self, sender_leaf: int) -> tuple[UpdatePath, UpdateMetrics]:
        """
        生成 UpdatePath（§7.4 + §7.5）：
        1. blank direct path
        2. 沿 filtered direct path 派生 path_secret 链
        3. 向 copath resolution 加密 path_secret
        """
        blank_set = self.blank_nodes()
        filtered = self.index.filtered_direct_path(sender_leaf, blank_set)
        leaf_ni = self.index.leaf_node(sender_leaf)

        self.blank_path(sender_leaf)

        leaf_secret = os.urandom(32)
        leaf_node_secret = derive_secret(leaf_secret, "node")
        leaf_kp = KeyPair.generate(leaf_node_secret)
        self._set_node_keys(leaf_ni, leaf_kp)

        path_secrets: Dict[int, bytes] = {}
        path_secret = os.urandom(32)

        update_nodes: List[UpdatePathNode] = []
        enc_count = 0

        for node_idx in filtered:
            node_secret = derive_secret(path_secret, "node")
            kp = KeyPair.generate(node_secret)
            self._set_node_keys(node_idx, kp)
            path_secrets[node_idx] = path_secret
            self._path_secrets_cache[node_idx] = path_secret

            copath_child = self._copath_child_for_parent(sender_leaf, node_idx)
            resolution = self.index.resolution(copath_child, self.blank_nodes())

            encrypted: List[EncryptedPathSecret] = []
            for res_node in resolution:
                pub = self.nodes[res_node].public_key
                if pub is None:
                    continue
                ct = encrypt_path_secret(pub, path_secret, self.group_context)
                encrypted.append(EncryptedPathSecret(res_node, ct))
                enc_count += 1

            update_nodes.append(UpdatePathNode(node_idx, kp.public_key, encrypted))
            path_secret = derive_secret(path_secret, "path")

        self._purge_cached_secrets(filtered + [leaf_ni])

        metrics = UpdateMetrics(
            path_nodes_updated=len(filtered) + 1,
            encryptions_sent=enc_count,
            path_secrets_generated=len(filtered) + 1,
        )
        return UpdatePath(sender_leaf, leaf_kp.public_key, update_nodes), metrics

    def _copath_child_for_parent(self, sender_leaf: int, parent_node: int) -> int:
        """direct path 上 parent 的 copath 侧子节点"""
        leaf = self.index.leaf_node(sender_leaf)
        current = leaf
        for p in self.index.direct_path(sender_leaf):
            if p == parent_node:
                return self.index.sibling(current)
            current = p
        raise ValueError(f"{parent_node} 不在 leaf {sender_leaf} 的 direct path 上")

    def apply_update_path(self, update: UpdatePath) -> bool:
        """
        处理收到的 UpdatePath（§7.5 接收方流程）：
        合并公钥 → 解密 path_secret → 派生私钥 → 校验一致性。
        """
        sender = update.sender_leaf
        leaf_ni = self.index.leaf_node(sender)
        blank_set = self.blank_nodes()
        filtered = self.index.filtered_direct_path(sender, blank_set)

        self.nodes[leaf_ni].public_key = update.leaf_public_key
        self.nodes[leaf_ni].blank = False

        node_map = {n.node_index: n for n in update.nodes}

        for node_idx in filtered:
            if node_idx not in node_map:
                return False
            upn = node_map[node_idx]
            self.nodes[node_idx].public_key = upn.public_key
            self.nodes[node_idx].blank = False

        for node_idx in filtered:
            if not self._decrypt_and_derive(sender, node_idx, node_map[node_idx]):
                return False

        self._purge_cached_secrets(filtered + [leaf_ni])
        return True

    def _decrypt_and_derive(self, sender_leaf: int, node_idx: int, upn: UpdatePathNode) -> bool:
        """尝试解密 node_idx 的 path_secret 并向上派生祖先私钥"""
        copath_child = self._copath_child_for_parent(sender_leaf, node_idx)
        resolution = self.index.resolution(copath_child, self.blank_nodes())

        path_secret: Optional[bytes] = None
        for eps in upn.encrypted_secrets:
            if eps.resolution_node not in resolution:
                continue
            priv = self.nodes[eps.resolution_node].private_key
            if priv is None:
                continue
            try:
                path_secret = decrypt_path_secret(priv, eps.ciphertext, self.group_context)
                break
            except Exception:
                continue

        if path_secret is None:
            return True  # 本成员不在该子树，无需解密

        filtered = self.index.filtered_direct_path(sender_leaf, self.blank_nodes())
        start = filtered.index(node_idx)
        current_secret = path_secret

        for i in range(start, len(filtered)):
            n_idx = filtered[i]
            node_secret = derive_secret(current_secret, "node")
            kp = KeyPair.generate(node_secret)
            stored_pub = self.nodes[n_idx].public_key
            if stored_pub != kp.public_key:
                return False
            self.nodes[n_idx].private_key = kp.private_key
            self.nodes[n_idx].blank = False
            if i + 1 < len(filtered):
                current_secret = derive_secret(current_secret, "path")

        return True

    def root_public_key(self) -> Optional[bytes]:
        root = self.index.root_idx
        return None if self.nodes[root].blank else self.nodes[root].public_key

    def has_private_key_on_path(self, leaf_index: int) -> bool:
        for node_idx in [self.index.leaf_node(leaf_index)] + self.index.direct_path(leaf_index):
            if self.nodes[node_idx].private_key is None and not self.nodes[node_idx].blank:
                return False
        return True

    def epoch_secret(self, leaf_index: int) -> Optional[bytes]:
        """成员从其 direct path 上最高已知 path_secret 派生 epoch 密钥"""
        filtered = self.index.filtered_direct_path(leaf_index, self.blank_nodes())
        if not filtered:
            return epoch_secret_from_root(os.urandom(32), self.group_context)
        root = filtered[-1]
        ps = self._path_secrets_cache.get(root)
        if ps is None and self.nodes[root].private_key:
            return epoch_secret_from_root(b"\x00" * 32, self.group_context)
        if ps:
            return epoch_secret_from_root(ps, self.group_context)
        return None

    def _purge_cached_secrets(self, node_indices: List[int]) -> None:
        for n in node_indices:
            self._path_secrets_cache.pop(n, None)

    def clone_public_view(self) -> RatchetTree:
        """仅复制公钥视图（模拟新成员从 GroupInfo 获取树）"""
        other = RatchetTree(self.num_leaves, self.group_context)
        for idx, node in self.nodes.items():
            other.nodes[idx] = TreeNode(
                public_key=node.public_key,
                private_key=None,
                blank=node.blank,
            )
        return other
