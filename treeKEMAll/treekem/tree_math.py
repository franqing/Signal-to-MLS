"""
RFC 9420 Appendix C — 数组表示的左平衡二叉树几何运算。

节点编号规则：叶子在偶数索引 2*i，内部节点在奇数索引。
direct_path / copath / resolution 与标准完全一致。
"""

from __future__ import annotations

import math
from typing import List, Set


def _log2_floor(x: int) -> int:
    if x <= 0:
        return 0
    return x.bit_length() - 1


class TreeIndex:
    """封装一棵有 num_leaves 个叶子的 ratchet 树索引运算"""

    def __init__(self, num_leaves: int):
        if num_leaves < 1:
            raise ValueError("num_leaves 必须 >= 1")
        self.num_leaves = num_leaves
        self.width = 2 * (num_leaves - 1) + 1
        self.root_idx = (1 << _log2_floor(self.width)) - 1

    @staticmethod
    def pad_to_power_of_two(n: int) -> int:
        return 1 << math.ceil(math.log2(max(n, 1)))

    def leaf_node(self, leaf_index: int) -> int:
        if not 0 <= leaf_index < self.num_leaves:
            raise IndexError(f"leaf_index {leaf_index} 越界")
        return 2 * leaf_index

    def is_leaf(self, node: int) -> bool:
        return self.level(node) == 0

    def level(self, node: int) -> int:
        if node & 1 == 0:
            return 0
        k = 0
        while (node >> k) & 1:
            k += 1
        return k

    def left(self, node: int) -> int:
        k = self.level(node)
        if k == 0:
            raise ValueError("叶子无子节点")
        return node ^ (1 << (k - 1))

    def right(self, node: int) -> int:
        k = self.level(node)
        if k == 0:
            raise ValueError("叶子无子节点")
        return node ^ (3 << (k - 1))

    def parent(self, node: int) -> int:
        if node == self.root_idx:
            raise ValueError("根节点无父节点")
        k = self.level(node)
        b = (node >> (k + 1)) & 1
        return (node | (1 << k)) ^ (b << (k + 1))

    def sibling(self, node: int) -> int:
        p = self.parent(node)
        if node < p:
            return self.right(p)
        return self.left(p)

    def direct_path(self, leaf_index: int) -> List[int]:
        """从叶到根的有序父节点列表（不含叶本身）"""
        node = self.leaf_node(leaf_index)
        if node == self.root_idx:
            return []
        path: List[int] = []
        while node != self.root_idx:
            node = self.parent(node)
            path.append(node)
        return path

    def copath(self, leaf_index: int) -> List[int]:
        """copath：direct path 上各节点的兄弟，叶到根顺序"""
        leaf = self.leaf_node(leaf_index)
        if leaf == self.root_idx:
            return []
        nodes = [leaf] + self.direct_path(leaf_index)
        nodes.pop()  # 去掉根
        return [self.sibling(n) for n in nodes]

    def filtered_direct_path(self, leaf_index: int, blank_nodes: Set[int]) -> List[int]:
        """
        过滤 direct path：若 copath 侧子树的 resolution 为空，则跳过该父节点。
        简化实现遵循 RFC 9420 §4.1.2 定义。
        """
        full = self.direct_path(leaf_index)
        copath_nodes = self.copath(leaf_index)
        if not full:
            return full

        filtered: List[int] = []
        leaf = self.leaf_node(leaf_index)
        current = leaf
        copath_iter = iter(copath_nodes)

        for parent in full:
            _ = next(copath_iter, None)
            copath_child = self.sibling(current)
            res = self.resolution(copath_child, blank_nodes)
            if res:
                filtered.append(parent)
            current = parent
        return filtered

    def resolution(self, node: int, blank_nodes: Set[int]) -> List[int]:
        """节点 resolution：覆盖其所有非 blank 后代的最小非 blank 节点集"""
        if node not in blank_nodes:
            return [node]
        if self.is_leaf(node):
            return []
        left_res = self.resolution(self.left(node), blank_nodes)
        right_res = self.resolution(self.right(node), blank_nodes)
        return left_res + right_res

    def subtree_contains(self, ancestor_leaf: int, node: int) -> bool:
        """node 是否在 ancestor_leaf 所在子树内（含自身）"""
        leaf_node = self.leaf_node(ancestor_leaf)
        if node == leaf_node:
            return True
        cur = leaf_node
        while cur != self.root_idx:
            cur = self.parent(cur)
            if cur == node:
                return True
        return False

    def lowest_common_ancestor(self, leaf_a: int, leaf_b: int) -> int:
        path_a = {self.leaf_node(leaf_a)} | set(self.direct_path(leaf_a))
        path_b = {self.leaf_node(leaf_b)} | set(self.direct_path(leaf_b))
        common = path_a & path_b
        if not common:
            raise ValueError("无公共祖先")
        return min(common, key=self.level)
