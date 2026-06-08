"""
TreeKEM 基础框架（向后兼容入口）

完整实现见 treekem/ 包与 run_experiment.py。
本文件保留原始教学示例，并演示如何调用完整框架。
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Optional, List

backend = default_backend()


class TreeKEMNode:
    """TreeKEM 树节点模型（简化堆式索引，教学用）"""

    def __init__(self, node_idx: int):
        self.node_idx = node_idx
        self.private_key: Optional[bytes] = None
        self.public_key: Optional[bytes] = None
        self.parent: Optional["TreeKEMNode"] = None
        self.left: Optional["TreeKEMNode"] = None
        self.right: Optional["TreeKEMNode"] = None
        self.is_leaf = False


class TreeKEMTree:
    """TreeKEM 二叉树基础架构（简化堆式索引，教学用）"""

    def __init__(self, member_num: int):
        self.member_num = member_num
        self.root: Optional[TreeKEMNode] = None
        self.nodes: List[TreeKEMNode] = []
        self._build_tree()

    def _build_tree(self):
        total_nodes = 2 * self.member_num - 1
        for i in range(total_nodes):
            self.nodes.append(TreeKEMNode(i))
        leaf_start = self.member_num - 1
        for i in range(leaf_start, total_nodes):
            self.nodes[i].is_leaf = True
        for node in self.nodes:
            idx = node.node_idx
            left_idx = 2 * idx + 1
            right_idx = 2 * idx + 2
            if left_idx < total_nodes:
                node.left = self.nodes[left_idx]
                self.nodes[left_idx].parent = node
            if right_idx < total_nodes:
                node.right = self.nodes[right_idx]
                self.nodes[right_idx].parent = node
        self.root = self.nodes[0]

    def get_leaf_node(self, member_id: int) -> TreeKEMNode:
        leaf_start = self.member_num - 1
        return self.nodes[leaf_start + member_id]

    def generate_node_key(self, node: TreeKEMNode, seed: bytes):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"treekem-node-{node.node_idx}".encode(),
            backend=backend,
        )
        derived_key = hkdf.derive(seed)
        node.private_key = derived_key
        h = hashes.Hash(hashes.SHA256(), backend)
        h.update(derived_key)
        node.public_key = h.finalize()

    def update_path_keys(self, leaf_node: TreeKEMNode, base_seed: bytes) -> int:
        current_node = leaf_node
        current_seed = base_seed
        update_count = 0
        while current_node is not None:
            self.generate_node_key(current_node, current_seed)
            update_count += 1
            current_seed = current_node.public_key
            current_node = current_node.parent
        return update_count


if __name__ == "__main__":
    print("=== 简化教学示例（堆式二叉树）===")
    kem_tree = TreeKEMTree(6)
    target_leaf = kem_tree.get_leaf_node(2)
    kem_tree.update_path_keys(target_leaf, b"mls-treekem-base-seed-2026")
    print(f"路径更新节点数: {kem_tree.update_path_keys.__doc__ and '见完整框架'}")

    print("\n=== RFC 9420 完整实现演示 ===")
    from run_experiment import main
    main()
