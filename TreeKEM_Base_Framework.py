from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Optional, List

# 后端初始化
backend = default_backend()

class TreeKEMNode:
    """TreeKEM 树节点模型"""
    def __init__(self, node_idx: int):
        self.node_idx = node_idx       # 节点唯一索引
        self.private_key: Optional[bytes] = None  # 节点私钥
        self.public_key: Optional[bytes] = None    # 节点公钥
        self.parent: Optional[TreeKEMNode] = None  # 父节点
        self.left: Optional[TreeKEMNode] = None     # 左子节点
        self.right: Optional[TreeKEMNode] = None   # 右子节点
        self.is_leaf = False         # 是否为叶子节点（群组成员）

class TreeKEMTree:
    """TreeKEM 二叉树基础架构"""
    def __init__(self, member_num: int):
        self.member_num = member_num  # 群组成员数量
        self.root: Optional[TreeKEMNode] = None
        self.nodes: List[TreeKEMNode] = []  # 全节点列表
        self._build_tree()

    def _build_tree(self):
        """递归构建满二叉树，叶子节点对应群组成员"""
        total_nodes = 2 * self.member_num - 1
        # 初始化所有节点
        for i in range(total_nodes):
            self.nodes.append(TreeKEMNode(i))
        # 标记叶子节点
        leaf_start = self.member_num - 1
        for i in range(leaf_start, total_nodes):
            self.nodes[i].is_leaf = True
        # 构建父子、左右子节点关联
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
        """根据成员ID获取对应叶子节点"""
        leaf_start = self.member_num - 1
        return self.nodes[leaf_start + member_id]

    def generate_node_key(self, node: TreeKEMNode, seed: bytes):
        """基于HKDF为节点生成公私钥（仿真密钥派生）"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"treekem-node-{node.node_idx}".encode(),
            backend=backend
        )
        derived_key = hkdf.derive(seed)
        node.private_key = derived_key
        # 仿真公钥（工程简化：公钥取私钥哈希）
        h = hashes.Hash(hashes.SHA256(), backend)
        h.update(derived_key)
        node.public_key = h.finalize()

    def update_path_keys(self, leaf_node: TreeKEMNode, base_seed: bytes):
        """
        路径密钥更新：从指定叶子节点向上遍历至根节点，逐级更新所有父节点密钥
        对应TreeKEM 成员密钥变更后，整条上行路径密钥刷新逻辑
        """
        current_node = leaf_node
        current_seed = base_seed
        update_count = 0
        while current_node is not None:
            # 更新当前节点密钥
            self.generate_node_key(current_node, current_seed)
            update_count += 1
            # 种子迭代：基于当前节点公钥生成下一级种子
            current_seed = current_node.public_key
            # 向上走到父节点
            current_node = current_node.parent
        print(f"路径更新完成，共更新 {update_count} 个节点密钥")
        return update_count

# 完整功能测试
if __name__ == "__main__":
    # 1. 基础树测试
    group_tree = TreeKEMTree(member_num=5)
    print(f"群组总节点数：{len(group_tree.nodes)}")
    print(f"根节点索引：{group_tree.root.node_idx}")
    print(f"成员0对应叶子节点索引：{group_tree.get_leaf_node(0).node_idx}")
    print("=== TreeKEM 基础架构搭建完成 ===")

    print("\n" + "="*50)

    # 2. 完整密钥更新测试
    member_count = 6
    kem_tree = TreeKEMTree(member_count)
    print(f"【初始化】{member_count}人群组TreeKEM树构建成功")

    target_leaf = kem_tree.get_leaf_node(2)
    print(f"【目标节点】成员2 对应叶子节点索引：{target_leaf.node_idx}")

    init_seed = b"mls-treekem-base-seed-2026"
    kem_tree.update_path_keys(target_leaf, init_seed)

    print(f"【节点密钥校验】叶子节点公钥：{target_leaf.public_key.hex()[:20]}...")
    print("=== TreeKEM 基础架构 + 密钥更新逻辑 运行正常 ===")