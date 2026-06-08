"""TreeKEM 完整场景单元测试"""

import pytest

from treekem.benchmark import pairwise_metrics, run_scaling_experiment, sender_key_metrics, treekem_measured_metrics
from treekem.group import MLSGroup
from treekem.tree_math import TreeIndex


class TestTreeGeometry:
    def test_leaf_positions(self):
        idx = TreeIndex(8)
        assert idx.leaf_node(0) == 0
        assert idx.leaf_node(7) == 14
        assert idx.root_idx == 7

    def test_direct_path_length(self):
        idx = TreeIndex(8)
        for leaf in range(8):
            assert len(idx.direct_path(leaf)) == idx.level(idx.root_idx)

    def test_copath_sibling_of_leaf(self):
        idx = TreeIndex(4)
        assert idx.copath(0)[0] == idx.leaf_node(1)

    def test_filtered_equals_direct_when_no_blanks(self):
        idx = TreeIndex(8)
        for leaf in range(8):
            assert idx.filtered_direct_path(leaf, set()) == idx.direct_path(leaf)


class TestMLSGroup:
    def test_init_consistency(self):
        g = MLSGroup(["A", "B", "C", "D"])
        assert g.verify_tree_consistency()
        assert len(g.members) == 4

    def test_self_update_preserves_consistency(self):
        g = MLSGroup(["A", "B", "C", "D"])
        g.broadcast_commit("B")
        assert g.verify_tree_consistency()

    def test_add_member(self):
        g = MLSGroup(["A", "B", "C", "D"])
        member, _ = g.add_member("E")
        assert "E" in g.members
        assert g.verify_tree_consistency()
        assert member.leaf_index == 4

    def test_remove_member(self):
        g = MLSGroup(["A", "B", "C", "D"])
        g.remove_member("C", "A")
        assert "C" not in g.members
        assert g.verify_tree_consistency()

    def test_multiple_updates_change_root(self):
        g = MLSGroup(["A", "B"])
        root0 = g.members["A"].root_public_key
        g.broadcast_commit("A")
        root1 = g.members["A"].root_public_key
        g.broadcast_commit("B")
        root2 = g.members["B"].root_public_key
        assert root0 != root1
        assert root1 != root2

    def test_epoch_increments(self):
        g = MLSGroup(["A", "B", "C"])
        initial = g.epoch
        g.broadcast_commit("A")
        g.broadcast_commit("B")
        assert g.epoch == initial + 2


class TestBenchmark:
    def test_pairwise_quadratic(self):
        m4 = pairwise_metrics(4)
        m8 = pairwise_metrics(8)
        assert m4.key_pairs_stored == 6
        assert m8.key_pairs_stored == 28

    def test_sender_key_linear_per_member(self):
        m = sender_key_metrics(10)
        assert m.key_pairs_stored == 90

    def test_treekem_logarithmic(self):
        m4 = treekem_measured_metrics(4)
        m16 = treekem_measured_metrics(16)
        assert m16.ciphertexts_per_update <= m16.tree_height + 2
        assert m16.ciphertexts_per_update < sender_key_metrics(16).ciphertexts_per_update

    def test_scaling_monotonic(self):
        rows = run_scaling_experiment([4, 8, 16])
        for i in range(1, len(rows)):
            assert rows[i]["pairwise_keys"] > rows[i - 1]["pairwise_keys"]
            assert rows[i]["treekem_measured_ciphertexts"] >= rows[i - 1]["treekem_measured_ciphertexts"]


class TestRatchetTreePaths:
  def test_resolution_blank_leaf(self):
      idx = TreeIndex(4)
      blanks = {idx.leaf_node(2)}
      assert idx.resolution(idx.leaf_node(2), blanks) == []

  def test_resolution_non_blank(self):
      idx = TreeIndex(4)
      node = idx.leaf_node(1)
      assert idx.resolution(node, set()) == [node]
