from unittest.mock import patch

from django.test import TestCase

from greedybear.cronjobs.commands.lsh import LSHConnectedComponents, UnionFind


class UnionFindTestCase(TestCase):
    def test_find_representative_applies_path_compression(self):
        u = UnionFind(4)
        u.parents = [0, 0, 1, 2]

        representative = u.find_representative(3)

        self.assertEqual(representative, 0)
        self.assertEqual(u.parents[3], 0)
        self.assertEqual(u.parents[2], 0)

    def test_union_merges_two_sets(self):
        u = UnionFind(3)

        u.union(0, 1)

        self.assertEqual(u.find_representative(0), u.find_representative(1))
        self.assertNotEqual(u.find_representative(0), u.find_representative(2))

    def test_union_same_element(self):
        u = UnionFind(3)

        u.union(1, 1)

        self.assertEqual(u.find_representative(1), 1)
        self.assertEqual(u.find_representative(0), 0)
        self.assertEqual(u.find_representative(2), 2)


class LSHConnectedComponentsTestCase(TestCase):
    def test_get_min_hashes_generates_matching_signatures(self):
        lsh = LSHConnectedComponents(num_perm=64)
        sequences = [
            ["ls", "-la", "/tmp"],
            ["ls", "-la", "/tmp"],
            ["python", "-m", "http.server"],
        ]

        min_hashes = lsh._get_min_hashes(sequences)

        self.assertEqual(len(min_hashes), len(sequences))
        self.assertEqual(min_hashes[0].jaccard(min_hashes[1]), 1.0)
        self.assertLess(min_hashes[0].jaccard(min_hashes[2]), 0.5)

    def test_get_labels_maps_components_to_compact_labels(self):
        sequences = [["a"], ["b"], ["c"], ["d"], ["e"]]
        u = UnionFind(len(sequences))
        u.union(0, 2)
        u.union(2, 4)
        u.union(1, 3)

        labels = LSHConnectedComponents()._get_labels(sequences, u)

        self.assertEqual(labels, [0, 1, 0, 1, 0])

    def test_get_components_returns_empty_for_empty_input(self):
        labels = LSHConnectedComponents().get_components([])
        self.assertEqual(labels, [])

    def test_get_components_single_element_input(self):
        sequences = [["a", "b", "c"]]
        labels = LSHConnectedComponents().get_components(sequences)
        self.assertEqual(labels, [0])

    def test_get_components_all_identical_sequences(self):
        sequences = [
            ["same", "sequence"],
            ["same", "sequence"],
            ["same", "sequence"],
        ]
        labels = LSHConnectedComponents().get_components(sequences)
        self.assertEqual(labels, [0, 0, 0])

    def test_get_components_groups_similar_sequences(self):
        sequences = [
            ["echo", "hello", "world"],
            ["echo", "hello", "world"],
            ["wget", "http://example.com"],
            ["wget", "http://example.com"],
        ]

        labels = LSHConnectedComponents(threshold=0.8, num_perm=256).get_components(sequences)

        self.assertEqual(len(labels), 4)
        self.assertEqual(labels[0], labels[1])
        self.assertEqual(labels[2], labels[3])
        self.assertNotEqual(labels[0], labels[2])

    def test_get_components_uses_lsh_matches_and_ignores_self_matches(self):
        class FakeLSH:
            def __init__(self, threshold, num_perm):
                self.threshold = threshold
                self.num_perm = num_perm
                self._inserted = []

            def insert(self, idx, min_hash):
                self._inserted.append((idx, min_hash))

            def query(self, min_hash):
                if min_hash == "mh0":
                    return [0, 1]
                if min_hash == "mh1":
                    return [1, 0, 2]
                return [2, 1]

        lsh = LSHConnectedComponents(threshold=0.7, num_perm=32)
        sequences = [["a"], ["b"], ["c"]]

        with (
            patch.object(lsh, "_get_min_hashes", return_value=["mh0", "mh1", "mh2"]),
            patch("greedybear.cronjobs.commands.lsh.MinHashLSH", FakeLSH),
        ):
            labels = lsh.get_components(sequences)

        self.assertEqual(labels, [0, 0, 0])
