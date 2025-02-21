import numpy as np
from greedybear.cronjobs.commands.cluster import compute_similarity_matrix, jaccard_similarity, tokenize

from . import CustomTestCase


class TokenizeTestCase(CustomTestCase):
    def test_tokenize_basic(self):
        """Test basic tokenization of simple commands"""
        input_seq = ["ls -l", "cd /home"]
        expected = ["ls", "-l", "cd", "/home"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_empty(self):
        """Test tokenization of empty sequences and strings"""
        self.assertEqual(tokenize([]), [])
        self.assertEqual(tokenize([""]), [])
        self.assertEqual(tokenize([" "]), [])
        self.assertEqual(tokenize(["", ""]), [])

    def test_tokenize_semicolons(self):
        """Test handling of semicolons in commands"""
        input_seq = ["ls -l;cd /home", "echo hello;pwd"]
        expected = ["ls", "-l", "cd", "/home", "echo", "hello", "pwd"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_multiple_spaces(self):
        """Test handling of multiple whitespace characters"""
        input_seq = ["ls   -l", "cd    /home"]
        expected = ["ls", "-l", "cd", "/home"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_mixed_delimiters(self):
        """Test handling of mixed semicolons and spaces"""
        input_seq = ["ls -l;  cd /home;pwd", "echo   hello ; ls"]
        expected = ["ls", "-l", "cd", "/home", "pwd", "echo", "hello", "ls"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_special_characters(self):
        """Test handling of special characters and paths"""
        input_seq = ["ls /usr/bin", "cd ../home", "echo $PATH"]
        expected = ["ls", "/usr/bin", "cd", "../home", "echo", "$PATH"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_quotes(self):
        """Test behavior with quoted strings (note: quotes are not preserved)"""
        input_seq = ['echo "hello world"', "ls 'Documents'"]
        expected = ["echo", '"hello', 'world"', "ls", "'Documents'"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_edge_cases(self):
        """Test edge cases with unusual inputs"""
        input_seq = [
            ";;;;;",  # Multiple semicolons
            "  ;  ;  ",  # Semicolons with spaces
            "\t\n",  # Special whitespace
            "cmd1;;cmd2",  # Multiple semicolons between commands
        ]
        expected = ["cmd1", "cmd2"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_mixed_content(self):
        """Test mixture of various command patterns"""
        input_seq = ["ls -l;cd /home;pwd", "echo hello   world", ";", "git commit -m 'update'"]
        expected = ["ls", "-l", "cd", "/home", "pwd", "echo", "hello", "world", "git", "commit", "-m", "'update'"]
        self.assertEqual(tokenize(input_seq), expected)


class JaccardTestCase(CustomTestCase):
    def test_jaccard_similarity_identical(self):
        """Test similarity of identical sequences"""
        self.assertEqual(jaccard_similarity(["a", "b", "c"], ["a", "b", "c"]), 1.0)
        self.assertEqual(jaccard_similarity(["a"], ["a"]), 1.0)

    def test_jaccard_similarity_disjoint(self):
        """Test similarity of completely different sequences"""
        self.assertEqual(jaccard_similarity(["a", "b"], ["c", "d"]), 0.0)

    def test_jaccard_similarity_partial(self):
        """Test similarity of partially overlapping sequences"""
        self.assertEqual(jaccard_similarity(["a", "b", "c"], ["b", "c", "d"]), 0.5)
        self.assertEqual(jaccard_similarity(["a", "b"], ["b", "c"]), 1 / 3)

    def test_jaccard_similarity_empty(self):
        """Test similarity with empty sequences"""
        self.assertEqual(jaccard_similarity([], []), 0.0)
        self.assertEqual(jaccard_similarity(["a", "b"], []), 0.0)
        self.assertEqual(jaccard_similarity([], ["a", "b"]), 0.0)

    def test_jaccard_similarity_duplicates(self):
        """Test that duplicates are handled correctly"""
        self.assertEqual(jaccard_similarity(["a", "a", "b"], ["a", "b", "b"]), 1.0)
        self.assertEqual(jaccard_similarity(["a", "a"], ["b", "b"]), 0.0)


class SimMatrixTestCase(CustomTestCase):
    def test_compute_similarity_matrix_basic(self):
        """Test basic similarity matrix computation"""
        sequences = [["a", "b"], ["b", "c"], ["a", "b", "c"]]
        matrix = compute_similarity_matrix(sequences)

        # Check dimensions
        self.assertEqual(matrix.shape, (3, 3))

        # Check symmetry
        self.assertEqual(np.allclose(matrix, matrix.T), True)

        # Check diagonal
        self.assertEqual(np.allclose(np.diag(matrix), 1.0), True)

        # Check specific values
        self.assertEqual(matrix[0, 1], 1 / 3)  # ['a', 'b'] vs ['b', 'c']
        self.assertEqual(matrix[0, 2], 2 / 3)  # ['a', 'b'] vs ['a', 'b', 'c']
        self.assertEqual(matrix[1, 2], 2 / 3)  # ['b', 'c'] vs ['a', 'b', 'c']

    def test_compute_similarity_matrix_empty(self):
        """Test handling of empty input"""
        self.assertEqual(compute_similarity_matrix([]).shape, (0, 0))

    def test_compute_similarity_matrix_single(self):
        """Test matrix computation with single sequence"""
        matrix = compute_similarity_matrix([["a", "b"]])
        self.assertEqual(matrix.shape, (1, 1))
        self.assertEqual(matrix[0, 0], 1.0)

    def test_compute_similarity_matrix_identical(self):
        """Test matrix computation with identical sequences"""
        sequences = [["a", "b"], ["a", "b"]]
        matrix = compute_similarity_matrix(sequences)
        self.assertEqual(np.allclose(matrix, np.ones((2, 2))), True)

    def test_compute_similarity_matrix_disjoint(self):
        """Test matrix computation with completely different sequences"""
        sequences = [["a", "b"], ["c", "d"], ["e", "f"]]
        matrix = compute_similarity_matrix(sequences)

        # Only diagonal should be 1.0, rest should be 0.0
        expected = np.eye(3)
        self.assertEqual(np.allclose(matrix, expected), True)

    def test_compute_similarity_matrix_properties(self):
        """Test mathematical properties of the similarity matrix"""
        sequences = [["a", "b"], ["b", "c"], ["c", "d"]]
        matrix = compute_similarity_matrix(sequences)

        # Properties to check:
        # 1. Symmetry
        self.assertEqual(np.allclose(matrix, matrix.T), True)

        # 2. Values between 0 and 1
        self.assertEqual(np.all((matrix >= 0) & (matrix <= 1)), True)

        # 3. Diagonal equals 1
        self.assertEqual(np.allclose(np.diag(matrix), 1.0), True)
