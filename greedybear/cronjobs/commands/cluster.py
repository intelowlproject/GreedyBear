import numpy as np
from greedybear.cronjobs.base import Cronjob
from greedybear.models import CommandSequence
from sklearn.cluster import DBSCAN


def tokenize(sequence: list[str]) -> list[str]:
    """
    Tokenize a sequence of command strings into individual tokens.

    This function processes a list of command strings and splits them into tokens.
    It treats semicolons and whitespace as token separators.

    Args:
        sequence: A list of command strings to tokenize.
            Example: ["cd foo; ls", "ls -la"]

    Returns:
        List[str]: A list of tokens extracted from the input sequence.
            Example: ["cd", "foo", "ls", "ls", "-la"]
    """
    result = []
    for line in sequence:
        result.extend(line.replace(";", " ").split())
    return result


def jaccard_similarity(seq1: list[str], seq2: list[str]) -> float:
    """
    Calculate the Jaccard similarity coefficient between two sequences.

    The Jaccard similarity coefficient is defined as the size of the intersection
    divided by the size of the union of two sets. It ranges from 0 (completely dissimilar)
    to 1 (identical).

    Args:
        seq1: First sequence of strings to compare
        seq2: Second sequence of strings to compare

    Returns:
        float: Jaccard similarity coefficient between the two sequences.
               Returns 0 if both sequences are empty.
    """
    set1 = set(seq1)
    set2 = set(seq2)
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union if union != 0 else 0


def compute_similarity_matrix(sequences: list[list[str]]) -> np.ndarray:
    """
    Compute a pairwise Jaccard similarity matrix for a list of sequences.

    Creates a symmetric matrix where each element [i,j] contains the Jaccard
    similarity between sequences[i] and sequences[j]. The diagonal elements
    are set to 1.0 (self-similarity).

    Time and space complexity: O(n²) where n is the number of sequences

    Args:
        sequences: List of token sequences to compare.

    Returns:
        np.ndarray: A symmetric n×n matrix of floats where n=len(sequences).
    """
    n = len(sequences)
    matrix = np.zeros((n, n))
    for i in range(n):
        for j in range(i + 1, n):
            similarity = jaccard_similarity(sequences[i], sequences[j])
            matrix[i, j] = similarity
            matrix[j, i] = similarity
        matrix[i, i] = 1.0
    return matrix


def dbscan_clustering(sequences: list[list[str]], eps: float = 0.5) -> np.ndarray:
    """
    Cluster sequences using DBSCAN based on Jaccard similarity.

    Performs density-based clustering on sequences using their pairwise Jaccard
    similarities. The similarity is converted to distance by subtracting from 1.
    Sequences with distance less than eps are considered neighbors.

    Args:
        sequences: List of token sequences to cluster.
        eps: Maximum distance between two samples for them to be
            considered as in the same neighborhood. Since we use Jaccard distance,
            eps=0.5 means sequences must share at least 50% of their tokens to be
            considered similar. Defaults to 0.5.

    Returns:
        np.ndarray: Array of cluster labels. Shape (n_samples,).
    """
    similarity_matrix = compute_similarity_matrix(sequences)
    distance_matrix = 1 - similarity_matrix
    dbscan = DBSCAN(eps=eps, min_samples=1, metric="precomputed")
    return dbscan.fit_predict(distance_matrix)


class ClusterCommandSequences(Cronjob):
    """
    A cronjob that clusters command sequences based on their similarity.

    This job processes all CommandSequence objects in the database, clusters them
    using DBSCAN algorithm with Jaccard similarity as the distance metric, and
    assigns cluster labels back to the objects. Commands within the same cluster
    represent similar execution patterns.
    """

    def run(self) -> None:
        """
        Workflow:
        1. Retrieve all command sequences with their current cluster assignments
        2. Early exit if no sequences exist
        3. Tokenize commands and performs DBSCAN clustering
        4. Identify sequences whose cluster assignment has changed
        5. Perform batched bulk updates for changed sequences only
        """
        sequences = list(CommandSequence.objects.all().only("commands", "cluster"))
        if not sequences:
            self.log.info("no sequences found to cluster")
            return
        self.log.info(f"clustering {len(sequences)} command sequences")
        tokenized_seqs = [tokenize(s.commands) for s in sequences]
        cluster_labels = dbscan_clustering(tokenized_seqs)
        seqs_to_update = []
        for seq, label in zip(sequences, cluster_labels):
            if seq.cluster != label:
                seq.cluster = label
                seqs_to_update.append(seq)
        self.log.info(f"writing updated clusters for {len(seqs_to_update)} command sequences to DB")
        result = CommandSequence.objects.bulk_update(seqs_to_update, ["cluster"], batch_size=1000) if seqs_to_update else 0
        self.log.info(f"{result} IoCs were updated")
