from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.commands.lsh import LSHConnectedComponents
from greedybear.models import CommandSequence


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
        cluster_labels = LSHConnectedComponents().get_components(tokenized_seqs)
        seqs_to_update = []
        for seq, label in zip(sequences, cluster_labels, strict=False):
            if seq.cluster != label:
                seq.cluster = label
                seqs_to_update.append(seq)
        self.log.info(
            f"writing updated clusters for {len(seqs_to_update)} command sequences to DB"
        )
        result = (
            CommandSequence.objects.bulk_update(
                seqs_to_update, ["cluster"], batch_size=1000
            )
            if seqs_to_update
            else 0
        )
        self.log.info(f"{result} IoCs were updated")
