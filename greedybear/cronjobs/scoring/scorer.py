import logging
from abc import ABCMeta, abstractmethod

import pandas as pd


class Scorer(metaclass=ABCMeta):
    """
    Abstract base class for implementing scoring mechanisms.

    This class serves as a template for different scoring implementations,
    enforcing a consistent interface while allowing flexible implementations.

    Attributes:
        name (str): Identifier for the scorer instance
        score_name (str): Name of the score this implementation produces
        trainable (bool): Indicates if the scorer requires/supports training

    Methods:
        score(df): Abstract method that must be implemented by subclasses
            to perform the actual scoring logic
    """

    def __init__(self, name: str, score_name: str, trainable: bool):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.name = name
        self.score_name = score_name
        self.trainable = trainable

    @abstractmethod
    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate scores for the provided data and append them as a new column.

        Args:
            df: Input data to be scored

        Returns:
            pd.DataFrame: Input DataFrame with a new column added, where:
                - Column name is specified by self.score_name
                - Column contains the calculated scores for each row
        """
