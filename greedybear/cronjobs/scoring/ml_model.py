from abc import abstractmethod
from functools import cached_property
from io import BytesIO

import joblib
import numpy as np
import pandas as pd
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from greedybear.cronjobs.scoring.consts import MULTI_VAL_FEATURES, SAMPLE_COUNT
from greedybear.cronjobs.scoring.scorer import Scorer
from greedybear.cronjobs.scoring.utils import multi_label_encode
from greedybear.settings import ML_MODEL_DIRECTORY
from sklearn.model_selection import train_test_split


class MLModel(Scorer):
    """
    Machine learning model wrapper that implements the Scorer interface.
    Supports both classification and regression models with persistent storage.
    """

    def __init__(self, name: str, score_name: str):
        super().__init__(name, score_name, True)

    @cached_property
    def file_name(self) -> str:
        """
        Convert model name to a filename-safe format.

        Returns:
            str: Lowercase model name with spaces replaced by underscores
        """
        return self.name.replace(" ", "_").lower()

    @cached_property
    def model(self):
        """
        Load the serialized model from persistent storage.

        Attempts to deserialize and load the model using joblib from
        the storage location determined by the model's name.
        """
        self.log.info(f"loading {self.name} model from file system")
        storage = FileSystemStorage(location=ML_MODEL_DIRECTORY)
        try:
            with storage.open(self.file_name, "rb") as file:
                result = joblib.load(file)
        except Exception as exc:
            self.log.error(f"failed to load model for {self.name}")
            raise exc
        return result

    def save(self) -> None:
        """
        Serialize and save the model to persistent storage.

        The model is saved using joblib serialization to a file location
        determined by the model's name. If a file already exists for this
        model, it will be overwritten.
        """
        self.log.info(f"saving {self.name} model to file system")
        storage = FileSystemStorage(location=ML_MODEL_DIRECTORY)
        with BytesIO() as model_buffer:
            joblib.dump(self.model, model_buffer)
            try:
                if storage.exists(self.file_name):
                    storage.delete(self.file_name)
                storage.save(self.file_name, ContentFile(model_buffer.getvalue()))
            except Exception as exc:
                self.log.error(f"failed to save model for {self.name}")
                raise exc

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Score input data using the trained model.

        Creates predictions for the input data and adds them as a new column.
        Handles multi-value feature encoding and ensures input data contains
        all required features.

        Args:
            df: Input data to score

        Returns:
            pd.DataFrame: Copy of input DataFrame with score column added
                as self.score_name

        Raises:
            ValueError: If required features are missing from input
        """
        self.log.info(f"calculate {self.score_name} with {self.name}")
        missing_features = set(self.features) - set(df.columns)
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")

        X = df[self.features].copy()
        for feature in MULTI_VAL_FEATURES:
            X = multi_label_encode(X, feature)

        result_df = df.copy()
        result_df[self.score_name] = self.predict(X)
        return result_df

    def recall_auc(self, X: pd.DataFrame, y: pd.DataFrame) -> float:
        """
        Calculate the area under the recall curve for top-k predictions.
        Quality metric for both, classification and regression tasks.

        Takes a fitted model (classifier or regressor) and calculates how well it ranks
        positive instances by computing recall at different depths k. The final score is
        the area under this recall curve, sampled at SAMPLE_COUNT evenly spaced points up to
        a quater of the dataset.

        Args:
            X: The input features to generate predictions for.
            y: Prediction targets.

        Returns:
            A score between 0 and 1, where 1 is perfect.
        """
        y = y.reset_index(drop=True)
        predictions = pd.Series(self.predict(X))
        ranked_data = pd.DataFrame({"target": y, "prediction": predictions}).sort_values(by="prediction", ascending=False)
        total_positives = y.sum()
        max_k = len(X) // 4  # look at the first quater of predictions
        k_values = np.linspace(0, max_k, num=SAMPLE_COUNT, dtype=np.int32, endpoint=True)
        recalls = [ranked_data.head(k)["target"].sum() / total_positives for k in k_values]
        area = np.trapezoid(recalls) / SAMPLE_COUNT
        return area

    @property
    @abstractmethod
    def features(self) -> list[str]:
        """
        List of feature names required by the model.

        Returns:
            list[str]: Names of all features needed for prediction.
        """

    @abstractmethod
    def training_target(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create target variable from input data.

        Args:
            df: Input data containing target information

        Returns:
            pd.DataFrame: Target values appropriate for the model type
        """

    @abstractmethod
    def split_train_test(self, X: pd.DataFrame, y: pd.DataFrame) -> list:
        """
        Split data into training and test sets.

        Args:
            X: Feature matrix
            y: Target values

        Returns:
            list: (X_train, X_test, y_train, y_test) split datasets
        """

    @abstractmethod
    def train(self, df: pd.DataFrame) -> None:
        """
        Train the model using the provided data.

        Args:
            df (pd.DataFrame): Training data containing the required features
                and target variable
        """

    @abstractmethod
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Generate predictions for the input features.

        Args:
            X: Feature matrix containing all the required and processed features

        Returns:
            np.ndarray: Array of predictions with shape (n_samples,)
        """


class Classifier(MLModel):
    """
    MLModel implementation for classification models that output probabilities.

    Handles models that implement predict_proba(), returning the probability of the positive class.
    """

    def training_target(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create binary classification target from interaction data.

        Args:
            df: Input data containing 'interactions_on_eval_day' column

        Returns:
            pd.DataFrame: Binary target where True indicates at least one interaction
        """
        return df["interactions_on_eval_day"] > 0

    def split_train_test(self, X: pd.DataFrame, y: pd.DataFrame) -> list:
        """
        Split data into training and test sets while preserving class distribution.

        Args:
            X: Feature matrix
            y: Binary target values

        Returns:
            list: (X_train, X_test, y_train, y_test) split datasets
        """
        return train_test_split(X, y, test_size=0.2, stratify=y)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Generate probability predictions for the positive class.

        Args:
            X: Feature matrix containing all the required and processed features

        Returns:
            np.ndarray: Array of probabilities for the positive class
                with shape (n_samples,), values in range [0,1]
        """
        return self.model.predict_proba(X)[:, 1]


class Regressor(MLModel):
    """
    MLModel implementation for regression models that output continuous values.

    Handles models that implement predict() for direct value prediction.
    """

    def training_target(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create regression target from interaction data.

        Args:
            df: Input data containing 'interactions_on_eval_day' column

        Returns:
            pd.DataFrame: Number of interactions for each instance
        """
        return df["interactions_on_eval_day"]

    def split_train_test(self, X: pd.DataFrame, y: pd.DataFrame) -> list:
        """
        Split data into training and test sets.

        Args:
            X: Feature matrix
            y: Continuous target values

        Returns:
            list: (X_train, X_test, y_train, y_test) split datasets
        """
        return train_test_split(X, y, test_size=0.2)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Generate numeric predictions.

        Args:
            X: Feature matrix containing all the required and processed features

        Returns:
            np.ndarray: Array of predicted values with shape (n_samples,)
        """
        return self.model.predict(X)
