from abc import abstractmethod

import pandas as pd
from greedybear.cronjobs.scoring.consts import MULTI_VAL_FEATURES, NUM_FEATURES
from greedybear.cronjobs.scoring.ml_model import Classifier, MLModel, Regressor
from greedybear.cronjobs.scoring.utils import multi_label_encode
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor


class RFModel(MLModel):
    """
    Abstract base class for Random Forest models.

    Provides common functionality for Random Forest Classifiers and Regressors,
    including feature preprocessing, model training, and evaluation.
    """

    @property
    def features(self) -> list[str]:
        """
        List of feature names required by the RandomFores models.

        Returns:
            list[str]: Names of all features needed for prediction,
                including both standard and multi-value features
        """
        return NUM_FEATURES + MULTI_VAL_FEATURES

    def train(self, df: pd.DataFrame) -> None:
        """
        Preprocesses features, splits data into train/test sets, and
        trains a Random Forest with optimized hyperparameters.
        Logs model performance using recall AUC score.

        Args:
            df: Training data containing features and
                'interactions_on_eval_day' target
        """
        self.log.info(f"start training {self.name}")

        X = df[self.features].copy()
        y = self.training_target(df).copy()

        for feature in MULTI_VAL_FEATURES:
            X = multi_label_encode(X, feature)

        X_train, X_test, y_train, y_test = self.split_train_test(X, y)

        self.model = self.untrained_model.fit(X_train, y_train)
        self.log.info(f"finished training {self.name} - recall AUC: {self.recall_auc(X_test, y_test):.4f}")
        self.save()

    @property
    @abstractmethod
    def untrained_model(self) -> BaseEstimator:
        """
        Create and configure an untrained Random Forest model.

        Returns:
            BaseEstimator: Configured but untrained scikit-learn Random Forest
                model with all hyperparameters set
        """


class RFClassifier(RFModel, Classifier):
    """
    Random Forest Classifier implementation for predicting IoC recurrence.

    Uses a Random Forest model with optimized hyperparameters.
    Predicts the probability of future interactions based on historical data.
    """

    def __init__(self):
        super().__init__("Random Forest Classifier", "recurrence_probability")

    @property
    def untrained_model(self) -> BaseEstimator:
        """
        Create and configure an untrained Random Forest Classifier.
        Hyperparameters were found by RandomSearchCV.

        Returns:
            BaseEstimator: Configured but untrained scikit-learn Random Forest
                Classifier with all hyperparameters set
        """
        params = {
            "class_weight": {False: 1, True: 4},
            "criterion": "entropy",
            "max_depth": 10,
            "max_features": "log2",
            "min_samples_leaf": 6,
            "min_samples_split": 3,
            "n_estimators": 241,
        }
        return RandomForestClassifier(**params)


class RFRegressor(RFModel, Regressor):
    """
    Random Forest Regressor implementation for predicting IoC interactions.

    Uses a Random Forest model with optimized hyperparameters.
    Predicts the number of interactions on the next day based on historical data.
    """

    def __init__(self):
        super().__init__("Random Forest Regressor", "expected_interactions")

    @property
    def untrained_model(self) -> BaseEstimator:
        """
        Create and configure an untrained Random Forest Regressor.
        Hyperparameters were found by RandomSearchCV.

        Returns:
            BaseEstimator: Configured but untrained scikit-learn Random Forest
                Regressor with all hyperparameters set
        """
        params = {
            "criterion": "squared_error",
            "max_depth": 11,
            "max_features": "sqrt",
            "min_samples_leaf": 3,
            "min_samples_split": 8,
            "n_estimators": 70,
        }
        return RandomForestRegressor(**params)
