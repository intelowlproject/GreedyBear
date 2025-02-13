import pandas as pd
from greedybear.cronjobs.scoring.consts import MULTI_VAL_FEATURES, NUM_FEATURES
from greedybear.cronjobs.scoring.ml_model import Classifier, Regressor
from greedybear.cronjobs.scoring.utils import multi_label_encode
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.model_selection import train_test_split


class RFClassifier(Classifier):
    """
    Random Forest Classifier implementation for predicting IoC recurrence.

    Uses a Random Forest model with optimized hyperparameters.
    Predicts the probability of future interactions based on historical data.
    """

    def __init__(self):
        super().__init__("Random Forest Classifier", "recurrence_probability")
        self.model = None
        self.features = NUM_FEATURES + MULTI_VAL_FEATURES

    def train(self, df: pd.DataFrame) -> None:
        """
        Preprocesses features, splits data into train/test sets, and
        trains a Random Forest with optimized hyperparameters.
        Logs model performance using recall AUC score.

        Args:
            df: Training data containing features and
                'interactions_on_eval_day' target

        Raises:
            ValueError: If required features or target are missing
        """
        self.log.info(f"start training {self.name}")

        if "interactions_on_eval_day" not in df.columns:
            raise ValueError("Missing target column 'interactions_on_eval_day'")

        X = df[self.features].copy()
        y = df["interactions_on_eval_day"] > 0

        for feature in MULTI_VAL_FEATURES:
            X = multi_label_encode(X, feature)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y)

        params = {
            "class_weight": {False: 1, True: 4},
            "criterion": "entropy",
            "max_depth": 10,
            "max_features": "log2",
            "min_samples_leaf": 6,
            "min_samples_split": 3,
            "n_estimators": 241,
        }
        self.model = RandomForestClassifier(
            **params,
        )
        self.model.fit(X_train, y_train)
        self.log.info(f"finished training {self.name} - recall AUC: {self.recall_auc(X_test, y_test):.4f}")


class RFRegressor(Regressor):
    """
    Random Forest Regressor implementation for predicting IoC interactions.

    Uses a Random Forest model with optimized hyperparameters.
    Predicts the number of interactions on the next day based on historical data.
    """

    def __init__(self):
        super().__init__("Random Forest Regressor", "expected_interactions")
        self.model = None
        self.features = NUM_FEATURES + MULTI_VAL_FEATURES

    def train(self, df: pd.DataFrame) -> None:
        """
        Preprocesses features, splits data into train/test sets, and
        trains a Random Forest with optimized hyperparameters.
        Logs model performance using recall AUC score.

        Args:
            df: Training data containing features and
                'interactions_on_eval_day' target

        Raises:
            ValueError: If required features or target are missing
        """
        self.log.info(f"start training {self.name}")

        if "interactions_on_eval_day" not in df.columns:
            raise ValueError("Missing target column 'interactions_on_eval_day'")

        X = df[self.features].copy()
        y = df["interactions_on_eval_day"]

        for feature in MULTI_VAL_FEATURES:
            X = multi_label_encode(X, feature)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

        params = {
            "criterion": "squared_error",
            "max_depth": 11,
            "max_features": "sqrt",
            "min_samples_leaf": 3,
            "min_samples_split": 8,
            "n_estimators": 70,
        }

        self.model = RandomForestRegressor(
            **params,
        )
        self.model.fit(X_train, y_train)
        self.log.info(f"finished training {self.name} - recall AUC: {self.recall_auc(X_test, y_test):.4f}")
