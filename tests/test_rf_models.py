from unittest.mock import Mock

import numpy as np
import pandas as pd
from greedybear.cronjobs.scoring.ml_model import Classifier, Regressor
from greedybear.cronjobs.scoring.random_forest import RFModel

from . import CustomTestCase

FEATURES = ["feature1", "feature2", "feature3", "honeypots"]
CLASSIFIER_TARGET = [False, True, True, False, True]
REGRESSOR_TARGET = [0, 1, 2, 0, 3]
SAMPLE_DATA = pd.DataFrame(
    {
        "interactions_on_eval_day": REGRESSOR_TARGET,
        "feature1": [1, 2, 3, 4, 5],
        "feature2": [0.1, 0.2, 0.3, 0.4, 0.5],
        "feature3": [122, 12, 0, 14, 87],
        "honeypots": ["A,B", "B,C", "A", "C", "A,B,C"],
    }
)


class TestClassifier(CustomTestCase):
    class MockRFModel(RFModel):
        @property
        def features(self) -> list[str]:
            return FEATURES

    class MockRFClassifier(MockRFModel, Classifier):
        def __init__(self):
            super().__init__("Mock Random Forest Classifier", "mock_score")

        @property
        def untrained_model(self):
            mock = Mock()
            mock.fit.return_value = mock
            a = np.zeros((5, 2))
            a[:, 1] = [0.9, 0.8, 0.3, 0.2, 0.1]
            mock.predict_proba.return_value = a
            return mock

    def test_rf_classifier(self):
        """Test mock Random Forest classifier"""
        classifier = self.MockRFClassifier()
        classifier.model = classifier.untrained_model
        self.assertEqual(classifier.file_name, "mock_random_forest_classifier")

        training_target = classifier.training_target(SAMPLE_DATA)
        self.assertEqual(len(training_target), len(CLASSIFIER_TARGET))
        for a, b in zip(training_target, CLASSIFIER_TARGET):
            self.assertEqual(a, b)

        df = classifier.score(SAMPLE_DATA)
        for a, b in zip(df["mock_score"], classifier.model.predict_proba.return_value[:, 1]):
            self.assertEqual(a, b)

        auc = classifier.recall_auc(df, training_target)
        self.assertEqual(0 <= auc <= 1, True)


class TestRegressor(CustomTestCase):
    class MockRFModel(RFModel):
        @property
        def features(self) -> list[str]:
            return FEATURES

    class MockRFRegressor(MockRFModel, Regressor):
        def __init__(self):
            super().__init__("Mock Random Forest Regressor", "mock_score")

        @property
        def untrained_model(self):
            mock = Mock()
            mock.fit.return_value = mock
            mock.predict.return_value = np.array([0, 3, 1, 4, 2])
            return mock

    def test_rf_regressor(self):
        """Test mock Random Forest regressor"""
        regressor = self.MockRFRegressor()
        regressor.model = regressor.untrained_model
        self.assertEqual(regressor.file_name, "mock_random_forest_regressor")

        training_target = regressor.training_target(SAMPLE_DATA)
        self.assertEqual(len(training_target), len(REGRESSOR_TARGET))
        for a, b in zip(training_target, REGRESSOR_TARGET):
            self.assertEqual(a, b)

        X_train, X_test, y_train, y_test = regressor.split_train_test(SAMPLE_DATA, training_target)
        self.assertEqual(len(X_train), 4)
        self.assertEqual(len(X_test), 1)
        self.assertEqual(len(X_train), len(y_train))
        self.assertEqual(len(X_test), len(y_test))

        df = regressor.score(SAMPLE_DATA)
        for a, b in zip(df["mock_score"], regressor.model.predict.return_value):
            self.assertEqual(a, b)

        auc = regressor.recall_auc(df, training_target)
        self.assertEqual(0 <= auc <= 1, True)
