import json
import logging
from collections import defaultdict

from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.scoring.random_forest import RFClassifier, RFRegressor
from greedybear.cronjobs.scoring.utils import correlated_features, get_current_data, get_features, update_iocs
from greedybear.settings import ML_MODEL_DIRECTORY

MODELS = [RFClassifier(), RFRegressor()]
TRAINING_DATA_FILENAME = "training_data.json"


class TrainingDataError(Exception):
    """Raised when there are issues with training data validity."""


class TrainModels(Cronjob):
    """
     Trains scoring models using historical IoC data.

    Manages training pipeline for scoring models by comparing current IoC data against
    previously stored training data. The class persists the current data after each run
    to serve as training data for the next iteration. Training requires historical data
    to calculate interaction deltas.
    """

    def __init__(self):
        super().__init__()
        self.storage = FileSystemStorage(location=ML_MODEL_DIRECTORY)
        self.current_data = None

    def save_training_data(self) -> None:
        """
        Save current IoC data to storage for future training runs.

        Saves the current dataset as JSON, overwriting any existing training data.
        Handles date serialization using default string conversion.
        """
        self.log.info("saving current data for future training")
        try:
            if self.storage.exists(TRAINING_DATA_FILENAME):
                self.storage.delete(TRAINING_DATA_FILENAME)
            self.storage.save(TRAINING_DATA_FILENAME, ContentFile(json.dumps(self.current_data, default=str)))
        except Exception as exc:
            self.log.error(f"error saving training data: {exc}")
            raise exc

    def load_training_data(self) -> list[dict]:
        """
        Load previously saved IoC data from storage.

        Returns:
            list: Previously stored IoC data, or empty dict if loading fails.
        """
        self.log.info("loading training data from file system")
        try:
            with self.storage.open(TRAINING_DATA_FILENAME, "r") as file:
                return json.load(file)
        except Exception as exc:
            self.log.error(f"error loading training data: {exc}")
            return {}

    def run(self):
        """
        Execute the model training pipeline.

        Workflow:
        1. Fetch current IoC data from database
        2. Load previous training data from storage
        3. Verify training data predates current data
        4. Calculate interaction count deltas between datasets
        5. Extract features and prepare training data
        6. Check for correlated features
        7. Train and save each model
        8. Store current data for next training iteration

        Raises:
            TrainingDataError: If training data is not older than current data.
        """
        self.log.info("fetching current IoC data from DB")
        self.current_data = get_current_data()
        current_date = max(row["last_seen"] for row in self.current_data)

        self.log.info(f"current IoC data is from {current_date}, contains {len(self.current_data)} IoCs")

        training_data = self.load_training_data()
        if not training_data:
            self.log.info("no training data found, skip training")
            self.save_training_data()
            return

        training_date = max(row["last_seen"] for row in training_data)
        training_ips = {ioc["value"]: ioc["interaction_count"] for ioc in training_data}
        self.log.info(f"training data is from {training_date}, contains {len(training_data)} IoCs")

        if not training_date < current_date:
            self.log.error("training data must be older than current data")
            raise TrainingDataError()

        current_ips = defaultdict(
            int, {ioc["value"]: ioc["interaction_count"] - training_ips.get(ioc["value"], 0) for ioc in self.current_data if ioc["last_seen"] > training_date}
        )

        self.log.info("extracting features from training data")
        training_df = get_features(training_data, training_date)
        training_df["interactions_on_eval_day"] = training_df["value"].map(current_ips)

        high_corr_pairs = correlated_features(training_df.select_dtypes(include="number"))
        if high_corr_pairs:
            self.log.debug("found highly correlated features")
        for f1, f2, corr in high_corr_pairs:
            self.log.debug(f"{f1} & {f2}: {corr:.2f}")

        for model in MODELS:
            model.train(training_df)
            model.save()

        self.save_training_data()


class UpdateScores(Cronjob):
    """
    Updates IoC scores by applying multiple scoring models.

    Retrieves current IoC data from the database, if they are not handed over by previous job,
    extracts relevant features, applies a series of scoring models,
    and writes the updated scores back to the database.
    Designed to run as a scheduled cronjob.
    """

    def __init__(self):
        super().__init__()
        self.data = None

    def run(self):
        """
        Execute the score update pipeline.

        The pipeline consists of these steps:
        1. Fetch IoC data if not handed over
        2. Determine the most recent date in the dataset
        3. Extract features from IoC data
        4. Apply each scoring model in sequence
        5. Write the updated scores back to the database

        The scoring models are expected to add
        their respective score columns to the dataframe.
        """
        if self.data is None:
            self.log.info("no data handed over from previous task")
            self.log.info("fetching current IoC data from DB")
            self.data = get_current_data()
        current_date = max(row["last_seen"] for row in self.data)
        self.log.info("extracting features")
        df = get_features(self.data, current_date)
        for model in MODELS:
            df = model.score(df)
        score_names = [m.score_name for m in MODELS]
        self.log.info("writing updated scores to DB")
        result = update_iocs(df, score_names)
        self.log.info(f"{result} IoCs were updated")
