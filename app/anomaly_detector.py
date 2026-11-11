import numpy as np
import logging
from sklearn.ensemble import IsolationForest
import threading
import time
from typing import Dict, Any, List

logger = logging.getLogger("appsec.anomaly_detector")

class AnomalyDetector:
    def __init__(self, anomaly_threshold: float = 0.85):
        self.anomaly_threshold = anomaly_threshold
        # Features used: [path_len, num_query_params, payload_size, req_rate_per_min]
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        self.lock = threading.Lock()

        # In-memory history of feature vectors for online learning
        self.history: List[List[float]] = []
        self.history_limit = 5000

        # Generate and fit standard baseline data immediately so we are ready at startup
        self._seed_baseline_and_train()

    def _seed_baseline_and_train(self):
        """
        Seeds the model with 100 synthetic normal request payloads
        to prevent cold-start classification errors.
        """
        try:
            logger.info("Initializing IsolationForest with pre-seeded normal request baseline...")
            np.random.seed(42)

            # Normal requests attributes:
            # - Path length: 10 to 40 chars
            # - Num query params: 0 to 2
            # - Payload size: 0 to 250 bytes
            # - Request rate per min: 5 to 30 requests
            path_lens = np.random.normal(25, 5, 150)
            query_counts = np.random.poisson(0.5, 150)
            payload_sizes = np.random.exponential(80, 150)
            req_rates = np.random.normal(15, 5, 150)

            baseline_features = np.column_stack((
                np.clip(path_lens, 5, 100),
                np.clip(query_counts, 0, 5),
                np.clip(payload_sizes, 0, 1000),
                np.clip(req_rates, 1, 50)
            ))

            with self.lock:
                self.model.fit(baseline_features)
                self.is_trained = True
                # Store seed data in history
                self.history = baseline_features.tolist()

            logger.info("IsolationForest successfully pre-trained with 150 baseline request vectors.")
        except Exception as e:
            logger.error(f"Failed to pre-train IsolationForest: {e}. Falling back to heuristics.")

    def record_and_evaluate(self, ip: str, path: str, query_params_count: int, payload_size: int, req_rate_per_min: int) -> Dict[str, Any]:
        """
        Records an incoming request's features, predicts whether it's an anomaly,
        and periodically schedules a retrain in the background.
        """
        feature_vector = [
            float(len(path)),
            float(query_params_count),
            float(payload_size),
            float(req_rate_per_min)
        ]

        # Append to history with bounds check
        with self.lock:
            self.history.append(feature_vector)
            if len(self.history) > self.history_limit:
                self.history = self.history[-self.history_limit:]

        # Run ML inference
        is_anomaly = False
        score = 0.5
        reason = ""

        # Dynamic Heuristic Backup Rules
        heuristic_triggered = False
        heuristic_reasons = []

        if payload_size > 150000:  # > 150 KB is abnormal for general API endpoints
            heuristic_triggered = True
            heuristic_reasons.append("Payload size exceeds high heuristic threshold (150KB)")
        if req_rate_per_min > 120:  # > 120 requests/min is excessive
            heuristic_triggered = True
            heuristic_reasons.append("Request rate per minute exceeds burst threshold (120 req/min)")
        if query_params_count > 15:  # massive query parameter fuzzing
            heuristic_triggered = True
            heuristic_reasons.append("Query parameter count is abnormally high (>15)")

        if self.is_trained:
            try:
                X = np.array([feature_vector])
                # Isolation Forest decision_function outputs: lower values mean more anomalous.
                # Standard decision score ranges from roughly -0.5 to 0.5, where < 0 is anomalous.
                # Let's map it: score = 1.0 - (decision_score + 0.5) to make higher scores represent threat level.
                decision_score = float(self.model.decision_function(X)[0])

                # Convert to anomaly score between 0.0 and 1.0
                # Normal is usually > 0 in decision_function, meaning score is low
                score = round(max(0.0, min(1.0, 0.5 - decision_score)), 3)

                # If score is high, flag as anomaly
                if score >= self.anomaly_threshold:
                    is_anomaly = True
                    reason = f"ML IsolationForest detected behavior anomaly (score: {score})"
            except Exception as e:
                logger.error(f"ML IsolationForest inference failed: {e}. Relying on heuristic fallbacks.")
                if heuristic_triggered:
                    is_anomaly = True
                    score = 0.90
                    reason = " + ".join(heuristic_reasons)
        else:
            # Fallback when model is not trained
            if heuristic_triggered:
                is_anomaly = True
                score = 0.88
                reason = "Heuristic rule: " + " + ".join(heuristic_reasons)

        # If heuristic is triggered, elevate score & anomaly status even if ML missed it (Hybrid approach)
        if heuristic_triggered and not is_anomaly:
            is_anomaly = True
            score = max(score, 0.88)
            reason = f"Heuristic safety override: " + " + ".join(heuristic_reasons)

        return {
            "is_anomaly": is_anomaly,
            "score": score,
            "reason": reason,
            "heuristic_triggered": heuristic_triggered
        }

    def trigger_retraining(self):
        """
        Retrains the IsolationForest model in a separate thread using collected history.
        """
        def _train_task():
            with self.lock:
                if len(self.history) < 50:
                    return
                data = np.array(self.history)

            try:
                new_model = IsolationForest(contamination=0.05, random_state=42)
                new_model.fit(data)
                with self.lock:
                    self.model = new_model
                    self.is_trained = True
                logger.info(f"AnomalyDetector model successfully retrained on {len(data)} sample vectors.")
            except Exception as e:
                logger.error(f"Error during background model retraining: {e}")

        threading.Thread(target=_train_task, daemon=True).start()
