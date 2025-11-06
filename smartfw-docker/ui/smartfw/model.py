from __future__ import annotations
import logging, os, time, threading, signal, pandas as pd, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump, load
from .config import MODEL_PATH, SCALER_PATH, LOG_PATH, RETRAIN_INTERVAL_SEC
from pathlib import Path


log = logging.getLogger(__name__)
MODEL_FILE = Path("/models/clf.joblib")
LAST_CHECK = 0

class AnomalyModel:
    def __init__(self) -> None:
        self.scaler: StandardScaler = StandardScaler()
        self.clf: IsolationForest | None = None
        self._lock = threading.Lock()
        self._last_retrain: float = 0.0


    def load_or_create(self) -> None:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            with self._lock:
                self.clf = load(MODEL_PATH)
                self.scaler = load(SCALER_PATH)
            log.info("Loaded exsisting model")
        else:
            self._bootstrap_dummy()
            self.save()

    def save(self) -> None:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with self._lock:
            dump(self.clf, MODEL_PATH)
            dump(self.scaler, SCALER_PATH)

    #Inference
    def score(self, X: np.ndarray) -> float:
        #return anomaly score, the higher the score the more normal
        with self._lock:
            if self.clf is None:
                return 0.0
            Xs = self.scaler.transform(X.reshape(1, -1))
            return float(self.clf.decision_function(Xs)[0])
        
    #Training
    def partial_fit(self, X: np.ndarray) -> None:
        with self._lock:
            self.scaler.partial_fit(X)
            Xs = self.scaler.transform(X)
            #No partial_fit in IsolationForest - refit from scratch
            self.clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
            self.clf.fit(Xs)

    def maybe_retrain(self) -> None:
        now = time.time()
        if now - self._last_retrain < RETRAIN_INTERVAL_SEC:
            return
        if not os.path.exists(LOG_PATH):
            return
        try:
            df = pd.read_csv(LOG_PATH, head=None, usecols=range(23))
            self.partial_fit(df.values)
            self.save()
            self._last_retrain = now
            log.info("Retrained model on %d rows", len(df))
        except Exception as e:
            log.exception("Retrain failed: %s", e)


    #Internals
    def _boostrap_dummy(self) -> None:
        dummy = np.random.rand(100, 23)
        self.scaler.fit(dummy)
        Xs = self.scaler.transform(dummy)
        self.clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
        self.clf.fit(Xs)

    
    #Hot Reload and Supervised Learning
    def __init__(self) -> None:
        self._last_retrain:float = 0.0
        threading.Thread(target=self._watch_models, daemon=True).start()

    def maybe_retrain(self) -> None:
        df = pd.read_csv(LOG_PATH, header=None, usecols=range(23))

    def predict_proba(self, X: np.ndarray) -> float:
        #Probability that flow is bad (0-1)
        with self._lock:
            if self.clf is None:
                return 0.0
            Xs = self.scaler.transform(X.reshape(1, -1))
            raw = self.clf.decision_function(Xs)[0]
            return float(1 / (1 + np.exp(raw + 0.5)))
        
    def _watch_models(self):
        global model, scaler, LAST_CHECK
        while True:
            time.sleep(30)
            if MODEL_FILE.exists() and MODEL_FILE.stat().st_mtime > LAST_CHECK:
                with self._lock:
                    self.load_or_create()
                LAST_CHECK = MODEL_FILE.stat().st_mtime
                print("Hot-loaded new supervised model")