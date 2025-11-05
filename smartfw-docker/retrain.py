import pandas as pd, sqlite3, joblib, os, signal
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score
from pathlib import Path


MODEL_DIR = Path("/models")
CSV_LOG = Path("/var/log/smartfw/features.csv")
LABEL_DB = Path("/var/log/smartfw_labels.db")

def retrain():
    #Loading Features
    df = pd.read_csv(CSV_LOG, header=None, usecols=range(23))
    #Loading Labels
    labels = pd.read_sql("SELECT ip.label FROM labels", sqlite3.connect(LABEL_DB))
    #Inner join on IP
    df['ip'] = df.iloc[:, 22]
    df= df.merge(labels, on='ip', how="inner")
    if df.empty:
        return
    X, y = df.iloc[:, 23], df['label']
    #Train the model
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    clf = RandomForestClassifier(n_estimators=300, class_weight='balanced', random_state=42)
    clf.fit(Xs, y)
    #Persistant training
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(scaler, MODEL_DIR / "scaler.joblib")
    joblib.dump(clf, MODEL_DIR / "clf.joblib")
    print(f"Retrained: {len(y)} samples, precision {precision_score(y, clf.predict(Xs)):.2f}")