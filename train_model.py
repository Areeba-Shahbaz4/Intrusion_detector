# ==========================================
# AI Intrusion Detection System
# Model Training
# ==========================================
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
print("=" * 50)
print("AI Intrusion Detection System")
print("=" * 50)
# Dataset Files
TRAIN_FILE = "dataset/KDDTrain+.txt"
TEST_FILE = "dataset/KDDTest+.txt"
# Column Names
columns = [
"duration", "protocol_type", "service", "flag", "src_bytes",
"dst_bytes", "land", "wrong_fragment", "urgent", "hot",
"num_failed_logins", "logged_in", "num_compromised", "root_shell",
"su_attempted", "num_root", "num_file_creations", "num_shells",
"num_access_files", "num_outbound_cmds", "is_host_login",
"is_guest_login", "count", "srv_count", "serror_rate",
"srv_serror_rate", "rerror_rate", "srv_rerror_rate",
"same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
"dst_host_count", "dst_host_srv_count",
"dst_host_same_srv_rate", "dst_host_diff_srv_rate",
"dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
"dst_host_serror_rate", "dst_host_srv_serror_rate",
"dst_host_rerror_rate", "dst_host_srv_rerror_rate",
"label",
"difficulty"
]
# Load Dataset
train_data = pd.read_csv(TRAIN_FILE, names=columns)
test_data = pd.read_csv(TEST_FILE, names=columns)
print("Training Shape :", train_data.shape)
print("Testing Shape  :", test_data.shape)
# Remove Difficulty Column
train_data.drop("difficulty", axis=1, inplace=True)
test_data.drop("difficulty", axis=1, inplace=True)
# Convert Labels
train_data["label"] = train_data["label"].apply(
lambda x: 0 if x == "normal" else 1
)
test_data["label"] = test_data["label"].apply(
lambda x: 0 if x == "normal" else 1
)
# Label Encoders
protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()
train_data["protocol_type"] = protocol_encoder.fit_transform(
train_data["protocol_type"]
)
test_data["protocol_type"] = protocol_encoder.transform(
test_data["protocol_type"]
)
train_data["service"] = service_encoder.fit_transform(
train_data["service"]
)
test_data["service"] = service_encoder.transform(
test_data["service"]
)
train_data["flag"] = flag_encoder.fit_transform(
train_data["flag"]
)
test_data["flag"] = flag_encoder.transform(
test_data["flag"]
)
# Save Encoders
joblib.dump(protocol_encoder, "models/protocol_encoder.pkl")
joblib.dump(service_encoder, "models/service_encoder.pkl")
joblib.dump(flag_encoder, "models/flag_encoder.pkl")
print("Encoders Saved Successfully")
# Features & Labels
X_train = train_data.drop("label", axis=1)
y_train = train_data["label"]
X_test = test_data.drop("label", axis=1)
y_test = test_data["label"]
# Train AI Model
model = RandomForestClassifier(
n_estimators=200,
max_depth=20,
min_samples_split=5,
random_state=42,
n_jobs=-1
)
print("Training AI Model...")
model.fit(X_train, y_train)
print("Model Training Completed Successfully!")
# Prediction
predictions = model.predict(X_test)
print("Prediction Completed Successfully!")
# Accuracy
accuracy = accuracy_score(y_test, predictions)
print("=" * 50)
print("MODEL ACCURACY :", round(accuracy * 100, 2), "%")
print("=" * 50)
#Save Model
joblib.dump(model, "models/ids_model.pkl")
print("AI Model Saved Successfully!")
#Finished
print("=" * 50)
print("AI Intrusion Detection System Ready")
print("=" * 50)