import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from tensorflow.keras.models import Sequential # type: ignore
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, Input # type: ignore
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau # type: ignore
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.utils.class_weight import compute_class_weight
# AI INTRUSION DETECTION SYSTEM
# IMPROVED DEEP LEARNING MODEL
print("=" * 70)
print("AI Intrusion Detection System - Deep Learning")
print("=" * 70)
# DATASET PATHS
TRAIN_PATH = "dataset/KDDTrain+.txt"
TEST_PATH = "dataset/KDDTest+.txt"
MODEL_PATH = "models/dl_model.keras"
PREPROCESSOR_PATH = "models/dl_preprocessor.pkl"
CHART_FOLDER = "static/charts"
os.makedirs("models", exist_ok=True)
os.makedirs(CHART_FOLDER, exist_ok=True)
# DATASET COLUMNS
columns = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty"
]
# CHECK DATASET FILES
if not os.path.exists(TRAIN_PATH):
    raise FileNotFoundError(
        f"Training dataset not found: {TRAIN_PATH}"
    )
if not os.path.exists(TEST_PATH):
    raise FileNotFoundError(
        f"Testing dataset not found: {TEST_PATH}"
    )
# LOAD TRAINING DATA
print("\nLoading training dataset...")
train_data = pd.read_csv(
    TRAIN_PATH,
    names=columns
)
print("Training Shape :", train_data.shape)
# LOAD TESTING DATA
print("\nLoading testing dataset...")
test_data = pd.read_csv(
    TEST_PATH,
    names=columns
)
print("Testing Shape  :", test_data.shape)
#CLEAN LABEL VALUES
# Remove extra spaces if present
train_data["label"] = (
    train_data["label"]
    .astype(str)
    .str.strip()
    .str.lower()
)
test_data["label"] = (
    test_data["label"]
    .astype(str)
    .str.strip()
    .str.lower()
)
# CONVERT LABEL TO BINARY
# NORMAL = 0
# ATTACK = 1
train_data["label"] = train_data["label"].apply(
    lambda x: 0 if x == "normal" else 1
)
test_data["label"] = test_data["label"].apply(
    lambda x: 0 if x == "normal" else 1
)
# REMOVE DIFFICULTY COLUMN
train_data.drop(
    "difficulty",
    axis=1,
    inplace=True
)
test_data.drop(
    "difficulty",
    axis=1,
    inplace=True
)
# SPLIT FEATURES AND LABEL
X_train = train_data.drop(
    "label",
    axis=1
)
y_train = train_data["label"]
X_test = test_data.drop(
    "label",
    axis=1
)
y_test = test_data["label"]
print("\nNormal/Attack distribution:")
print(
    "Training Normal :",
    (y_train == 0).sum()
)
print(
    "Training Attack :",
    (y_train == 1).sum()
)
print(
    "Testing Normal  :",
    (y_test == 0).sum()
)
print(
    "Testing Attack  :",
    (y_test == 1).sum()
)
# CATEGORICAL COLUMNS
categorical_features = [
    "protocol_type",
    "service",
    "flag"
]
# NUMERICAL COLUMNS
numerical_features = [
    column
    for column in X_train.columns
    if column not in categorical_features
]
# PREPROCESSING
# Categorical:
# OneHotEncoder
# Numerical:
# StandardScaler
print("\nPreparing preprocessing...")
preprocessor = ColumnTransformer(
    transformers=[
        (
            "numeric",
            StandardScaler(),
            numerical_features
        ),
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore",
                sparse_output=False
            ),
            categorical_features
        )
    ]
)
# TRANSFORM TRAINING DATA
print("Encoding and scaling training data...")
X_train_processed = preprocessor.fit_transform(
    X_train
)
# TRANSFORM TEST DATA
print("Encoding and scaling testing data...")
X_test_processed = preprocessor.transform(
    X_test
)
# CONVERT TO NUMPY FLOAT32
X_train_processed = np.asarray(
    X_train_processed,
    dtype=np.float32
)
X_test_processed = np.asarray(
    X_test_processed,
    dtype=np.float32
)
y_train = np.asarray(
    y_train,
    dtype=np.float32
)
y_test = np.asarray(
    y_test,
    dtype=np.float32
)
print(
    "\nFinal training features :",
    X_train_processed.shape
)
print(
    "Final testing features  :",
    X_test_processed.shape
)
# SAVE PREPROCESSOR
joblib.dump(
    preprocessor,
    PREPROCESSOR_PATH
)
print("\nPreprocessor saved successfully!")
# CALCULATE CLASS WEIGHTS
print("\nCalculating class weights...")
classes = np.unique(y_train)
class_weights_array = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=y_train
)
class_weights = {
    int(classes[i]): float(class_weights_array[i])
    for i in range(len(classes))
}
print(
    "Class Weights :",
    class_weights
)
# BUILD DEEP LEARNING MODEL
print("\nBuilding Deep Learning Model...")
input_features = X_train_processed.shape[1]
model = Sequential([
    Input(
        shape=(input_features,)
    ),
    Dense(
        128,
        activation="relu"
    ),
    BatchNormalization(),
    Dropout(0.30),
    Dense(
        64,
        activation="relu"
    ),
    BatchNormalization(),
    Dropout(0.25),
    Dense(
        32,
        activation="relu"
    ),
    Dropout(0.20),
    Dense(
        16,
        activation="relu"
    ),
    Dense(
        1,
        activation="sigmoid"
    )
])
# COMPILE MODEL
model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=["accuracy"]
)
print("\nModel Summary:")
model.summary()
# EARLY STOPPING
early_stopping = EarlyStopping(
    monitor="val_loss",
    patience=7,
    restore_best_weights=True,
    verbose=1
)
# REDUCE LEARNING RATE
reduce_learning_rate = ReduceLROnPlateau(
    monitor="val_loss",
    factor=0.5,
    patience=3,
    min_lr=0.00001,
    verbose=1
)
# TRAIN MODEL
print("\n" + "=" * 70)
print("Training Deep Learning Model...")
print("=" * 70)
history = model.fit(
    X_train_processed,
    y_train,
    validation_split=0.20,
    epochs=30,
    batch_size=128,
    class_weight=class_weights,
    callbacks=[
        early_stopping,
        reduce_learning_rate
    ],
    verbose=1
)
print("\nTraining completed successfully!")
# MODEL EVALUATION
print("\n" + "=" * 70)
print("Evaluating Deep Learning Model...")
print("=" * 70)
test_loss, test_accuracy = model.evaluate(
    X_test_processed,
    y_test,
    verbose=0
)
# PREDICTIONS
y_probability = model.predict(
    X_test_processed,
    verbose=0
).ravel()
y_prediction = (
    y_probability >= 0.5
).astype(int)
# CALCULATE PERFORMANCE METRICS
accuracy = accuracy_score(
    y_test,
    y_prediction
)
precision = precision_score(
    y_test,
    y_prediction,
    zero_division=0
)
recall = recall_score(
    y_test,
    y_prediction,
    zero_division=0
)
f1 = f1_score(
    y_test,
    y_prediction,
    zero_division=0
)
# DISPLAY RESULTS
print("\n" + "=" * 70)
print(
    f"DEEP LEARNING ACCURACY  : {accuracy * 100:.2f} %"
)
print(
    f"PRECISION               : {precision * 100:.2f} %"
)
print(
    f"RECALL                  : {recall * 100:.2f} %"
)
print(
    f"F1 SCORE                : {f1 * 100:.2f} %"
)
print(
    f"TEST LOSS               : {test_loss:.4f}"
)
print("=" * 70)
# CLASSIFICATION REPORT
print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_prediction,
        target_names=[
            "Normal",
            "Attack"
        ],
        zero_division=0
    )
)
# CONFUSION MATRIX
cm = confusion_matrix(
    y_test,
    y_prediction
)
print("\nConfusion Matrix:")
print(cm)
# CONFUSION MATRIX CHART
plt.figure(
    figsize=(8, 6)
)
plt.imshow(
    cm,
    interpolation="nearest",
    cmap=plt.cm.Blues
)
plt.title(
    "Deep Learning Confusion Matrix"
)
plt.colorbar()
plt.xticks(
    [0, 1],
    ["Normal", "Attack"]
)
plt.yticks(
    [0, 1],
    ["Normal", "Attack"]
)
plt.xlabel(
    "Predicted Label"
)
plt.ylabel(
    "Actual Label"
)
for i in range(2):
    for j in range(2):
        plt.text(
            j,
            i,
            cm[i, j],
            horizontalalignment="center",
            color="white"
            if cm[i, j] > cm.max() / 2
            else "black",
            fontsize=14
        )
plt.tight_layout()
confusion_chart = os.path.join(
    CHART_FOLDER,
    "deep_learning_confusion_matrix.png"
)
plt.savefig(
    confusion_chart,
    dpi=150,
    bbox_inches="tight"
)
plt.close()
# ACCURACY GRAPH
plt.figure(
    figsize=(10, 6)
)
plt.plot(
    history.history["accuracy"],
    label="Training Accuracy"
)
plt.plot(
    history.history["val_accuracy"],
    label="Validation Accuracy"
)
plt.title(
    "Deep Learning Model Accuracy"
)
plt.xlabel(
    "Epoch"
)
plt.ylabel(
    "Accuracy"
)
plt.legend()
plt.grid(True)
accuracy_chart = os.path.join(
    CHART_FOLDER,
    "deep_learning_accuracy.png"
)
plt.savefig(
    accuracy_chart,
    dpi=150,
    bbox_inches="tight"
)
plt.close()
# LOSS GRAPH
plt.figure(
    figsize=(10, 6)
)
plt.plot(
    history.history["loss"],
    label="Training Loss"
)
plt.plot(
    history.history["val_loss"],
    label="Validation Loss"
)
plt.title(
    "Deep Learning Model Loss"
)
plt.xlabel(
    "Epoch"
)
plt.ylabel(
    "Loss"
)
plt.legend()
plt.grid(True)
loss_chart = os.path.join(
    CHART_FOLDER,
    "deep_learning_loss.png"
)
plt.savefig(
    loss_chart,
    dpi=150,
    bbox_inches="tight"
)
plt.close()
#SAVE MODEL
model.save(
    MODEL_PATH
)
print("\nDeep Learning Model saved successfully!")
print(
    "Model Path :",
    MODEL_PATH
)
print(
    "Preprocessor Path :",
    PREPROCESSOR_PATH
)
#CHART INFORMATION
print("\nCharts generated:")
print(
    accuracy_chart
)
print(
    loss_chart
)
print(
    confusion_chart
)
# FINAL MESSAGE
print("\n" + "=" * 70)
print("AI INTRUSION DETECTION SYSTEM READY")
print("=" * 70)