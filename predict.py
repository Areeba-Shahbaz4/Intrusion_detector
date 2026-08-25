# ZERO TRUST AI INTRUSION DETECTION SYSTEM
# FINAL PREDICTION ENGINE
# Machine Learning + Deep Learning
import joblib
import numpy as np
import pandas as pd
# LOAD MACHINE LEARNING MODEL
ml_model = joblib.load(
    "models/ids_model.pkl"
)
# LOAD ML ENCODERS
protocol_encoder = joblib.load(
    "models/protocol_encoder.pkl"
)
service_encoder = joblib.load(
    "models/service_encoder.pkl"
)
flag_encoder = joblib.load(
    "models/flag_encoder.pkl"
)
# LOAD DEEP LEARNING MODEL
dl_model = None
dl_preprocessor = None
try:
    from tensorflow.keras.models import load_model # type: ignore
    dl_model = load_model(
        "models/dl_model.keras"
    )
    dl_preprocessor = joblib.load(
        "models/dl_preprocessor.pkl"
    )
    print(
        "Deep Learning Model Loaded Successfully!"
    )
except Exception as e:
    print(
        "Deep Learning Model could not be loaded:",
        e
    )
# NSL-KDD DATASET COLUMNS
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
# PREDICTION FUNCTION
def predict_csv(file_path):
    # LOAD UPLOADED DATASET
    data = pd.read_csv(
        file_path,
        names=columns
    )
    # REMOVE UNUSED COLUMNS
    if "difficulty" in data.columns:
        data.drop(
            "difficulty",
            axis=1,
            inplace=True
        )
    if "label" in data.columns:
        data.drop(
            "label",
            axis=1,
            inplace=True
        )
    # Empty dataset protection
    if data.empty:
        raise ValueError(
            "The uploaded file contains no records."
        )
    # MACHINE LEARNING PREDICTION
    ml_data = data.copy()
    # Encode categorical features
    ml_data["protocol_type"] = (
        protocol_encoder.transform(
            ml_data["protocol_type"]
        )
    )
    ml_data["service"] = (
        service_encoder.transform(
            ml_data["service"]
        )
    )
    ml_data["flag"] = (
        flag_encoder.transform(
            ml_data["flag"]
        )
    )
    # ML Prediction
    ml_predictions = ml_model.predict(
        ml_data
    )
    total_records = len(
        ml_predictions
    )
    ml_attack = int(
        np.sum(
            ml_predictions == 1
        )
    )
    ml_normal = int(
        np.sum(
            ml_predictions == 0
        )
    )
    ml_attack_percentage = round(
        (
            ml_attack /
            total_records
        ) * 100,
        2
    )
    # ML Confidence
    if hasattr(
        ml_model,
        "predict_proba"
    ):
        ml_probabilities = (
            ml_model.predict_proba(
                ml_data
            )
        )
        ml_confidence = round(
            float(
                np.max(
                    ml_probabilities,
                    axis=1
                ).mean()
            ) * 100,
            2
        )
    else:
        ml_confidence = 0
    # DEEP LEARNING PREDICTION
    dl_attack = 0
    dl_normal = 0
    dl_attack_percentage = 0
    dl_confidence = 0
    dl_predictions = None
    if (
        dl_model is not None
        and
        dl_preprocessor is not None
    ):
        try:
            # Use original categorical data
            # because the DL preprocessor
            # performs its own encoding.
            dl_data = data.copy()
            # Apply saved preprocessing pipeline
            dl_processed = (
                dl_preprocessor.transform(
                    dl_data
                )
            )
            dl_processed = np.asarray(
                dl_processed,
                dtype=np.float32
            )
            # DL probability prediction
            dl_probabilities = (
                dl_model.predict(
                    dl_processed,
                    verbose=0
                ).ravel()
            )
            # Convert probabilities to classes
            dl_predictions = (
                dl_probabilities >= 0.5
            ).astype(int)
            dl_attack = int(
                np.sum(
                    dl_predictions == 1
                )
            )
            dl_normal = int(
                np.sum(
                    dl_predictions == 0
                )
            )
            dl_attack_percentage = round(
                (
                    dl_attack /
                    total_records
                ) * 100,
                2
            )
            # DL Confidence
            dl_confidence = round(
                float(
                    np.maximum(
                        dl_probabilities,
                        1 - dl_probabilities
                    ).mean()
                ) * 100,
                2
            )
        except Exception as e:
            print(
                "Deep Learning Prediction Error:",
                e
            )
    # MODEL AGREEMENT
    if dl_predictions is not None:
        agreement_count = int(
            np.sum(
                ml_predictions ==
                dl_predictions
            )
        )
        agreement_percentage = round(
            (
                agreement_count /
                total_records
            ) * 100,
            2
        )
    else:
        agreement_count = 0
        agreement_percentage = 0
    # FINAL COMBINED SECURITY ANALYSIS
    if dl_predictions is not None:
        # Attack if either AI model
        # identifies the record as an attack.
        combined_predictions = (
            (
                ml_predictions +
                dl_predictions
            ) >= 1
        ).astype(int)
        combined_attack = int(
            np.sum(
                combined_predictions == 1
            )
        )
        combined_normal = int(
            np.sum(
                combined_predictions == 0
            )
        )
    else:
        # Fallback to ML if DL
        # is unavailable.
        combined_attack = ml_attack
        combined_normal = ml_normal
    combined_attack_percentage = round(
        (
            combined_attack /
            total_records
        ) * 100,
        2
    )
    # SECURITY STATUS
    if combined_attack_percentage >= 70:
        security_status = "CRITICAL"
    elif combined_attack_percentage >= 40:
        security_status = "HIGH RISK"
    elif combined_attack_percentage >= 15:
        security_status = "MEDIUM RISK"
    else:
        security_status = "LOW RISK"
    # RETURN COMPLETE ANALYSIS
    return {
        # Overall Result
        "total_records":
            total_records,
        "normal":
            combined_normal,
        "attack":
            combined_attack,
        "attack_percentage":
            combined_attack_percentage,
        "security_status":
            security_status,
        # Machine Learning
        "ml_normal":
            ml_normal,
        "ml_attack":
            ml_attack,
        "ml_attack_percentage":
            ml_attack_percentage,
        "ml_confidence":
            ml_confidence,
        # Deep Learning
        "dl_normal":
            dl_normal,
        "dl_attack":
            dl_attack,
        "dl_attack_percentage":
            dl_attack_percentage,
        "dl_confidence":
            dl_confidence,
        # Model Agreement
        "model_agreement":
            agreement_count,
        "model_agreement_percentage":
            agreement_percentage
    }