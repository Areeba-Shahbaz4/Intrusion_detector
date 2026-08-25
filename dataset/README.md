# Dataset

This folder contains the network traffic dataset used for training and evaluating the AI-based Intrusion Detection System.

## Dataset Used

The project uses the **NSL-KDD Dataset**, a benchmark dataset commonly used for research and experimentation in network intrusion detection.

The dataset contains network traffic records representing:

- Normal network activity
- Malicious network activity
- Different network traffic features used for intrusion detection

## Dataset Files

The dataset files used by the project include:

- `KDDTrain+.txt` — Training dataset used to train the Machine Learning model.
- `KDDTest+.txt` — Testing dataset used to evaluate the trained model.

## Preprocessing

Before training, the dataset is processed by the system to:

1. Load the network traffic records.
2. Remove the difficulty attribute.
3. Encode categorical features such as protocol type, service, and flag.
4. Convert the original attack labels into binary classes:
   - `0` → Normal
   - `1` → Attack
5. Prepare the processed data for Machine Learning.

g## Usage

The dataset is used by the training module to develop the Random Forest-based intrusion detection model.

The trained model is then used by the Flask application to analyze uploaded network traffic data.

## Note

The dataset is provided for educational, research, and cybersecurity experimentation purposes.

The dataset itself is not modified by the web application. Uploaded files are processed temporarily for intrusion detection.