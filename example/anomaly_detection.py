#!/usr/bin/python3

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import glob
from sklearn.preprocessing import MultiLabelBinarizer, OneHotEncoder, MinMaxScaler
from sklearn.metrics import confusion_matrix
import numpy as np
import matplotlib.pyplot as plt

class MultiCSVDatasetAnomaly(Dataset):
    def __init__(self, folder_path, multilabel_columns=None):
        if multilabel_columns is None:
            multilabel_columns = []

        csv_files = glob.glob(folder_path + "/*.csv")
        dataframes = [pd.read_csv(f) for f in csv_files]
        data = pd.concat(dataframes, ignore_index=True)
        data = data.fillna(0)

        if "malware_name" in data.columns:
        	labels = data["malware_name"].astype(str).apply(lambda s: 0 if s in ["", "0", "nan", "None"] else 1).astype(int).values
        	# remove metadata columns used as labels so they are not treated as features
        	data = data.drop(columns=["malware_name"])
        elif any(c in data.columns for c in ["anti_forensic", "anti_debugging", "anti_sandbox", "persistence"]):
        	flag_cols = [c for c in ["anti_forensic", "anti_debugging", "anti_sandbox", "persistence"] if c in data.columns]
        	labels = (data[flag_cols].astype(float).sum(axis=1) > 0).astype(int).values
        	data = data.drop(columns=flag_cols)
        else:
        	labels = None

        self.y = torch.tensor(labels, dtype=torch.long) if labels is not None else None

        # Scale numeric features
        numeric_cols = data.select_dtypes(include=np.number).columns
        if len(numeric_cols) > 0:
            scaler = MinMaxScaler()
            data[numeric_cols] = scaler.fit_transform(data[numeric_cols])

        # Encode all columns consistently
        X_list = []
        for col in data.columns:
            if col in multilabel_columns:
                labels_col = data[col].apply(lambda x: str(x).split(','))
                mlb = MultiLabelBinarizer()
                transformed = mlb.fit_transform(labels_col)
                new_cols = [f"{col}_{c}" for c in mlb.classes_]
                X_list.append(pd.DataFrame(transformed, columns=new_cols))

            elif np.issubdtype(data[col].dtype, np.number):
                X_list.append(data[[col]])

            else:
                values = data[col].astype(str)
                ohe = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
                transformed = ohe.fit_transform(values.values.reshape(-1, 1))
                new_cols = [f"{col}_{c}" for c in ohe.categories_[0]]
                X_list.append(pd.DataFrame(transformed, columns=new_cols))

        self.X = torch.tensor(pd.concat(X_list, axis=1).values, dtype=torch.float32)
        if not hasattr(self, "y"):
        	self.y = None

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx]

class MalwareAutoencoder(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Linear(128, 32),
            nn.ReLU(),
            nn.Linear(32, 8),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 32),
            nn.ReLU(),
            nn.Linear(32, 128),
            nn.ReLU(),
            nn.Linear(128, input_size),
            nn.ReLU()
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)

dataset = MultiCSVDatasetAnomaly(
    folder_path="test_data",
    multilabel_columns=["tags", "anti_forensic", "anti_debugging", "anti_sandbox", "persistence"]
)

print(f"Loaded dataset with {dataset.X.shape[0]} samples and {dataset.X.shape[1]} features")

loader = DataLoader(dataset, batch_size=64, shuffle=True)

input_size = dataset.X.shape[1]
model = MalwareAutoencoder(input_size)

criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=1e-3)

epochs = 20
for epoch in range(epochs):
    model.train()
    epoch_loss = 0

    for batch in loader:
        optimizer.zero_grad()
        output = model(batch)
        loss = criterion(output, batch)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()

    print(f"Epoch {epoch+1}/{epochs} | Loss: {epoch_loss/len(loader):.6f}")

model.eval()
with torch.no_grad():
    reconstructed = model(dataset.X)
    errors = torch.mean((reconstructed - dataset.X)**2, dim=1)

threshold = errors.mean() + 2 * errors.std()
print(f"Anomaly threshold: {float(threshold)}")

anomaly_mask = errors > threshold
anomaly_indices = np.where(anomaly_mask.numpy())[0]

# Compute FNR/FPR
y_pred = (errors > threshold).cpu().numpy().astype(int)

tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0,1]).ravel()

fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
print(f"False Positive Rate: {fpr}")
print(f"False Negative Rate: {fnr}")

# Results
print("ANOMALY DETECTION RESULTS")
print(f"Total anomalies: {len(anomaly_indices)}")
print(f"Anomaly indices: {anomaly_indices}")

plt.figure(figsize=(10, 5))
plt.plot(errors.numpy(), label='Reconstruction Error', alpha=0.8)
plt.scatter(anomaly_indices,
            errors[anomaly_indices].numpy(),
            color='red',
            s=40,
            label='Anomaly')
plt.axhline(threshold, color='orange', linestyle='--', label='Threshold')

plt.xlabel("Sample Index")
plt.ylabel("Error")
plt.legend()

ax = plt.gca()
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.savefig("anomaly_plot.svg", format="svg", bbox_inches="tight")

plt.show()




