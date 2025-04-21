import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib


# Load the dataset 
train_url = 'NSL_KDD_Train.csv'
test_url = 'NSL_KDD_Test.csv'

# Define column names
col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]

# After loading the datasets
df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test = pd.read_csv(test_url, header=None, names=col_names)

# Extract 1000 rows for future prediction
test_subset = df_test.sample(n=1000, random_state=41)
test_subset.to_csv('upload/test.csv', index=False)
print('1000 random rows saved for future prediction use!')

# Remove those 1000 rows from the test set to avoid data leakage
df_test = df_test.drop(test_subset.index)
print(f'Remaining test set size after extraction: {len(df_test)}')

#Label Mapping to 5 categories
attack_to_category = {
    'normal': 'normal',
    'neptune': 'dos', 'back': 'dos', 'land': 'dos', 'pod': 'dos', 'teardrop': 'dos', 
    'smurf': 'dos', 'apache2': 'dos', 'udpstorm': 'dos', 'mailbomb': 'dos', 
    'processtable': 'dos', 'worm': 'dos', 'httptunnel': 'dos', 'sendmail': 'dos', 'snmpgetattack': 'dos',
    
    'satan': 'probe', 'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 
    'mscan': 'probe', 'symantec_corp': 'probe', 'saint': 'probe', 'snmpguess': 'probe', 'tftp': 'probe',

    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'phf': 'r2l', 
    'warezclient': 'r2l', 'warezmaster': 'r2l', 'sendmail': 'r2l', 'named': 'r2l', 
    'snmpgetattack': 'r2l', 'snmpguess': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l', 'multihop': 'r2l',
    
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r', 
    'hpsh': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r',
    
    'other': 'unknown'
}

# Map labels to 5 categories
df_train['category'] = df_train['label'].map(attack_to_category)
df_test['category'] = df_test['label'].map(attack_to_category)

df_train = df_train.dropna(subset=['category'])
df_test = df_test.dropna(subset=['category'])

#Encoding Categorical Features
categorical_columns = ['protocol_type', 'service', 'flag']

# Use separate LabelEncoders for each categorical column
encoders = {}
for col in categorical_columns:
    le = LabelEncoder()
    df_train[col] = le.fit_transform(df_train[col])
    df_test[col] = le.transform(df_test[col])
    encoders[col] = le

# Feature Engineering- average connection duration per service
df_train['avg_connection_duration_per_service'] = df_train.groupby('service')['duration'].transform('mean')
df_test['avg_connection_duration_per_service'] = df_test.groupby('service')['duration'].transform('mean')

# Feature Scaling
numerical_columns = [col for col in df_train.columns if col not in categorical_columns + ['label', 'category']]

scaler = StandardScaler()
df_train[numerical_columns] = scaler.fit_transform(df_train[numerical_columns])
df_test[numerical_columns] = scaler.transform(df_test[numerical_columns])

# Prepare Feature Matrix (X) and Target Vector (y)
X_train = df_train.drop(columns=['label', 'category'])
y_train = df_train['category']

X_test = df_test.drop(columns=['label', 'category'])
y_test = df_test['category']

# Handle Class Imbalance using SMOTE
smote = SMOTE(random_state=42)

# Ensure y_train is string type for SMOTE
y_train = y_train.astype(str)

X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

print("Starting RandomForest training...")

# Simplified training 
rf_model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
rf_model.fit(X_train_smote, y_train_smote)

print("RandomForest training completed.")

# Use this model directly for prediction and saving
best_rf_model = rf_model

# Evaluate the Model
y_pred = best_rf_model.predict(X_test)

# Print evaluation metrics
print('Accuracy:', accuracy_score(y_test, y_pred))
print('Classification Report:')
print(classification_report(y_test, y_pred))

# Save the Model, Scaler, and LabelEncoders
joblib.dump(best_rf_model, 'models/rf_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(encoders, 'models/label_encoders.pkl')

print("Model, Scaler, and LabelEncoders saved!")

# Plot class distribution before SMOTE
plt.figure(figsize=(10,6))
df_train['category'].value_counts().plot(kind='bar')
plt.title("Class Distribution Before SMOTE")
plt.xlabel("Categories")
plt.ylabel("Count")
plt.show()

# Plot class distribution after SMOTE
plt.figure(figsize=(10,6))
y_train_smote.value_counts().plot(kind='bar')
plt.title("Class Distribution After SMOTE")
plt.xlabel("Categories")
plt.ylabel("Count")
plt.show()

# Final metrics - Precision, Recall, F1-Score
plt.figure(figsize=(10, 6))
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

precision = precision_score(y_test, y_pred, average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')

print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-Score: {f1}")