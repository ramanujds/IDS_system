import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

# Load and preprocess data
df = pd.read_csv('PCAP_OF_SERVER.csv')

# Drop rows with missing values
df.dropna(inplace=True)

# Encode categorical features
categorical_features = ['src', 'dst', 'Protocol']
df = pd.get_dummies(df, columns=categorical_features, drop_first=True)
print(f"This Dataframe has {df.shape[0]} rows and {df.shape[1]} columns after encoding")

# Display information and summary of the dataframe
print(f"This Dataset has {df.shape[0]} rows and {df.shape[1]} columns")
df.info()
df.describe()

# Separate input and output attributes
x = df.drop(['label'], axis=1)
y = df['label']

# Scale features
ms = MinMaxScaler()
x = ms.fit_transform(x)

# Split data
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.3)
print(f"Training set size: {X_train.shape}, Test set size: {X_test.shape}")

# Classifier accuracies
Classifier_accuracy = []
Classifier_names = []

# K-Nearest Neighbor Classifier
knn_clf = KNeighborsClassifier()
knn_clf.fit(X_train, y_train)
y_pred = knn_clf.predict(X_test)
accuracy = metrics.accuracy_score(y_test, y_pred)
Classifier_accuracy.append(accuracy * 100)
Classifier_names.append('KNN')
print("Accuracy of KNN Classifier : %.2f" % (accuracy * 100))

# Decision Tree Classifier
dt_clf = DecisionTreeClassifier(max_depth=5)
dt_clf.fit(X_train, y_train)
y_pred = dt_clf.predict(X_test)
accuracy = metrics.accuracy_score(y_test, y_pred)
Classifier_accuracy.append(accuracy * 100)
Classifier_names.append('Decision Tree')
print("Accuracy of Decision Tree Classifier : %.2f" % (accuracy * 100))

# Logistic Regression
lr_clf = LogisticRegression(max_iter=1000)
lr_clf.fit(X_train, y_train)
y_pred = lr_clf.predict(X_test)
accuracy = metrics.accuracy_score(y_test, y_pred)
Classifier_accuracy.append(accuracy * 100)
Classifier_names.append('Logistic Regression')
print("Accuracy of Logistic Regression Classifier : %.2f" % (accuracy * 100))

# Display classifier accuracies
df_clf = pd.DataFrame()
df_clf['name'] = Classifier_names
df_clf['Accuracy'] = Classifier_accuracy
df_clf = df_clf.sort_values(by=['Accuracy'], ascending=False)
print(df_clf.head(10))

# Plot attacker IP addresses involved in DDoS attacks
# Check if any 'src_' columns exist
src_columns = [col for col in df.columns if col.startswith('src_')]

if src_columns:
    # Filter for DDoS attacks
    ddos_df = df[df['label'] == 1]
    
    # Initialize a dictionary to hold IP address counts
    ip_counts = {col: ddos_df[col].sum() for col in src_columns}

    # Convert dictionary to DataFrame for easy viewing
    ip_counts_df = pd.DataFrame(list(ip_counts.items()), columns=['IP Address', 'Count'])
    
    # Sort and display the top 10 attacker IP addresses
    ip_counts_df = ip_counts_df.sort_values(by='Count', ascending=False)
    print("Attacker IP Addresses Involved in DoS Attacks:")
    print(ip_counts_df.head(10))
else:
    print("No 'src_' columns found for plotting attacker IP addresses.")
