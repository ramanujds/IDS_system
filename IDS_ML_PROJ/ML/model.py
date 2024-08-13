import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.impute import SimpleImputer

# Load and preprocess data
df = pd.read_csv('pck_data.csv')

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

# Check the distribution of labels
print("Label distribution in dataset:")
print(df['label'].value_counts())

# Separate input and output attributes
x = df.drop(['label'], axis=1)
y = df['label']

# Handle missing values if any remain
if x.isnull().values.any():
    imputer = SimpleImputer(strategy='mean')
    x = imputer.fit_transform(x)

# Scale features
ms = MinMaxScaler()
x = ms.fit_transform(x)

# Split data
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)

# Check if both classes are present in train and test sets
print("Training label distribution:")
print(pd.Series(y_train).value_counts())

print("Testing label distribution:")
print(pd.Series(y_test).value_counts())

# Ensure that both classes are in the training and test sets
if len(pd.Series(y_train).value_counts()) < 2 or len(pd.Series(y_test).value_counts()) < 2:
    print("Warning: Training or testing set does not contain samples of both classes.")
    # Here, you might need to recheck your dataset or use techniques to balance it.

# Classifier accuracies
Classifier_accuracy = []
Classifier_names = []

# K-Nearest Neighbor Classifier
try:
    knn_clf = KNeighborsClassifier()
    knn_clf.fit(X_train, y_train)
    y_pred = knn_clf.predict(X_test)
    accuracy = metrics.accuracy_score(y_test, y_pred)
    Classifier_accuracy.append(accuracy * 100)
    Classifier_names.append('KNN')
    print("Accuracy of KNN Classifier : %.2f" % (accuracy * 100))
    print("Classification Report for KNN:")
    print(metrics.classification_report(y_test, y_pred))
    print("Confusion Matrix for KNN:")
    print(metrics.confusion_matrix(y_test, y_pred))
except ValueError as e:
    print(f"Error encountered with KNN Classifier: {e}")

# Decision Tree Classifier
try:
    dt_clf = DecisionTreeClassifier(max_depth=5)
    dt_clf.fit(X_train, y_train)
    y_pred = dt_clf.predict(X_test)
    accuracy = metrics.accuracy_score(y_test, y_pred)
    Classifier_accuracy.append(accuracy * 100)
    Classifier_names.append('Decision Tree')
    print("Accuracy of Decision Tree Classifier : %.2f" % (accuracy * 100))
    print("Classification Report for Decision Tree:")
    print(metrics.classification_report(y_test, y_pred))
    print("Confusion Matrix for Decision Tree:")
    print(metrics.confusion_matrix(y_test, y_pred))
except ValueError as e:
    print(f"Error encountered with Decision Tree Classifier: {e}")

# Logistic Regression
try:
    lr_clf = LogisticRegression(max_iter=1000)
    lr_clf.fit(X_train, y_train)
    y_pred = lr_clf.predict(X_test)
    accuracy = metrics.accuracy_score(y_test, y_pred)
    Classifier_accuracy.append(accuracy * 100)
    Classifier_names.append('Logistic Regression')
    print("Accuracy of Logistic Regression Classifier : %.2f" % (accuracy * 100))
    print("Classification Report for Logistic Regression:")
    print(metrics.classification_report(y_test, y_pred))
    print("Confusion Matrix for Logistic Regression:")
    print(metrics.confusion_matrix(y_test, y_pred))
except ValueError as e:
    print(f"Error encountered with Logistic Regression: {e}")

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
    
    # Find and display the IP address with the highest count
    if not ip_counts_df.empty:
        highest_ip = ip_counts_df.loc[ip_counts_df['Count'].idxmax()]
        print("Attacker IP Address with the Highest Count of DoS Attacks:")
        print(highest_ip)
    else:
        print("No attacker IP addresses found with label 1.")
else:
    print(" columns found for plotting attacker IP addresses.")
