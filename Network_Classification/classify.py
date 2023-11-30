import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import BernoulliNB
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score
from telnetlib import GA
import matplotlib.pyplot as plt
import numpy as np
import itertools
import seaborn as sns
import random


# CONFUSION MATRIX
def plot_confusion_matrix(cm, classes, normalize=False, title='Confusion matrix', cmap=plt.cm.Blues):
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes)
    plt.yticks(tick_marks, classes)

    print(cm)
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, cm[i, j],
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()


# FEATURE IMPORTANCE
def plot_feature_importance(importance,names,model_type):    
    feature_importance = np.array(importance)
    feature_names = np.array(names)
    data={'feature_names':feature_names,'feature_importance':feature_importance}
    fi_df = pd.DataFrame(data)
    fi_df.sort_values(by=['feature_importance'], ascending=False,inplace=True)
    plt.figure(figsize=(10,8))
    sns.barplot(x=fi_df['feature_importance'], y=fi_df['feature_names'], color='skyblue')
    plt.title('FEATURE IMPORTANCE')
    plt.xlabel('FEATURE IMPORTANCE')
    plt.ylabel('FEATURE NAMES')
    plt.show()


# PREPROCESSING
df_benign = pd.read_csv('benign_new.csv')
df_malware = pd.read_csv('malware_new.csv')

df_benign = df_benign.iloc[:108000]
df_malware = df_malware.iloc[:126000]

df_benign['status'] = 0
df_malware['status'] = 1

df = [df_benign, df_malware]
random.shuffle(df)
df = pd.concat(df, ignore_index = True)

df = df.fillna(0)

X = df[['tcp_frame_length', 'tcp_ip_length', 'tcp_length', 'udp_frame_length', 'udp_ip_length', 'udp_length', 'num_tls', 'num_http', 'num_dhcp', 'num_dns', 'num_tcp', 'num_udp', 'num_igmp', 'num_connection_pairs', 'num_ports', 'num_packets']]
y = df[['status']]
 
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4)

scaler = StandardScaler()
scaler.fit(X_train)
X_train_scaled = scaler.transform(X_train)
X_test_scaled = scaler.transform(X_test)


# LOGISTIC REGRESSION
logistic = LogisticRegression(solver='liblinear', random_state=0)
logistic.fit(X_train_scaled, y_train)
y_pred = logistic.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("Logistic Regression Classifier")
print("True Positive: ",tp)
print("True Negative: ",tn)
print("False Positive: ",fp)
print("False Negative: ",fn)
print("Recall: ",tp/(tp + fn))
print("Precision: ",tp/(tp + fp))
print("Accuracy: ",a)
print("F1 Score: ",f1)
cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Normal', 'Attack'], title='Logistic Regression')


# DECISION TREE
tree = DecisionTreeClassifier()
tree.fit(X_train_scaled, y_train)
y_pred = tree.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("Decision Tree Classifier")
print("True Positive: ",tp)
print("True Negative: ",tn)
print("False Positive: ",fp)
print("False Negative: ",fn)
print("Recall: ",tp/(tp + fn))
print("Precision: ",tp/(tp + fp))
print("Accuracy: ",a)
print("F1 Score: ",f1)

cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Normal', 'Attack'], title='Decision Tree')


# RANDOM FOREST CLASSIFIER
forest = RandomForestClassifier(n_estimators=10)
forest.fit(X_train_scaled, y_train)
y_pred = forest.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("Random Forest Classifier")
print("True Positive: ",tp)
print("True Negative: ",tn)
print("False Positive: ",fp)
print("False Negative: ",fn)
print("Recall: ",tp/(tp + fn))
print("Precision: ",tp/(tp + fp))
print("Accuracy: ",a)
print("F1 Score: ",f1)

cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Normal', 'Attack'], title='Random Forest')


# K-NEIGHBOURS CLASSIFIER
neighbours = KNeighborsClassifier()
neighbours.fit(X_train_scaled, y_train)
y_pred = neighbours.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("K Neighbours Classifier")
print("True Positive: ",tp)
print("True Negative: ",tn)
print("False Positive: ",fp)
print("False Negative: ",fn)
print("Recall: ",tp/(tp + fn))
print("Precision: ",tp/(tp + fp))
print("Accuracy: ",a)
print("F1 Score: ",f1)
cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Normal', 'Attack'], title='K Neighbours')


# NAIVE BAYES
bayes = BernoulliNB()
bayes.fit(X_train_scaled, y_train)
y_pred = bayes.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("Naive Bayes Classifier")
print("True Positive: ",tp)
print("True Negative: ",tn)
print("False Positive: ",fp)
print("False Negative: ",fn)
print("Recall: ",tp/(tp + fn))
print("Precision: ",tp/(tp + fp))
print("Accuracy: ",a)
print("F1 Score: ",f1)
cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Normal', 'Attack'], title='Naive Bayes')


# SUPPORT VECTOR MACHINE
svc = SVC()
svc.fit(X_train_scaled, y_train)
y_pred = svc.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("Standard Vector Machine")
print("True Positive: ",tp)
print("True Negative: ",tn)
print("False Positive: ",fp)
print("False Negative: ",fn)
print("Recall: ",tp/(tp + fn))
print("Precision: ",tp/(tp + fp))
print("Accuracy: ",a)
print("F1 Score: ",f1)
cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Normal', 'Attack'], title='Standard Vector Machine')


# PLOT FEATURE IMPORTANCE
for i,v in enumerate(forest.feature_importances_):
	print('Feature: %0d, Score: %.5f' % (i,v))

plot_feature_importance(forest.feature_importances_,X.columns,'RANDOM FOREST')
