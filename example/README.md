# Neural Network

This example uses an autoencoder for anomaly detection based on this [blog entry](https://www.geeksforgeeks.org/deep-learning/how-to-use-pytorch-for-anomaly-detection/).

![pandas](https://img.shields.io/badge/pandas-2.x-150458?logo=pandas&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-ee4c2c?logo=pytorch&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.0+-f7931e?logo=scikitlearn&logoColor=white)

# Dataset

The dataset has non-numeric values which requires One-hot-encoding as well as [Multilabel Binarizer](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.MultiLabelBinarizer.html)

The dataset contains network traffic and binary information regarding IoT botnets of 2024. The goal was to create a dataset that is able to be used for on-device training in a Smart Home sandbox.
