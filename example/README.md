# Neural Network

This example uses an autoencoder for anomaly detection based on https://www.geeksforgeeks.org/deep-learning/how-to-use-pytorch-for-anomaly-detection/.

We use Pytorch2 2.9.1 and Scikit-Learn 1.7.2

# Dataset

The dataset has non-numeric values which requires One-hot-encoding as well as (Multilabel Binarizer)[https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.MultiLabelBinarizer.html]

The dataset contains network traffic and binary information regarding IoT botnets of 2024. The goal was to create a dataset that is able to be used for on-device training in a Smart Home sandbox.
