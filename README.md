# Phishing Email Detection System

## Overview
This project builds a multi-class classifier to detect phishing emails by analyzing email content, subject lines, and sender patterns. It uses advanced NLP techniques like BERT (Bidirectional Encoder Representations from Transformers) for contextual understanding, combined with feature extraction from URLs, urgency language, and sender spoofing patterns. The model classifies emails into three categories: **phishing**, **spam**, or **legitimate**.

Key Features:
- **NLP Model**: Fine-tuned BERT or similar transformer for email text analysis.
- **Feature Engineering**: Extracts patterns like suspicious URLs, urgent phrases (e.g., "Act now!"), and sender anomalies (e.g., spoofed domains).
- **Classification**: Multi-class output with evaluation metrics (accuracy, precision, recall, F1-score).
- **Deployment**: Simple API or script for real-time prediction.

This system aims to help users and organizations identify malicious emails, reducing risks from phishing attacks.

## Technologies Used
- **Programming Language**: Python 3.8+
- **Libraries**:
  - Transformers (Hugging Face) for BERT models
  - Scikit-learn for feature extraction and traditional ML
  - Pandas/Numpy for data handling
  - NLTK or SpaCy for text preprocessing
  - Flask or FastAPI for API deployment (optional)
- **Hardware**: GPU recommended for training (e.g., via Google Colab or local CUDA setup)
- **Datasets**: Public datasets like Enron Email Dataset, Phishing Email Dataset from Kaggle, or custom scraped data.

## Installation and Setup
1. **Clone the Repository**:
