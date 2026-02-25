# app/ml_model.py
from transformers import pipeline

# Загружаем модель один раз при старте backend
ML_PIPELINE = pipeline(
    "zero-shot-classification",
    model="MoritzLaurer/mDeBERTa-v3-base-mnli-xnli"
)

# Категории угроз
CATEGORIES = [
    "illegal drugs",
    "online casino",
    "pyramid scheme",
    "financial fraud",
    "safe website"
]

def predict(features: dict) -> float:
    """
    features: словарь с признаками страницы, включая title/meta/body_snippet
    Возвращает score от 0 до 1
    """
    text = " ".join([
        features.get("title", ""),
        features.get("meta_description", ""),
        features.get("body_snippet", "")
    ])
    result = ML_PIPELINE(text, CATEGORIES)
    
    # Берём max вероятность по опасным категориям
    max_score = 0
    for label, score in zip(result["labels"], result["scores"]):
        if label != "safe website" and score > max_score:
            max_score = score
    return float(max_score)
