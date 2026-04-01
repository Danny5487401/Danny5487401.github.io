from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class Sample:
    label: str
    text: str


TRAIN_SAMPLES = [
    Sample("tech", "python 代码 脚本 自动化 开发 调试 接口 服务"),
    Sample("tech", "机器学习 模型 训练 向量 特征 推理 算法 数据"),
    Sample("tech", "数据库 查询 索引 存储 事务 性能 优化 表"),
    Sample("tech", "前端 页面 组件 状态 渲染 交互 打包 工程"),
    Sample("tech", "后端 接口 缓存 队列 部署 监控 日志 服务"),
    Sample("sports", "足球 比赛 进球 防守 联赛 教练 球队 战术"),
    Sample("sports", "篮球 球员 投篮 篮板 助攻 反击 节奏 对抗"),
    Sample("sports", "羽毛球 发球 扣杀 步伐 训练 体能 对抗 单打"),
    Sample("sports", "跑步 配速 耐力 心率 训练 马拉松 赛道 补给"),
    Sample("sports", "游泳 自由泳 转身 呼吸 节奏 划水 体能 训练"),
    Sample("food", "火锅 麻辣 牛肉 蘸料 聚餐 美食 锅底 毛肚"),
    Sample("food", "蛋糕 烘焙 奶油 甜点 香草 下午茶 松软 可可"),
    Sample("food", "咖啡 手冲 豆子 香气 烘焙 回甘 酸质 风味"),
    Sample("food", "烧烤 孜然 炭火 羊肉 夜宵 香味 油脂 啤酒"),
    Sample("food", "寿司 米饭 三文鱼 芥末 冷食 新鲜 拼盘 口感"),
]

TEST_SAMPLES = [
    Sample("tech", "模型 训练 向量 算法 数据"),
    Sample("sports", "球队 比赛 进球 教练 战术"),
    Sample("food", "甜点 奶油 烘焙 可可 香草"),
]

QUERY_TEXTS = [
    "向量 模型 算法",
    "球队 比赛 教练",
    "麻辣 牛肉 火锅",
]

VECTOR_SIZE = 48


@dataclass
class DemoEmbeddingModel:
    vector_size: int
    document_vectors: dict[str, np.ndarray]


def tokenize(text: str) -> list[str]:
    return [token.strip() for token in text.split() if token.strip()]


def normalize(vector: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vector))
    if norm == 0:
        return vector
    return vector / norm


def token_to_vector(token: str, vector_size: int) -> np.ndarray:
    # 使用 token 的哈希作为随机种子，保证浏览器里每次运行得到相同向量。
    seed = int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "little")
    rng = np.random.default_rng(seed)
    return normalize(rng.standard_normal(vector_size))


def embed_text(text: str, vector_size: int) -> np.ndarray:
    tokens = tokenize(text)
    if not tokens:
        return np.zeros(vector_size, dtype=np.float64)

    vectors = [token_to_vector(token, vector_size) for token in tokens]
    return normalize(np.mean(vectors, axis=0))


def train_model(train_samples: list[Sample]) -> DemoEmbeddingModel:
    # 本地脚本使用 Doc2Vec 训练文档向量；这里改成 NumPy 版轻量 Embeddings，
    # 方便在 Pyodide 里直接运行，同时保留“向量化 -> 检索 -> 分类”的流程。
    document_vectors = {
        f"train_{idx}": embed_text(sample.text, VECTOR_SIZE)
        for idx, sample in enumerate(train_samples)
    }
    return DemoEmbeddingModel(vector_size=VECTOR_SIZE, document_vectors=document_vectors)


def cosine_similarity(left: np.ndarray, right: np.ndarray) -> float:
    denominator = float(np.linalg.norm(left) * np.linalg.norm(right))
    if denominator == 0:
        return 0.0
    return float(np.dot(left, right) / denominator)


def show_similar_documents(model: DemoEmbeddingModel, train_samples: list[Sample], query: str) -> None:
    query_vector = embed_text(query, model.vector_size)
    similar_docs = sorted(
        (
            (tag, cosine_similarity(query_vector, vector))
            for tag, vector in model.document_vectors.items()
        ),
        key=lambda item: item[1],
        reverse=True,
    )[:3]

    print(f"\n查询: {query}")
    for tag, score in similar_docs:
        index = int(tag.split("_")[1])
        sample = train_samples[index]
        print(f"  - 相似文档: {sample.text} | label={sample.label} | score={score:.4f}")


def build_label_centroids(model: DemoEmbeddingModel, train_samples: list[Sample]) -> dict[str, np.ndarray]:
    grouped_vectors: dict[str, list[np.ndarray]] = defaultdict(list)
    for idx, sample in enumerate(train_samples):
        grouped_vectors[sample.label].append(model.document_vectors[f"train_{idx}"])

    return {
        label: normalize(np.mean(vectors, axis=0))
        for label, vectors in grouped_vectors.items()
    }


def evaluate_classification(
    model: DemoEmbeddingModel,
    train_samples: list[Sample],
    test_samples: list[Sample],
) -> None:
    centroids = build_label_centroids(model, train_samples)
    predictions: list[str] = []
    truths = [sample.label for sample in test_samples]

    print("\n分类验证:")
    for sample in test_samples:
        vector = embed_text(sample.text, model.vector_size)
        predicted_label = max(
            centroids,
            key=lambda label: cosine_similarity(vector, centroids[label]),
        )
        predictions.append(predicted_label)
        print(f"  - text={sample.text} | true={sample.label} | pred={predicted_label}")

    correct = sum(pred == truth for pred, truth in zip(predictions, truths))
    accuracy = correct / len(test_samples)
    print(f"\n准确率: {accuracy:.2%}")
    print(f"预测分布: {dict(Counter(predictions))}")


def main() -> None:
    print("开始构建浏览器版 Embeddings 示例...")
    model = train_model(TRAIN_SAMPLES)

    print("\n文档向量维度:", model.vector_size)
    print("训练语料条数:", len(TRAIN_SAMPLES))

    for query in QUERY_TEXTS:
        show_similar_documents(model, TRAIN_SAMPLES, query)

    evaluate_classification(model, TRAIN_SAMPLES, TEST_SAMPLES)


if __name__ == "__main__":
    main()
