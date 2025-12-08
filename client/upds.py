"""
Расширённый классификатор файлов (multi-task):
- вход: только эмбеддинг, который строится из содержимого файла
- выходы: метка (virus/nonvirus), filetype (exe, docx, png, ...), threatType (CVE... / none)

Изменения по сравнению с исходным скриптом:
1) Новая функция file_to_embedding_new(...) — расширенный эмбеддинг (~1299 признаков):
   - гистограмма байт (256)
   - хэшированная гистограмма пар байт (1024)
   - лог_размер, среднее, std, энтропия (4)
   - перцентили 10,25,50,75,90 (5)
   - доля нулевых байт, доля печатных символов (2)
   - первые 8 байт файла (8)

2) Загрузка датасета поддерживает формат строк:
   path label filetype threatType
   Например:
       C:/lol.txt virus exe CVE2000
   Если filetype или threatType отсутствуют, указывайте "none".

3) Модель — multi-task: общий стак (trunk) + 3 головы:
   - virus_head: бинарная классификация (BCEWithLogits)
   - filetype_head: CrossEntropy (multi-class)
   - threat_head: CrossEntropy (multi-class)
   Потери суммируются с весами, регулируемыми через аргументы.

4) Сохранение:
   - model.pt — состояние модели
   - normalization.npz — mean/std для нормировки эмбеддингов
   - meta.json — словари mappings (filetype->idx, threat->idx) и параметры обучения

5) Предсказание: predict подгружает модель и возвращает:
   - вероятность вируса
   - предсказанный filetype + вероятность
   - предсказанный threatType + вероятность

Использование (CLI):
  train --list LIST --model-dir DIR [--epochs ...] [--batch-size ...] [--lr ...]
  predict --model-dir DIR --file FILE [--threshold 0.5]

"""

import argparse
import os
import math
import json
from collections import Counter
from typing import Tuple, List, Dict

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

# -------------------------------
# 1) Расширённый эмбеддинг
# -------------------------------

def file_to_embedding_new(file_path: str, pair_dim: int = 1024, chunk_size: int = 1024 * 1024) -> np.ndarray:
    """
    Собирает расширенный эмбеддинг для файла.
    Возвращает numpy array dtype float32, shape = D (примерно 1299)
    Состав признаков подробно в докстринге модуля.
    """
    counts = np.zeros(256, dtype=np.int64)
    total_bytes = 0
    sum_bytes = 0
    sumsq_bytes = 0
    zero_count = 0
    printable_count = 0

    # Для пар байт используем хэширование: считаем (b[i], b[i+1]) -> bucket
    pair_counts = np.zeros(pair_dim, dtype=np.int64)
    prev_byte = None

    first_bytes = []

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            data = np.frombuffer(chunk, dtype=np.uint8)
            if data.size == 0:
                continue

            if len(first_bytes) < 8:
                to_take = min(8 - len(first_bytes), data.size)
                first_bytes.extend([int(b) for b in data[:to_take]])

            total_bytes += data.size
            sum_bytes += int(data.sum())
            sumsq_bytes += int((data.astype(np.int64) ** 2).sum())
            counts += np.bincount(data, minlength=256)
            zero_count += int((data == 0).sum())
            # printable: ASCII 32..126
            printable_count += int(((data >= 32) & (data <= 126)).sum())

            # пары
            if prev_byte is None:
                prev = data[0]
                # pairs inside chunk
                pairs = (prev, )
            else:
                prev = prev_byte
            # iterate pairs (prev, data[0]), (data[0], data[1]), ...
            if data.size >= 1:
                # first pair
                idx = (int(prev) << 8) | int(data[0])
                bucket = (idx * 2654435761) & 0xFFFFFFFF
                bucket = (bucket >> 32 - int(math.log2(pair_dim))) if (pair_dim & (pair_dim-1) == 0 and pair_dim>0) else bucket % pair_dim
                pair_counts[bucket] += 1
                for i in range(data.size - 1):
                    b1 = int(data[i])
                    b2 = int(data[i+1])
                    idx = (b1 << 8) | b2
                    bucket = (idx * 2654435761) & 0xFFFFFFFF
                    bucket = (bucket >> 32 - int(math.log2(pair_dim))) if (pair_dim & (pair_dim-1) == 0 and pair_dim>0) else bucket % pair_dim
                    pair_counts[bucket] += 1
                prev_byte = int(data[-1])

    if total_bytes == 0:
        # пустой файл
        hist = np.zeros(256, dtype=np.float32)
        pair_hist = np.zeros(pair_dim, dtype=np.float32)
        mean = 0.0
        std = 0.0
        entropy = 0.0
        log_size = 0.0
        percentiles = np.zeros(5, dtype=np.float32)
        zero_ratio = 0.0
        printable_ratio = 0.0
        first_bytes_arr = np.zeros(8, dtype=np.float32)
    else:
        hist = counts.astype(np.float64) / float(total_bytes)

        pair_hist = pair_counts.astype(np.float64)
        pair_hist_sum = pair_hist.sum()
        if pair_hist_sum > 0:
            pair_hist = pair_hist / float(pair_hist_sum)
        else:
            pair_hist = np.zeros_like(pair_hist)

        mean = sum_bytes / float(total_bytes)
        variance = sumsq_bytes / float(total_bytes) - mean ** 2
        if variance < 0:
            variance = 0.0
        std = math.sqrt(variance)

        p = hist[hist > 0]
        entropy = float(-(p * np.log2(p)).sum())

        log_size = math.log10(float(total_bytes))

        # percentiles — для этого нужно прочитать файл снова (память): быстрее — восстановим распределение
        # создаём массив байтов повторяющихся counts[i] — но это может быть большой; вместо этого используем cumulative
        cum = np.cumsum(counts)
        percentiles = []
        for q in [10, 25, 50, 75, 90]:
            target = total_bytes * (q / 100.0)
            idx = np.searchsorted(cum, target)
            if idx >= 256:
                idx = 255
            percentiles.append(float(idx))
        percentiles = np.array(percentiles, dtype=np.float32)

        zero_ratio = zero_count / float(total_bytes)
        printable_ratio = printable_count / float(total_bytes)

        first_bytes_arr = np.zeros(8, dtype=np.float32)
        for i, b in enumerate(first_bytes[:8]):
            first_bytes_arr[i] = float(b)

    # Собираем фичи
    features = np.concatenate([
        hist.astype(np.float32),               # 256
        pair_hist.astype(np.float32),          # pair_dim (1024)
        np.array([log_size, mean, std, entropy], dtype=np.float32),  # 4
        percentiles.astype(np.float32),       # 5
        np.array([zero_ratio, printable_ratio], dtype=np.float32),  # 2
        first_bytes_arr.astype(np.float32)    # 8
    ])

    # ожидаемая размерность: 256 + pair_dim + 4 + 5 + 2 + 8
    expected = 256 + pair_dim + 4 + 5 + 2 + 8
    assert features.shape[0] == expected, f"Unexpected embedding dim: {features.shape[0]} vs {expected}"
    return features


# -------------------------------
# 2) Модель (multi-task)
# -------------------------------

class MultiTaskVirusClassifier(nn.Module):
    def __init__(self, input_dim: int, n_filetypes: int, n_threats: int, hidden_dim: int = 512, dropout: float = 0.2):
        super().__init__()
        self.trunk = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
        )

        trunk_out = hidden_dim // 2
        self.virus_head = nn.Linear(trunk_out, 1)  # логит
        self.filetype_head = nn.Linear(trunk_out, n_filetypes)
        self.threat_head = nn.Linear(trunk_out, n_threats)

    def forward(self, x: torch.Tensor):
        h = self.trunk(x)
        virus_logits = self.virus_head(h).squeeze(1)  # [B]
        filetype_logits = self.filetype_head(h)       # [B, n_filetypes]
        threat_logits = self.threat_head(h)           # [B, n_threats]
        return virus_logits, filetype_logits, threat_logits


# -------------------------------
# 3) Загрузка датасета (новый формат)
# -------------------------------

def parse_label_token(token: str) -> int:
    token = token.strip().lower()
    if token == 'virus':
        return 1
    elif token == 'nonvirus':
        return 0
    else:
        raise ValueError(f"Unknown label token: {token}")


def load_dataset_extended(list_path: str, embedding_fn=file_to_embedding_new) -> Tuple[np.ndarray, np.ndarray, List[str], List[str], List[str]]:
    """
    Читает разметку в формате:
      path label filetype threatType
    Возвращает:
      X: [N, D]
      y: [N] (0/1)
      filetypes: list of filetype strings (per example)
      threats: list of threat strings (per example)
      paths: list of paths
    """
    X = []
    y = []
    filetypes = []
    threats = []
    paths = []

    with open(list_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                print(f"[WARN] Line {line_num}: cannot parse: {line}")
                continue
            # Support both 2-token (path label) and 4-token formats
            file_path = parts[0]
            label_token = parts[1]
            filetype_token = 'none'
            threat_token = 'none'
            if len(parts) >= 3:
                filetype_token = parts[2]
            if len(parts) >= 4:
                threat_token = parts[3]

            try:
                label = parse_label_token(label_token)
            except ValueError as e:
                print(f"[WARN] Line {line_num}: {e}")
                continue

            if not os.path.isfile(file_path):
                print(f"[WARN] File not found: {file_path}, skipping")
                continue

            try:
                emb = embedding_fn(file_path)
            except Exception as e:
                print(f"[WARN] Error processing file {file_path}: {e}")
                continue

            X.append(emb)
            y.append(label)
            filetypes.append(filetype_token.lower())
            threats.append(threat_token.lower())
            paths.append(file_path)

    if not X:
        raise RuntimeError("No valid examples found in dataset")

    X = np.stack(X).astype(np.float32)
    y = np.array(y, dtype=np.float32)
    return X, y, filetypes, threats, paths


# -------------------------------
# 4) Обучение
# -------------------------------

def train_model_extended(
    list_path: str,
    model_dir: str,
    batch_size: int = 64,
    epochs: int = 20,
    lr: float = 1e-3,
    val_split: float = 0.2,
    device: str = None,
    pair_dim: int = 1024,
    loss_weights: Tuple[float, float, float] = (1.0, 1.0, 1.0)  # virus, filetype, threat
):
    os.makedirs(model_dir, exist_ok=True)
    print(f"[INFO] Loading dataset from {list_path}...")
    X, y, filetypes, threats, paths = load_dataset_extended(list_path, embedding_fn=lambda p: file_to_embedding_new(p, pair_dim))
    print(f"[INFO] Loaded {X.shape[0]} examples.")

    # Mappings for filetypes and threats
    filetype_set = sorted(set(filetypes))
    threat_set = sorted(set(threats))
    filetype2idx = {ft: i for i, ft in enumerate(filetype_set)}
    threat2idx = {t: i for i, t in enumerate(threat_set)}

    y_file = np.array([filetype2idx[ft] for ft in filetypes], dtype=np.int64)
    y_threat = np.array([threat2idx[t] for t in threats], dtype=np.int64)

    # Normalization
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1.0
    X_norm = (X - mean) / std

    # save normalization and mappings
    norm_path = os.path.join(model_dir, 'normalization.npz')
    np.savez(norm_path, mean=mean, std=std)
    meta = {
        'filetype_list': filetype_set,
        'threat_list': threat_set,
        'input_dim': X.shape[1],
        'pair_dim': pair_dim
    }
    with open(os.path.join(model_dir, 'meta.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"[INFO] Saved normalization to {norm_path} and meta.json")

    # Train/Val split
    n_samples = X_norm.shape[0]
    indices = np.arange(n_samples)
    np.random.shuffle(indices)
    n_val = int(n_samples * val_split)
    val_indices = indices[:n_val]
    train_indices = indices[n_val:]

    X_train = X_norm[train_indices]
    y_train = y[train_indices]
    y_file_train = y_file[train_indices]
    y_threat_train = y_threat[train_indices]

    X_val = X_norm[val_indices]
    y_val = y[val_indices]
    y_file_val = y_file[val_indices]
    y_threat_val = y_threat[val_indices]

    print(f"[INFO] Train samples: {X_train.shape[0]}, Val samples: {X_val.shape[0]}")

    # Tensors and loaders
    X_train_t = torch.from_numpy(X_train)
    y_train_t = torch.from_numpy(y_train)
    y_file_train_t = torch.from_numpy(y_file_train)
    y_threat_train_t = torch.from_numpy(y_threat_train)

    X_val_t = torch.from_numpy(X_val)
    y_val_t = torch.from_numpy(y_val)
    y_file_val_t = torch.from_numpy(y_file_val)
    y_threat_val_t = torch.from_numpy(y_threat_val)

    train_dataset = TensorDataset(X_train_t, y_train_t, y_file_train_t, y_threat_train_t)
    val_dataset = TensorDataset(X_val_t, y_val_t, y_file_val_t, y_threat_val_t)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    if device is None:
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"[INFO] Using device: {device}")

    model = MultiTaskVirusClassifier(input_dim=X.shape[1], n_filetypes=len(filetype_set), n_threats=len(threat_set)).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)

    criterion_virus = nn.BCEWithLogitsLoss()
    criterion_file = nn.CrossEntropyLoss()
    criterion_threat = nn.CrossEntropyLoss()

    w_virus, w_file, w_threat = loss_weights

    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        for batch in train_loader:
            batch_X, batch_y, batch_file, batch_threat = batch
            batch_X = batch_X.to(device)
            batch_y = batch_y.to(device)
            batch_file = batch_file.to(device)
            batch_threat = batch_threat.to(device)

            opt.zero_grad()
            virus_logits, file_logits, threat_logits = model(batch_X)
            loss_v = criterion_virus(virus_logits, batch_y)
            loss_f = criterion_file(file_logits, batch_file)
            loss_t = criterion_threat(threat_logits, batch_threat)
            loss = w_virus * loss_v + w_file * loss_f + w_threat * loss_t
            loss.backward()
            opt.step()
            running_loss += loss.item() * batch_X.size(0)

        running_loss /= X_train.shape[0]

        # Validation
        model.eval()
        val_loss = 0.0
        correct_v = 0
        total_v = 0
        correct_file = 0
        correct_threat = 0
        total = 0
        with torch.no_grad():
            for batch in val_loader:
                batch_X, batch_y, batch_file, batch_threat = batch
                batch_X = batch_X.to(device)
                batch_y = batch_y.to(device)
                batch_file = batch_file.to(device)
                batch_threat = batch_threat.to(device)

                virus_logits, file_logits, threat_logits = model(batch_X)
                loss_v = criterion_virus(virus_logits, batch_y)
                loss_f = criterion_file(file_logits, batch_file)
                loss_t = criterion_threat(threat_logits, batch_threat)
                loss = w_virus * loss_v + w_file * loss_f + w_threat * loss_t
                val_loss += loss.item() * batch_X.size(0)

                probs_v = torch.sigmoid(virus_logits)
                preds_v = (probs_v >= 0.5).float()
                correct_v += (preds_v == batch_y).sum().item()
                total_v += batch_y.size(0)

                preds_file = file_logits.argmax(dim=1)
                correct_file += (preds_file == batch_file).sum().item()

                preds_threat = threat_logits.argmax(dim=1)
                correct_threat += (preds_threat == batch_threat).sum().item()

                total += batch_X.size(0)

        val_loss /= X_val.shape[0]
        val_acc_v = correct_v / total_v if total_v > 0 else 0.0
        val_acc_file = correct_file / total if total > 0 else 0.0
        val_acc_threat = correct_threat / total if total > 0 else 0.0

        print(f"Epoch {epoch:03d} | train_loss={running_loss:.4f} | val_loss={val_loss:.4f} | "
              f"val_acc_virus={val_acc_v:.4f} filetype={val_acc_file:.4f} threat={val_acc_threat:.4f}")

    # Save model
    model_path = os.path.join(model_dir, 'model.pt')
    torch.save(model.state_dict(), model_path)
    print(f"[INFO] Model saved to {model_path}")


# -------------------------------
# 5) Загрузка модели и предсказание
# -------------------------------

def load_model_extended(model_dir: str, device: str = None):
    if device is None:
        device = 'cuda' if torch.cuda.is_available() else 'cpu'

    norm_path = os.path.join(model_dir, 'normalization.npz')
    model_path = os.path.join(model_dir, 'model.pt')
    meta_path = os.path.join(model_dir, 'meta.json')

    if not os.path.isfile(norm_path) or not os.path.isfile(model_path) or not os.path.isfile(meta_path):
        raise FileNotFoundError('Model, normalization or meta file missing in model_dir')

    data = np.load(norm_path)
    mean = data['mean'].astype(np.float32)
    std = data['std'].astype(np.float32)

    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)

    input_dim = meta['input_dim']
    filetype_list = meta['filetype_list']
    threat_list = meta['threat_list']

    model = MultiTaskVirusClassifier(input_dim=input_dim, n_filetypes=len(filetype_list), n_threats=len(threat_list))
    state = torch.load(model_path, map_location=device)
    model.load_state_dict(state)
    model.to(device)
    model.eval()
    return model, mean, std, filetype_list, threat_list, device


def predict_file_extended(model_dir: str, file_path: str, threshold: float = 0.5, pair_dim: int = 1024):
    model, mean, std, filetype_list, threat_list, device = load_model_extended(model_dir)
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    emb = file_to_embedding_new(file_path, pair_dim)
    emb_norm = (emb - mean) / std
    x = torch.from_numpy(emb_norm.astype(np.float32)).unsqueeze(0).to(device)

    with torch.no_grad():
        virus_logits, file_logits, threat_logits = model(x)
        prob = torch.sigmoid(virus_logits).item()

        file_probs = torch.softmax(file_logits, dim=1).squeeze(0).cpu().numpy()
        threat_probs = torch.softmax(threat_logits, dim=1).squeeze(0).cpu().numpy()

        file_idx = int(file_probs.argmax())
        threat_idx = int(threat_probs.argmax())

        filetype_pred = filetype_list[file_idx] if file_idx < len(filetype_list) else 'unknown'
        threat_pred = threat_list[threat_idx] if threat_idx < len(threat_list) else 'unknown'

    label_str = 'virus' if prob >= threshold else 'nonvirus'
    return {
        'label': label_str,
        'prob_virus': float(prob),
        'filetype': filetype_pred,
        'filetype_confidence': float(file_probs[file_idx]),
        'threat': threat_pred,
        'threat_confidence': float(threat_probs[threat_idx])
    }


# -------------------------------
# 6) CLI
# -------------------------------

def main():
    parser = argparse.ArgumentParser(description='Extended multi-task file classifier')
    subparsers = parser.add_subparsers(dest='command', required=True)

    train_p = subparsers.add_parser('train', help='Train model')
    train_p.add_argument('--list', required=True)
    train_p.add_argument('--model-dir', required=True)
    train_p.add_argument('--batch-size', type=int, default=64)
    train_p.add_argument('--epochs', type=int, default=20)
    train_p.add_argument('--lr', type=float, default=1e-3)
    train_p.add_argument('--val-split', type=float, default=0.2)
    train_p.add_argument('--pair-dim', type=int, default=1024)

    predict_p = subparsers.add_parser('predict', help='Predict single file')
    predict_p.add_argument('--model-dir', required=True)
    predict_p.add_argument('--file', required=True)
    predict_p.add_argument('--threshold', type=float, default=0.5)

    args = parser.parse_args()

    if args.command == 'train':
        train_model_extended(
            list_path=args.list,
            model_dir=args.model_dir,
            batch_size=args.batch_size,
            epochs=args.epochs,
            lr=args.lr,
            val_split=args.val_split,
            pair_dim=args.pair_dim
        )
    elif args.command == 'predict':
        res = predict_file_extended(model_dir=args.model_dir, file_path=args.file, threshold=args.threshold)
        print(f"File: {args.file}")
        print(f"Prob(virus): {res['prob_virus']:.4f} -> {res['label']}")
        print(f"Predicted filetype: {res['filetype']} (conf={res['filetype_confidence']:.3f})")
        print(f"Predicted threat: {res['threat']} (conf={res['threat_confidence']:.3f})")


if __name__ == '__main__':
    main()
