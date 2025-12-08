import os
import math
import numpy as np
import torch
import json
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from .ai_embeddings import *
from ..utils import logger

_logger = logger.get_module_logger("ThreateningFileMapper")


class FileEmbedding:
    def __init__(
        self,
        file_name: str = '',
        sha256: str = '',
        file_embedding: np.ndarray = None,
        threat_type: str = 'None',
        file_type: str = 'None',
        file_verdict: str = ''
    ):
        self.file_name = file_name
        self.sha256 = sha256
        self.file_embedding = file_embedding
        self.threat_type = threat_type
        self.file_type = file_type
        self.file_verdict = file_verdict

    @classmethod
    def from_dict(cls, data: dict) -> "FileEmbedding":
        emb = data.get("fileEmbedding", None)
        if emb is not None:
            emb = np.array(emb, dtype=np.float32)
        return cls(
            file_name=data.get("fileName", ""),
            sha256=data.get("sha256", ""),
            file_embedding=emb,
            threat_type=data.get("threatType", "None"),
            file_type=data.get("fileType", "None"),
            file_verdict=data.get("fileVerdict", "None"),
        )

    def to_dict(self) -> dict:
        emb_serial = None
        if isinstance(self.file_embedding, np.ndarray):
            emb_serial = self.file_embedding.tolist()
        return {
            "fileName": self.file_name,
            "sha256": self.sha256,
            "fileEmbedding": emb_serial,
            "threatType": self.threat_type,
            "fileType": self.file_type,
            "fileVerdict": self.file_verdict
        }


class MultiTaskThreatClassifier(nn.Module):

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
        self.virus_head = nn.Linear(trunk_out, 1)
        self.filetype_head = nn.Linear(trunk_out, n_filetypes)
        self.threat_head = nn.Linear(trunk_out, n_threats)

    def forward(self, x: torch.Tensor):
        h = self.trunk(x)
        virus_logits = self.virus_head(h).squeeze(1)
        filetype_logits = self.filetype_head(h)
        threat_logits = self.threat_head(h)
        return virus_logits, filetype_logits, threat_logits


def _load_model(model_dir: str, device: str = None):
    if device is None:
        device = 'cuda' if torch.cuda.is_available() else 'cpu'

    norm_path = os.path.join(model_dir, 'normalization.npz')
    model_path = os.path.join(model_dir, 'model.pt')
    meta_path = os.path.join(model_dir, 'meta.json')

    if not os.path.isfile(norm_path) or not os.path.isfile(model_path) or not os.path.isfile(meta_path):
        raise FileNotFoundError(
            'Model, normalization or meta file missing in model_dir')

    data = np.load(norm_path)
    mean = data['mean'].astype(np.float32)
    std = data['std'].astype(np.float32)

    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)

    input_dim = meta['input_dim']
    filetype_list = meta['filetype_list']
    threat_list = meta['threat_list']

    model = MultiTaskThreatClassifier(input_dim=input_dim, n_filetypes=len(
        filetype_list), n_threats=len(threat_list))
    state = torch.load(model_path, map_location=device)
    model.load_state_dict(state)
    model.to(device)
    model.eval()
    return model, mean, std, filetype_list, threat_list, device


def predict_file_with_path(file_path: str, model_dir: str, threshold: float = 0.5, pair_dim: int = 1024):
    file = _load_data_from_filepath(file_path)
    result = predict_embedding(file, model_dir, threshold, pair_dim)
    return result


def predict_embedding(files: list[FileEmbedding], model_dir: str, threshold: float = 0.5, pair_dim: int = 1024) -> list[FileEmbedding]:
    model, mean, std, filetype_list, threat_list, device = _load_model(
        model_dir)

    if isinstance(files, FileEmbedding):
        files = [files]

    result = []
    for file in files:
        emb = file.file_embedding
        emb_norm = (emb - mean) / std
        x = torch.from_numpy(emb_norm.astype(
            np.float32)).unsqueeze(0).to(device)

        with torch.no_grad():
            virus_logits, file_logits, threat_logits = model(x)
            prob = torch.sigmoid(virus_logits).item()

            file_probs = torch.softmax(
                file_logits, dim=1).squeeze(0).cpu().numpy()
            threat_probs = torch.softmax(
                threat_logits, dim=1).squeeze(0).cpu().numpy()

            file_idx = int(file_probs.argmax())
            threat_idx = int(threat_probs.argmax())

            filetype_pred = filetype_list[file_idx] if file_idx < len(
                filetype_list) else 'None'
            threat_pred = threat_list[threat_idx] if threat_idx < len(
                threat_list) else 'None'

        verdict = 'Threat' if prob >= threshold else 'Safe'
        file.file_verdict = verdict
        file.file_type = filetype_pred
        file.threat_type = threat_pred
        result.append(file)

    return result


def parse_label_token(verdict: str) -> float:
    if verdict is None:
        return 0.0
    token = str(verdict).strip().lower()
    positive = {'virus', 'threat', 'malware', '1', 'true', 'yes'}
    return 1.0 if token in positive else 0.0


def _extract_dataset(files: list[FileEmbedding]):
    embs = []
    verdicts = []
    filetypes = []
    threats = []

    for file in files:
        emb = file.file_embedding
        if emb is None:
            continue
        emb = np.asarray(emb, dtype=np.float32)
        if emb.ndim != 1:
            raise RuntimeError(
                f"Unexpected embedding shape for file {file.file_name}: {emb.shape}")

        embs.append(emb)
        verdicts.append(parse_label_token(file.file_verdict))
        filetypes.append((file.file_type or 'None').lower())
        threats.append((file.threat_type or 'None').lower())

    if not embs:
        raise RuntimeError("No valid examples found in dataset")

    emb_shapes = [e.shape[0] for e in embs]
    if len(set(emb_shapes)) != 1:
        raise RuntimeError(
            f"Inconsistent embedding sizes found: {set(emb_shapes)}")

    X = np.stack(embs, axis=0)
    y = np.array(verdicts, dtype=np.float32)
    return X, y, filetypes, threats


def train_model_with_embeddings(files: list[FileEmbedding], model_dir: str, batch_size: int = 64, epochs: int = 20, lr: float = 1e-3, val_split: float = 0.2, device: str = None, pair_dim: int = 1024, loss_weights: tuple[float, float, float] = (1.0, 1.0, 1.0)):
    os.makedirs(model_dir, exist_ok=True)
    X, y, filetypes, threats = _extract_dataset(files)
    _logger.info(f"[INFO] Loaded {X.shape[0]} examples.")

    filetype_set = sorted(set(filetypes))
    threat_set = sorted(set(threats))
    filetype2idx = {ft: i for i, ft in enumerate(filetype_set)}
    threat2idx = {t: i for i, t in enumerate(threat_set)}

    y_file = np.array([filetype2idx[ft] for ft in filetypes], dtype=np.int64)
    y_threat = np.array([threat2idx[t] for t in threats], dtype=np.int64)

    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1.0
    X_norm = (X - mean) / std
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

    _logger.info(f"[INFO] Saved normalization to {norm_path} and meta.json")
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
    _logger.info(
        f"[INFO] Train samples: {X_train.shape[0]}, Val samples: {X_val.shape[0]}")

    X_train_t = torch.from_numpy(X_train)
    y_train_t = torch.from_numpy(y_train)
    y_file_train_t = torch.from_numpy(y_file_train)
    y_threat_train_t = torch.from_numpy(y_threat_train)

    X_val_t = torch.from_numpy(X_val)
    y_val_t = torch.from_numpy(y_val)
    y_file_val_t = torch.from_numpy(y_file_val)
    y_threat_val_t = torch.from_numpy(y_threat_val)

    train_dataset = TensorDataset(
        X_train_t, y_train_t, y_file_train_t, y_threat_train_t)
    val_dataset = TensorDataset(X_val_t, y_val_t, y_file_val_t, y_threat_val_t)

    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    if device is None:
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    _logger.info(f"[INFO] Using device: {device}")

    model = MultiTaskThreatClassifier(input_dim=X.shape[1], n_filetypes=len(
        filetype_set), n_threats=len(threat_set)).to(device)
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

        _logger.info(f"Epoch {epoch:03d} | train_loss={running_loss:.4f} | val_loss={val_loss:.4f} | "
                     f"val_acc_virus={val_acc_v:.4f} filetype={val_acc_file:.4f} threat={val_acc_threat:.4f}")

    model_path = os.path.join(model_dir, 'model.pt')
    torch.save(model.state_dict(), model_path)
    _logger.info(f"[INFO] Model saved to {model_path}")


def _load_dataset_from_file(file_path: str):
    scanned = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) < 1:
                continue

            path = parts[0]
            verdict = parts[1] if len(parts) >= 2 else ''
            file_type = parts[2] if len(parts) >= 3 else 'None'
            threat = parts[3] if len(parts) >= 4 else 'None'

            try:
                emb = file2embedding(path)
                sha = file2sha(path)
            except Exception as e:
                _logger.error(
                    f"Error embedding file {path} at line {line_num}: {e}")
                continue

            file_to_scan = FileEmbedding(
                file_name=os.path.basename(path),
                file_embedding=emb,
                sha256=sha,
                threat_type=threat,
                file_type=file_type,
                file_verdict=verdict
            )
            scanned.append(file_to_scan)
    return scanned


def _load_data_from_filepath(filepath: str):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    return FileEmbedding(
        file_name=os.path.basename(filepath),
        file_embedding=file2embedding(filepath),
        sha256=file2sha(filepath),
    )


def train_model_with_list(
    list_path: str,
    model_dir: str,
    batch_size: int = 64,
    epochs: int = 20,
    lr: float = 1e-3,
    val_split: float = 0.2,
    device: str = None,
    pair_dim: int = 1024,
    loss_weights: tuple[float, float, float] = (1.0, 1.0, 1.0)
):
    files = _load_dataset_from_file(list_path)
    train_model_with_embeddings(
        files, model_dir, batch_size, epochs, lr, val_split, device, pair_dim, loss_weights)
    return files
