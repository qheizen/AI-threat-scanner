import io
import base64
import numpy as np
import math
import hashlib


def file2embedding(file_path: str, pair_dim: int = 1024, chunk_size: int = 1024 * 1024) -> np.ndarray:
    counts = np.zeros(256, dtype=np.int64)
    total_bytes = 0
    sum_bytes = 0
    sumsq_bytes = 0
    zero_count = 0
    printable_count = 0

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
            printable_count += int(((data >= 32) & (data <= 126)).sum())

            if prev_byte is None:
                prev = data[0]
                pairs = (prev, )
            else:
                prev = prev_byte

            if data.size >= 1:
                idx = (int(prev) << 8) | int(data[0])
                bucket = (idx * 2654435761) & 0xFFFFFFFF
                bucket = (bucket >> 32 - int(math.log2(pair_dim))) if (pair_dim &
                                                                       (pair_dim-1) == 0 and pair_dim > 0) else bucket % pair_dim
                pair_counts[bucket] += 1
                for i in range(data.size - 1):
                    b1 = int(data[i])
                    b2 = int(data[i+1])
                    idx = (b1 << 8) | b2
                    bucket = (idx * 2654435761) & 0xFFFFFFFF
                    bucket = (bucket >> 32 - int(math.log2(pair_dim))) if (pair_dim &
                                                                           (pair_dim-1) == 0 and pair_dim > 0) else bucket % pair_dim
                    pair_counts[bucket] += 1
                prev_byte = int(data[-1])

    if total_bytes == 0:
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

    features = np.concatenate([
        hist.astype(np.float32),
        pair_hist.astype(np.float32),
        np.array([log_size, mean, std, entropy], dtype=np.float32),
        percentiles.astype(np.float32),
        np.array([zero_ratio, printable_ratio], dtype=np.float32),
        first_bytes_arr.astype(np.float32)
    ])

    expected = 256 + pair_dim + 4 + 5 + 2 + 8
    assert features.shape[
        0] == expected, f"Unexpected embedding dim: {features.shape[0]} vs {expected}"
    return features


def embedding_to_str(arr: np.ndarray) -> str:
    buf = io.BytesIO()
    np.save(buf, arr, allow_pickle=False)
    raw = buf.getvalue()
    return base64.b64encode(raw).decode("ascii")


def embedding_from_str(s: str) -> np.ndarray:
    raw = base64.b64decode(s.encode("ascii"))
    buf = io.BytesIO(raw)
    buf.seek(0)
    return np.load(buf, allow_pickle=False)

def file2sha(file_path: str):
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл не найден: {file_path}")
    except IOError as e:
        raise IOError(f"Ошибка чтения файла {file_path}: {str(e)}")