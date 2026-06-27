"""
图像取证核心模块

功能:
  1. ELA (Error Level Analysis) - 检测图像是否被PS篡改
  2. EXIF 签名提取 - 提取拍摄时间等元数据
  3. ORB + RANSAC 特征匹配 - 判断两张图是否同一底板
  4. 问题图片库管理 - 存储和查询问题图片

依赖: Pillow, numpy, scipy, opencv-contrib-python
"""

import io
import os
import json
import numpy as np
from PIL import Image, ImageChops
from scipy.spatial import ConvexHull
from datetime import datetime

# ═══════════════════════════════════════════
# 配置参数
# ═══════════════════════════════════════════

# ELA 参数
ELA_QUALITY = 75          # JPEG 重压缩质量
ELA_BLOCK_SIZE = 24       # 分析块大小(像素)
ELA_THRESHOLD = 3.5       # z-score 离群阈值

# ORB 参数
ORB_NFEATURES = 4000      # 最大特征点数
ORB_SCALE = 1.3           # 尺度金字塔因子
ORB_NLEVELS = 12          # 尺度金字塔层数
ORB_RATIO = 0.75          # Lowe's 比例测试阈值
ORB_INLIER_THRESHOLD = 0.02  # RANSAC 内点率阈值(2%)

# ═══════════════════════════════════════════
# 1. ELA 篡改检测
# ═══════════════════════════════════════════

def ela_detect(image_path, quality=ELA_QUALITY):
    """检测图像是否被PS篡改。

    算法: z-score + 空间聚类 + 组合置信度

    Args:
        image_path: 图片文件路径
        quality: JPEG重压缩质量(默认75)

    Returns:
        dict: {
            "tamper_score": 0-100,
            "verdict": "normal"|"suspicious"|"tampered",
            "confidence": "normal"|"medium"|"high",
            "abnormal_ratio": float,
            "ela_image_path": str  # 热力图路径
        }
    """
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception as e:
        return {"error": f"无法打开图片: {e}", "tamper_score": 0, "verdict": "error"}

    w, h = img.size
    if w * h > 4000 * 3000:
        img.thumbnail((2000, 2000), Image.LANCZOS)
        w, h = img.size

    # ── ELA: JPEG重压缩差异 ──
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    compressed = Image.open(buf).convert("RGB")

    diff = ImageChops.difference(img, compressed)
    pixel_errors = np.array(diff, dtype=np.float32).sum(axis=2)

    base, _ = os.path.splitext(image_path)
    orig_gray = np.array(img.convert("L"), dtype=np.float32)

    # ── 分块分析 ──
    raw_means, positions = [], []
    for y in range(0, h, ELA_BLOCK_SIZE):
        for x in range(0, w, ELA_BLOCK_SIZE):
            bh = min(ELA_BLOCK_SIZE, h - y); bw = min(ELA_BLOCK_SIZE, w - x)
            err_blk = pixel_errors[y:y+bh, x:x+bw]
            raw_means.append(float(np.mean(err_blk)))
            positions.append((x + bw // 2, y + bh // 2))

    raw = np.array(raw_means, dtype=np.float64)
    med_raw = max(float(np.median(raw)), 0.1)

    # ── z-score 离群分析 ──
    mu, sigma = float(np.mean(raw)), max(float(np.std(raw)), 0.5)
    z_scores = (raw - mu) / sigma

    strong = z_scores > ELA_THRESHOLD
    n_strong = int(np.sum(strong))
    ratio_strong = float(np.sum(strong)) / len(raw) * 100
    max_z = float(np.max(z_scores))
    max_raw = float(np.max(raw))
    p2m = max_raw / med_raw

    # ── 空间聚类分析 ──
    strong_positions = np.array([positions[i] for i in range(len(strong)) if strong[i]])
    cluster_ratio = 1.0
    if n_strong >= 3:
        try:
            hull = ConvexHull(strong_positions)
            cluster_ratio = hull.volume / (w * h)
        except Exception:
            cluster_ratio = 1.0
    elif n_strong == 2:
        d = float(np.linalg.norm(strong_positions[0] - strong_positions[1]))
        cluster_ratio = min(d * d / (w * h), 1.0)

    cluster_ratio = min(cluster_ratio, 1.0)

    # ── 综合评分 ──
    score = 0.0

    # 峰值惩罚(0-30): max_z > 5 强烈异常信号
    if max_z > 5.0:
        score += min((max_z - 5.0) * 10, 30)

    # 聚类奖励(0-40): 强离群块紧密聚类 -> PS 嫌疑
    if n_strong >= 3 and cluster_ratio < 0.15:
        cb = (1.0 - cluster_ratio / 0.15) * 40
        if n_strong <= 20 and max_z < 5.0:
            cb *= 0.1  # 噪声抑制
        score += cb

    # JPEG 幻影惩罚: 大量分散的离群块
    if n_strong > 50 and cluster_ratio > 0.3:
        score -= min(n_strong * 0.03, 25)

    # 离群比例奖励
    if n_strong >= 5 and ratio_strong > 0.01:
        score += min(ratio_strong * 3, 15)

    # 安全阀: JPEG 幻影图像不应达到 tampered
    if n_strong > 100 and cluster_ratio > 0.4 and p2m < 8:
        score = min(score, 18)

    score = max(0, min(round(score, 1), 100))

    # ── 判定 ──
    if score >= 25:
        verdict = "tampered"
    elif score >= 10:
        verdict = "suspicious"
    else:
        verdict = "normal"

    # ── 置信度 (基于交叉验证: ELA + 边缘方向一致性) ──
    _edge = _edge_consistency(img)
    if score >= 25 and _edge["cross_confirm"]:
        confidence = "high"       # ELA + 边缘方向一致 → 高
    elif score >= 25:
        confidence = "medium"     # 仅ELA → 中
    elif score >= 10:
        confidence = "medium"     # 可疑
    else:
        confidence = "normal"     # 正常

    # ── 蓝色热力图 (20倍放大) ──
    AMP = 20.0
    err_norm = np.clip(pixel_errors * AMP / 255.0, 0, 1).astype(np.float32)
    gray_arr = np.array(img.convert("L")).astype(float) / 255.0
    ctx = 1.0 - err_norm * 0.95
    b_ch = err_norm * 255 + (1 - err_norm) * 5
    g_ch = np.maximum(0, err_norm - 0.2) * 2.0 * 255 + (1 - err_norm) * 2.5
    r_ch = np.maximum(0, err_norm - 0.5) * 3.0 * 255 + (1 - err_norm) * 1.5
    R = np.clip(r_ch * (1 - ctx) + gray_arr * ctx * 30, 0, 255).astype(np.uint8)
    G = np.clip(g_ch * (1 - ctx) + gray_arr * ctx * 30, 0, 255).astype(np.uint8)
    B = np.clip(b_ch * (1 - ctx) + gray_arr * ctx * 30, 0, 255).astype(np.uint8)
    ela_img = np.stack([R, G, B], axis=2)
    ela_path = f"{base}_ela.png"
    Image.fromarray(ela_img, mode="RGB").save(ela_path)

    return {
        "tamper_score": score,
        "verdict": verdict,
        "confidence": confidence,
        "abnormal_ratio": round(ratio_strong, 4),
        "ela_image_path": ela_path,
    }


# ═══════════════════════════════════════════
# 1b. 边缘方向一致性 (交叉验证置信度)
# ═══════════════════════════════════════════

def _edge_consistency(image, block_size=24):
    """边缘方向局部一致性分析，作为ELA的交叉验证。

    原理: 自然图像的边缘方向在局部连续变化，
    PS操作会在修改区域产生方向突变。
    如果ELA异常区域也同时有边缘方向异常 → 篡改确认。

    Returns:
        dict: {"anomaly_ratio": float, "cluster_ratio": float,
               "cross_confirm": bool}
    """
    try:
        from scipy.ndimage import sobel
        import numpy as np

        gray = np.array(image.convert('L'), dtype=np.float32)
        h, w = gray.shape
        gx = sobel(gray, axis=1)
        gy = sobel(gray, axis=0)

        # 计算每块的主方向
        block_dirs = {}
        for y in range(0, h, block_size):
            for x in range(0, w, block_size):
                bh = min(block_size, h - y)
                bw = min(block_size, w - x)
                bx = gx[y:y+bh, x:x+bw]
                by = gy[y:y+bh, x:x+bw]
                mag = np.sqrt(bx**2 + by**2)
                if np.max(mag) > 0.5:
                    s2 = np.sum(mag * np.sin(2 * np.arctan2(by, bx)))
                    c2 = np.sum(mag * np.cos(2 * np.arctan2(by, bx)))
                    div = max(np.sqrt(s2**2 + c2**2), 1)
                    d = np.arctan2(s2 / div, c2 / div) / 2
                    block_dirs[(y // block_size, x // block_size)] = d

        # 计算相邻块方向差异
        dir_diffs = []
        for (r, c), d in block_dirs.items():
            neigh = []
            for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
                if (r + dr, c + dc) in block_dirs:
                    nd = block_dirs[(r + dr, c + dc)]
                    diff_ = abs(d - nd)
                    neigh.append(min(diff_, np.pi - diff_))
            if len(neigh) >= 2:
                dir_diffs.append(float(np.mean(neigh)))

        if len(dir_diffs) < 20:
            return {"anomaly_ratio": 0, "cluster_ratio": 1.0, "cross_confirm": False}

        dd = np.array(dir_diffs)
        mu, sig = float(np.mean(dd)), max(float(np.std(dd)), 0.02)
        z = (dd - mu) / sig

        # z > 2.0 的块视为边缘方向异常
        n_anom = int(np.sum(z > 2.0))
        ratio = n_anom / len(dd) * 100

        return {
            "anomaly_ratio": round(ratio, 4),
            "cross_confirm": n_anom > 10,  # 有边缘方向异常 → 交叉验证通过
        }
    except Exception:
        return {"anomaly_ratio": 0, "cluster_ratio": 1.0, "cross_confirm": False}


# ═══════════════════════════════════════════
# 2. EXIF 签名提取
# ═══════════════════════════════════════════

def exif_signature(image_path):
    """提取图片的EXIF+XMP签名。

    来源(按优先级):
    1. EXIF DateTimeOriginal (36867)
    2. XMP CreateDate
    3. EXIF DateTime (306) + Make (271) + Model (272)

    Returns:
        dict: {36867: str, "xmp_create_date": str, 306: str, 271: str, 272: str}
    """
    import re
    sig = {}
    try:
        img = Image.open(image_path)
        exif = img._getexif()
        if exif:
            for tag_id in (36867, 306, 271, 272, 36868):
                val = exif.get(tag_id)
                if val is not None:
                    if isinstance(val, bytes):
                        val = val.decode('ascii', errors='ignore').strip('\x00').strip()
                    if isinstance(val, str) and len(val) > 1:
                        sig[tag_id] = val
    except Exception:
        pass

    # EXIF 没有 DateTimeOriginal 时搜索 XMP CreateDate
    if not sig.get(36867):
        try:
            with open(image_path, 'rb') as f:
                raw = f.read()
            m = re.search(rb'xmp:CreateDate[="\s>]+([^"<>\s]+)', raw)
            if m:
                cd = m.group(1).decode('ascii', errors='ignore').strip()
                if cd:
                    sig["xmp_create_date"] = cd
        except Exception:
            pass

    return sig


# ═══════════════════════════════════════════
# 3. ORB + RANSAC 特征匹配
# ═══════════════════════════════════════════

_orb_cache = {}  # path -> (kp, des)

def _orb_features(path):
    """获取或缓存 ORB 特征"""
    if path not in _orb_cache:
        try:
            import cv2
            img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
            if img is not None:
                orb = cv2.ORB_create(nfeatures=ORB_NFEATURES,
                                     scaleFactor=ORB_SCALE,
                                     nlevels=ORB_NLEVELS)
                kp, des = orb.detectAndCompute(img, None)
                _orb_cache[path] = (kp, des)
            else:
                _orb_cache[path] = (None, None)
        except Exception:
            _orb_cache[path] = (None, None)
    return _orb_cache[path]


def orb_match(path_a, path_b):
    """ORB + RANSAC 特征匹配，判断两张图是否同一底板。

    支持尺度适应: 如果两图尺寸差异 > 3x, 缩小大图以匹配小图

    Returns:
        dict: {"inlier_count": int, "inlier_ratio": float, "match_count": int}
    """
    # 先检查依赖
    try:
        import cv2
    except ImportError:
        raise ImportError(
            "ORB特征匹配需要 opencv-contrib-python，请安装:\n"
            "  pip install opencv-contrib-python"
        )
    import numpy as np

    try:
        img_a = cv2.imread(path_a, cv2.IMREAD_GRAYSCALE)
        img_b = cv2.imread(path_b, cv2.IMREAD_GRAYSCALE)
        if img_a is None or img_b is None:
            return {"inlier_count": 0, "inlier_ratio": 0.0, "match_count": 0}

        # 尺度适应
        ha, wa = img_a.shape
        hb, wb = img_b.shape
        area_ratio = max(ha*wa, hb*wb) / max(min(ha*wa, hb*wb), 1)
        if area_ratio > 3:
            if ha*wa > hb*wb:
                sc = min(wb/wa, hb/ha) * 0.5
                img_a = cv2.resize(img_a, None, fx=sc, fy=sc,
                                   interpolation=cv2.INTER_AREA)
            else:
                sc = min(wa/wb, ha/hb) * 0.5
                img_b = cv2.resize(img_b, None, fx=sc, fy=sc,
                                   interpolation=cv2.INTER_AREA)

        orb = cv2.ORB_create(nfeatures=ORB_NFEATURES,
                             scaleFactor=ORB_SCALE,
                             nlevels=ORB_NLEVELS)
        kp_a, des_a = orb.detectAndCompute(img_a, None)
        kp_b, des_b = orb.detectAndCompute(img_b, None)

        if des_a is None or des_b is None or len(kp_a) < 5 or len(kp_b) < 5:
            return {"inlier_count": 0, "inlier_ratio": 0.0, "match_count": 0}

        bf = cv2.BFMatcher(cv2.NORM_HAMMING)
        matches = bf.knnMatch(des_a, des_b, k=2)

        # Lowe's ratio test
        good = []
        for pair in matches:
            if len(pair) == 2:
                m, n = pair
                if m.distance < ORB_RATIO * n.distance:
                    good.append(m)

        inliers = 0
        if len(good) >= 4:
            src = np.float32([kp_a[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
            dst = np.float32([kp_b[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)
            _, mask = cv2.findHomography(src, dst, cv2.RANSAC, 5.0)
            if mask is not None:
                inliers = int(np.sum(mask))

        min_kp = min(len(kp_a), len(kp_b))
        inlier_ratio = inliers / max(min_kp, 1)

        return {
            "inlier_count": inliers,
            "inlier_ratio": round(inlier_ratio, 4),
            "match_count": len(good),
        }
    except Exception as e:
        return {"inlier_count": 0, "inlier_ratio": 0.0,
                "match_count": 0, "error": str(e)}


# ═══════════════════════════════════════════
# 4. 问题图片库管理
# ═══════════════════════════════════════════

class ProblemLibrary:
    """问题图片库管理"""

    def __init__(self, lib_path=None):
        self.lib_path = lib_path or os.path.join(
            os.path.dirname(__file__), "problem_images.json"
        )

    def load(self):
        if not os.path.exists(self.lib_path):
            return []
        with open(self.lib_path, "r") as f:
            data = json.load(f)
        return data.get("images", [])

    def save(self, images):
        os.makedirs(os.path.dirname(self.lib_path), exist_ok=True)
        with open(self.lib_path, "w") as f:
            json.dump({"images": images}, f, ensure_ascii=False, indent=2)

    def add(self, case_id, original_name, file_path, ela_score, ela_result):
        images = self.load()
        for img in images:
            if img.get("original_name") == original_name:
                return False  # 文件名重复, 拒绝入库
        images.append({
            "case_id": case_id,
            "original_name": original_name,
            "file_path": file_path,
            "ela_score": ela_score,
            "ela_result": ela_result,
            "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        self.save(images)
        return True

    def remove(self, case_id, original_name):
        images = self.load()
        before = len(images)
        images = [i for i in images
                  if not (i["case_id"] == case_id and i["original_name"] == original_name)]
        if len(images) < before:
            self.save(images)
            return True
        return False

    def find_matches(self, image_path, exif_only=False):
        """在库中查找与给定图片匹配的条目。

        Args:
            image_path: 待检测图片路径
            exif_only: 仅用EXIF匹配, 不使用ORB

        Returns:
            list: [{"case_id", "original_name", "method", "detail"}]
        """
        library = self.load()
        matches = []

        for entry in library:
            lp = entry.get("file_path", "")
            if not lp or not os.path.exists(lp):
                continue

            sig = exif_signature(image_path)
            sig_lib = exif_signature(lp) if sig else None

            # EXIF 匹配 (始终)
            exif_ok = False
            exif_detail = ""
            if sig and sig_lib:
                x1 = sig.get("xmp_create_date") or sig.get(36867)
                x2 = sig_lib.get("xmp_create_date") or sig_lib.get(36867)
                if x1 and x2 and x1 == x2:
                    exif_ok = True
                    exif_detail = "EXIF时间戳: " + x1

            # ORB 匹配 (始终, 除非 exif_only=True)
            orb_ok = False
            orb_detail = ""
            if not exif_only:
                try:
                    orb_r = orb_match(image_path, lp)
                except ImportError:
                    raise
                except Exception:
                    orb_r = None
                if orb_r and orb_r.get("inlier_ratio", 0) > ORB_INLIER_THRESHOLD:
                    orb_ok = True
                    orb_detail = "内点率%.1f%%" % (orb_r['inlier_ratio'] * 100)

            # 合并结果
            if exif_ok or orb_ok:
                methods = []
                details = []
                if exif_ok:
                    methods.append("exif")
                    details.append(exif_detail)
                if orb_ok:
                    methods.append("orb")
                    details.append(orb_detail)
                matches.append({
                    "case_id": entry.get("case_id", ""),
                    "original_name": entry.get("original_name", ""),
                    "method": "+".join(methods),
                    "detail": " | ".join(details),
                })

        return matches


# ═══════════════════════════════════════════
# 5. 组合分析
# ═══════════════════════════════════════════

def analyze_image(image_path, library=None, output_ela=True):
    """对单张图片进行完整的图像取证分析。

    Args:
        image_path: 图片路径
        library: ProblemLibrary 实例或 None
        output_ela: 是否生成ELA热力图

    Returns:
        dict: {"ela": ..., "matches": [...]}
    """
    result = {"image": image_path}

    # ELA 检测
    ela_result = ela_detect(image_path)
    result["ela"] = ela_result

    # 底板比对
    if library is not None:
        matches = library.find_matches(image_path)
        result["matches"] = matches
    else:
        result["matches"] = []

    return result
