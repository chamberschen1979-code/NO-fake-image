"""
图像取证工具 - Web界面

三个功能:
  1. 图片篡改识别 (ELA检测 + 自动入库)
  2. 图片查重检测 (两图对比 / 与问题库对比)
  3. 问题图片库 (查看 / 批量上传 / 删除)

分数与判定标准:

  ▸ 篡改评分 (0-100):
    - 峰值惩罚(0-30): z-score > 5 → 强烈异常信号
    - 聚类奖励(0-40): 异常块紧密聚集 → PS篡改
    - 幻影惩罚(-25): 大量分散异常块 → JPEG压缩伪影
    - 比例奖励(0-15): 离群比例确认

  ▸ 判定:
    - 正常: 0-9分    → 无篡改信号
    - 可疑: 10-24分  → 局部修改可能
    - 篡改: ≥25分    → 明确篡改

  ▸ 置信度:
    - 高(high):   评分≥40
    - 中(medium): 评分10-39
    - 正常(normal): 评分<10

  ▸ 查重(EXIF/ORB):
    - EXIF: 同一 XMP CreateDate / DateTimeOriginal
    - ORB : 内点率 > 2% → 同一底板
"""

import os, sys, json, uuid, shutil, argparse, asyncio, re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import ela_detect, exif_signature, orb_match, ProblemLibrary

from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import uvicorn

app = FastAPI(title="图像防伪工具v1.0")
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
LIB_STORAGE = os.path.join(UPLOAD_DIR, "library")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LIB_STORAGE, exist_ok=True)

LIB_PATH = None   # 问题库 JSON 文件路径


# ── 工具函数 ──

async def _save_upload(file: UploadFile) -> str:
    """保存上传文件(安全校验), 返回路径"""
    # 校验文件类型
    ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
    orig = (file.filename or "image.jpg").split("/")[-1].split("\\")[-1]
    ext = os.path.splitext(orig)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"不支持的文件类型: {ext}，仅支持图片格式")
    # 校验文件大小 (10MB)
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "文件太大，最大 10MB")
    name = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, name)
    with open(path, "wb") as f:
        f.write(content)
    return path


def _get_lib() -> ProblemLibrary:
    if not LIB_PATH:
        raise HTTPException(400, "问题库未加载")
    return ProblemLibrary(LIB_PATH)


# ── API: 状态 ──

@app.get("/api/status")
async def status():
    lib = _get_lib() if LIB_PATH else None
    return {
        "status": "ok",
        "lib_loaded": lib is not None,
        "lib_count": len(lib.load()) if lib else 0,
    }


# ── API: 图片篡改识别 ──

@app.post("/api/tamper-check")
async def api_tamper_check(file: UploadFile = File(...)):
    """ELA篡改检测, 可疑/篡改则自动入库"""
    save_path = await _save_upload(file)
    result = ela_detect(save_path)
    filename = file.filename or os.path.basename(save_path)

    # ELA 热力图
    ela_src = result.get("ela_image_path", "")
    if ela_src and os.path.exists(ela_src):
        ela_dst = os.path.join(UPLOAD_DIR, f"ela_{uuid.uuid4().hex}.png")
        shutil.copy2(ela_src, ela_dst)
        result["ela_url"] = f"/uploads/{os.path.basename(ela_dst)}"

    # EXIF
    result["exif"] = exif_signature(save_path)

    # 自动入库(可疑或篡改)
    lib = _get_lib() if LIB_PATH else None
    lib_entry = None
    if lib and result["verdict"] in ("tampered", "suspicious"):
        # 复制图片到库存储
        lib_path = os.path.join(LIB_STORAGE, os.path.basename(save_path))
        shutil.copy2(save_path, lib_path)
        case_id = f"AUTO-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        added = lib.add(
            case_id=case_id,
            original_name=filename,
            file_path=lib_path,
            ela_score=result["tamper_score"],
            ela_result=result["verdict"],
        )
        if added:
            lib_entry = {"case_id": case_id, "original_name": filename}
            result["auto_added"] = lib_entry

    return result


# ── API: 图片查重检测 ──

@app.post("/api/compare-two")
async def api_compare_two(file_a: UploadFile = File(...), file_b: UploadFile = File(...)):
    """两张图片对比查重 (EXIF + ORB)"""
    pa, pb = await _save_upload(file_a), await _save_upload(file_b)
    sa, sb = exif_signature(pa), exif_signature(pb)
    orb = orb_match(pa, pb)

    x1 = sa.get("xmp_create_date") or sa.get(36867)
    x2 = sb.get("xmp_create_date") or sb.get(36867)
    exif_match = bool(x1 and x2 and x1 == x2)

    return {
        "exif_a": {str(k): v for k, v in sa.items()},
        "exif_b": {str(k): v for k, v in sb.items()},
        "exif_match": exif_match,
        "exif_detail": x1 if exif_match else None,
        "orb": orb,
        "same_base": exif_match or orb.get("inlier_ratio", 0) > 0.02,
    }


@app.post("/api/compare-lib")
async def api_compare_lib(file: UploadFile = File(...)):
    """单张图片与问题库对比查重"""
    save_path = await _save_upload(file)
    lib = _get_lib() if LIB_PATH else ProblemLibrary(os.path.join(BASE_DIR, "problem_images.json"))

    try:
        matches = lib.find_matches(save_path)
    except ImportError as e:
        return {"error": str(e), "matches": []}

    sig = exif_signature(save_path)
    return {
        "exif": {str(k): v for k, v in sig.items()},
        "matches": matches,
        "lib_count": len(lib.load()),
    }


# ── API: 问题图片库管理 ──

@app.get("/api/library")
async def api_library():
    """查看问题库"""
    lib = _get_lib()
    return {"images": lib.load(), "count": len(lib.load())}


@app.post("/api/library/add")
async def api_library_add(files: List[UploadFile] = File(...)):
    """批量上传到问题库"""
    lib = _get_lib()
    added = []
    for f in files:
        sp = await _save_upload(f)
        lib_path = os.path.join(LIB_STORAGE, os.path.basename(sp))
        shutil.copy2(sp, lib_path)
        # 先做 ELA
        try:
            ela = ela_detect(sp)
            score = ela["tamper_score"]
            verdict = ela["verdict"]
        except Exception:
            score = 0
            verdict = "unknown"

        case_id = f"LIB-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
        ok = lib.add(case_id, f.filename or os.path.basename(sp), lib_path, score, verdict)
        if ok:
            added.append({"case_id": case_id, "name": f.filename, "score": score, "verdict": verdict})
    return {"added": added, "count": len(added)}


@app.delete("/api/library/remove")
async def api_library_remove(case_id: str = Query(...), original_name: str = Query(...)):
    """删除问题库条目"""
    lib = _get_lib()
    ok = lib.remove(case_id, original_name)
    if not ok:
        raise HTTPException(404, "未找到该条目")
    return {"removed": True}


# ── 静态文件 ──

@app.get("/uploads/{filename}")
async def serve_upload(filename: str):
    # 防目录穿越
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        return JSONResponse({"error": "invalid path"}, status_code=400)
    fp = os.path.join(UPLOAD_DIR, filename)
    real = os.path.realpath(fp)
    base = os.path.realpath(UPLOAD_DIR)
    if not real.startswith(base):
        return JSONResponse({"error": "invalid path"}, status_code=400)
    if os.path.exists(fp):
        return FileResponse(fp)
    return JSONResponse({"error": "not found"}, status_code=404)


# ═══════════════════════════════════════════════════════════
# 前端 HTML
# ═══════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index():
    path = _os.path.join(_TMPL_DIR, "index.html")
    if _os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            from fastapi.responses import HTMLResponse as _HR
            _c = f.read()
            resp = _HR(_c)
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            return resp
    return HTMLResponse("<h1>页面未找到</h1>")


HTML_PAGE = None  # served from file

import os as _os
_TMPL_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "templates")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="图像取证工具 - Web界面")
    parser.add_argument("--port", type=int, default=8505)
    parser.add_argument("--lib", type=str, default=None)
    args = parser.parse_args()

    if args.lib:
        p = os.path.abspath(args.lib)
        if os.path.exists(p): LIB_PATH = p
    else:
        default = os.path.join(BASE_DIR, "problem_images.json")
        if os.path.exists(default): LIB_PATH = default

    if LIB_PATH:
        lib = ProblemLibrary(LIB_PATH)
        print(f"问题库已加载 ({len(lib.load())} 条): {LIB_PATH}")

    print(f"启动: http://localhost:{args.port}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
