# 图像防伪工具 v1.0

图片 PS 篡改检测（ELA）+ 底板比对查重（EXIF/ORB）+ 问题图片库

## 功能

| 功能 | 说明 |
|------|------|
| **图片篡改识别** | 上传图片，ELA 检测篡改痕迹，返回评分/判定/置信度/热力图。可疑或篡改自动入库。 |
| **图片查重检测** | 两张图对比 或 与问题库对比，基于 EXIF 时间戳 + ORB 特征匹配判断是否同一底板。 |
| **问题图片库** | 管理可疑/篡改图片，支持批量上传、查看、删除。 |

## 安装

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动 Web 界面
python web_app.py --port 8505

# 3. 打开浏览器
# http://localhost:8505
```

## 分数与判定标准

| 评分 | 判定 | 说明 |
|------|------|------|
| 0-9 | 正常 | 无篡改信号 |
| 10-24 | 可疑 | 存在局部修改可能 |
| ≥25 | 篡改 | 明确窜改 |

**置信度**（交叉验证）：
- **高** → ELA + 边缘方向一致性 均确认窜改
- **中** → 仅 ELA 检测到异常
- **正常** → 无异常

**查重标准**：
- EXIF：同一 XMP CreateDate / DateTimeOriginal
- ORB：内点率 > 2% → 同一底板（实测同一底板最低 13%，不同底板最高 0.2%）

## 命令行工具

```bash
# ELA 检测
python cli.py check 照片.jpg

# 两张图片对比
python cli.py compare 图1.jpg 图2.jpg

# 与问题库比对
python cli.py match 照片.jpg --lib 问题库.json

# 全量分析
python cli.py analyze 照片.jpg --lib 问题库.json
```

## Web 界面

```bash
python web_app.py --port 8505 --lib 问题库.json
```

默认端口 8505，打开 http://localhost:8505

## 安全说明

- 仅接受图片格式（jpg/png/bmp/webp），最大 10MB
- 上传文件以 UUID 重命名存储，防止路径遍历
- 文件路径经过 realpath 校验，防止目录穿越
- 无外部网络请求，纯本地运算
- 无数据库，数据存储在本地 JSON 文件
