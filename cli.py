"""
图像取证工具 - 命令行接口

用法:
  python -m tools.image_forensic_tool.cli check <image>                     # ELA检测
  python -m tools.image_forensic_tool.cli match <image> --lib <path>        # 底板比对
  python -m tools.image_forensic_tool.cli analyze <image> --lib <path>      # 全量分析
  python -m tools.image_forensic_tool.cli library-add <image> <case_id>     # 入库
  python -m tools.image_forensic_tool.cli library-list --lib <path>         # 查看库
  python -m tools.image_forensic_tool.cli compare <img1> <img2>             # 两图比较
"""

import sys
import os
import json
import argparse

from core import ela_detect, exif_signature, orb_match, ProblemLibrary


def cmd_check(args):
    """ELA篡改检测"""
    result = ela_detect(args.image)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"图片: {args.image}")
        print(f"篡改评分: {result['tamper_score']}")
        print(f"判定: {result['verdict']}")
        print(f"置信度: {result['confidence']}")
        print(f"异常块占比: {result['abnormal_ratio']}%")
        if result.get('ela_image_path'):
            print(f"ELA热力图: {result['ela_image_path']}")


def cmd_match(args):
    """底板比对 - 与问题库匹配"""
    lib = ProblemLibrary(args.lib or
                         os.path.join(os.path.dirname(__file__), "problem_images.json"))
    matches = lib.find_matches(args.image, exif_only=args.exif_only)
    if args.json:
        print(json.dumps(matches, ensure_ascii=False, indent=2))
    else:
        if matches:
            print(f"✅ 底板比对命中! ({len(matches)} match)")
            for m in matches:
                print(f"  项目: {m['case_id']}")
                print(f"  名称: {m['original_name']}")
                print(f"  方法: {m['method']}")
                print(f"  详情: {m['detail']}")
        else:
            print(f"❌ 未命中问题图片库")


def cmd_analyze(args):
    """全量分析: ELA检测 + 底板比对"""
    lib = ProblemLibrary(args.lib or
                         os.path.join(os.path.dirname(__file__), "problem_images.json")) if args.lib else None
    result = {
        "image": args.image,
        "ela": ela_detect(args.image),
        "exif": exif_signature(args.image),
        "matches": lib.find_matches(args.image) if lib else [],
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"=== 图像取证分析报告 ===")
        print(f"图片: {args.image}")
        print()
        print(f"【ELA篡改检测】")
        e = result['ela']
        print(f"  评分: {e['tamper_score']}/100")
        print(f"  判定: {e['verdict']}")
        print(f"  置信度: {e['confidence']}")
        print(f"  热力图: {e.get('ela_image_path', 'N/A')}")
        print()
        print(f"【EXIF元数据】")
        s = result['exif']
        if s.get(36867):
            print(f"  拍摄时间: {s[36867]}")
        if s.get("xmp_create_date"):
            print(f"  XMP时间戳: {s['xmp_create_date']}")
        print()
        print(f"【底板比对】{len(result['matches'])}条")
        for m in result['matches']:
            print(f"  ✅ {m['case_id']}({m['original_name']}) - {m['method']} - {m['detail']}")
        if not result['matches']:
            print(f"  ❌ 未命中")


def cmd_library_add(args):
    """添加图片到问题库"""
    lib = ProblemLibrary(args.lib or
                         os.path.join(os.path.dirname(__file__), "problem_images.json"))
    ela = ela_detect(args.image)
    ok = lib.add(args.case_id, args.name or os.path.basename(args.image),
                 args.image, ela['tamper_score'], ela['verdict'])
    if ok:
        print(f"✅ 已入库: {args.case_id}/{args.name or os.path.basename(args.image)}")
    else:
        print(f"⚠️ 已存在, 跳过")


def cmd_library_list(args):
    """列出问题库"""
    lib = ProblemLibrary(args.lib or
                         os.path.join(os.path.dirname(__file__), "problem_images.json"))
    images = lib.load()
    if not images:
        print("问题库为空")
        return
    print(f"问题图片库共 {len(images)} 条:")
    print(f"{'项目编号':<20} {'文件名':<18} {'ELA分数':<8} {'状态':<6}")
    print("-" * 55)
    for img in images:
        print(f"{img.get('case_id','?'):<20} {img.get('original_name','?'):<18} "
              f"{img.get('ela_score','?'):<8} {img.get('ela_result','?'):<6}")


def cmd_compare(args):
    """直接比较两张图片"""
    m = orb_match(args.img1, args.img2)
    sig1 = exif_signature(args.img1)
    sig2 = exif_signature(args.img2)

    if args.json:
        print(json.dumps({
            "image_a": args.img1,
            "image_b": args.img2,
            "exif_a": {str(k): v for k, v in sig1.items()},
            "exif_b": {str(k): v for k, v in sig2.items()},
            "orb": m,
        }, ensure_ascii=False, indent=2))
    else:
        x1 = sig1.get("xmp_create_date") or sig1.get(36867)
        x2 = sig2.get("xmp_create_date") or sig2.get(36867)
        print(f"图A: {args.img1}")
        print(f"图B: {args.img2}")
        print(f"EXIF匹配: {'✅' if x1 and x2 and x1 == x2 else '❌'} "
              f"(A={x1}, B={x2})")
        ratio = m.get('inlier_ratio', 0)
        same = ratio > ORB_INLIER_THRESHOLD if 'ORB_INLIER_THRESHOLD' in dir() else ratio > 0.02
        print(f"ORB匹配: {'✅ 同一底板' if same else '❌ 不同底板'} "
              f"(内点率={ratio*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="图像取证工具")
    parser.add_argument("--json", action="store_true", help="JSON格式输出")
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="ELA篡改检测")
    p_check.add_argument("image")

    p_match = sub.add_parser("match", help="底板比对")
    p_match.add_argument("image")
    p_match.add_argument("--lib", help="问题库路径")
    p_match.add_argument("--exif-only", action="store_true", help="仅用EXIF")

    p_analyze = sub.add_parser("analyze", help="全量分析")
    p_analyze.add_argument("image")
    p_analyze.add_argument("--lib", help="问题库路径")

    p_add = sub.add_parser("library-add", help="入库")
    p_add.add_argument("image")
    p_add.add_argument("case_id")
    p_add.add_argument("--name", help="文件原名")
    p_add.add_argument("--lib", help="问题库路径")

    p_list = sub.add_parser("library-list", help="查看库")
    p_list.add_argument("--lib", help="问题库路径")

    p_cmp = sub.add_parser("compare", help="两图比较")
    p_cmp.add_argument("img1")
    p_cmp.add_argument("img2")

    args = parser.parse_args()

    if args.command == "check":
        cmd_check(args)
    elif args.command == "match":
        cmd_match(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "library-add":
        cmd_library_add(args)
    elif args.command == "library-list":
        cmd_library_list(args)
    elif args.command == "compare":
        cmd_compare(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    # Allow standalone: python core.py ...
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    main()
