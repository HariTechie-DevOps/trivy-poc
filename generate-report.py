#!/usr/bin/env python3
import json, argparse, os
from datetime import datetime

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--repo-report',  default=None)
    p.add_argument('--fs-report',    default=None)
    p.add_argument('--image-report', default=None)
    p.add_argument('--aws-report',   default=None)
    p.add_argument('--output',       default='trivy-report.html')
    p.add_argument('--app-name',     default='Application')
    p.add_argument('--build-number', default='N/A')
    p.add_argument('--image-name',   default='N/A')
    return p.parse_args()

def load_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

def get_stats(data):
    s = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0,"total":0}
    if not data:
        return s
    for r in data.get("Results",[]):
        for item in (r.get("Vulnerabilities") or []) + (r.get("Misconfigurations") or []) + (r.get("Secrets") or []):
            sev = item.get("Severity","UNKNOWN").upper()
            if sev in s:
                s[sev] += 1
                s["total"] += 1
    return s

def sev_badge(sev):
    colors = {"CRITICAL":"#FF4444","HIGH":"#FF8800","MEDIUM":"#FFCC00","LOW":"#44BB44","UNKNOWN":"#888888"}
    c = colors.get(sev,"#888888")
    txt_color = "#000" if sev == "MEDIUM" else "#fff"
    return f"<span style='background:{c};color:{txt_color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold'>{sev}</span>"

def build_rows(data):
    if not data:
        return "<tr><td colspan='6' style='text-align:center;color:#888;padding:20px'>No data / scan skipped</td></tr>"
    rows = ""
    found = False
    for r in data.get("Results",[]):
        target = r.get("Target","")
        for v in (r.get("Vulnerabilities") or []):
            found = True
            rows += f"<tr><td><code style='font-size:11px;color:#4A9EFF'>{target}</code></td><td>{v.get('PkgName','')}</td><td><a href='{v.get('PrimaryURL','#')}' target='_blank' style='color:#4A9EFF'>{v.get('VulnerabilityID','')}</a></td><td>{sev_badge(v.get('Severity','UNKNOWN'))}</td><td>{v.get('InstalledVersion','')}</td><td style='color:#44BB44'>{v.get('FixedVersion','No fix yet')}</td></tr>"
        for m in (r.get("Misconfigurations") or []):
            found = True
            rows += f"<tr><td><code style='font-size:11px;color:#4A9EFF'>{target}</code></td><td>Misconfiguration</td><td style='color:#FF8800'>{m.get('ID','')}</td><td>{sev_badge(m.get('Severity','UNKNOWN'))}</td><td colspan='2'>{m.get('Title','')}</td></tr>"
        for s in (r.get("Secrets") or []):
            found = True
            rows += f"<tr><td><code style='font-size:11px;color:#4A9EFF'>{target}</code></td><td style='color:#FF4444;font-weight:bold'>SECRET EXPOSED</td><td>-</td><td>{sev_badge('CRITICAL')}</td><td>{s.get('Category','')}</td><td>Rule: {s.get('RuleID','')}</td></tr>"
    if not found:
        rows = "<tr><td colspan='6' style='text-align:center;color:#44BB44;padding:20px'>✅ No issues found</td></tr>"
    return rows

def card(label, val, color):
    return f"<div style='background:{color}22;border:2px solid {color};border-radius:8px;padding:16px 20px;text-align:center;min-width:90px'><div style='font-size:28px;font-weight:bold;color:{color}'>{val}</div><div style='font-size:11px;color:#aaa;margin-top:2px'>{label}</div></div>"

def section(title, icon, stats, rows):
    sc = "#FF4444" if stats["CRITICAL"]>0 else "#FF8800" if stats["HIGH"]>0 else "#44BB44"
    st = "CRITICAL FOUND" if stats["CRITICAL"]>0 else "HIGH FOUND" if stats["HIGH"]>0 else "✅ CLEAN"
    return f"""
    <div style='background:#1A2035;border-radius:12px;padding:24px;margin-bottom:24px;border-left:4px solid {sc}'>
      <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px'>
        <h2 style='color:#E0E0FF;margin:0;font-size:18px'>{icon} {title}</h2>
        <span style='background:{sc};color:white;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:bold'>{st}</span>
      </div>
      <div style='display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px'>
        {card('CRITICAL',stats['CRITICAL'],'#FF4444')}
        {card('HIGH',stats['HIGH'],'#FF8800')}
        {card('MEDIUM',stats['MEDIUM'],'#FFCC00')}
        {card('LOW',stats['LOW'],'#44BB44')}
        {card('TOTAL',stats['total'],'#4A9EFF')}
      </div>
      <div style='overflow-x:auto'>
        <table style='width:100%;border-collapse:collapse;font-size:13px'>
          <thead><tr style='background:#0D1526;color:#888'>
            <th style='padding:10px;text-align:left;border-bottom:1px solid #333'>Target</th>
            <th style='padding:10px;text-align:left;border-bottom:1px solid #333'>Package / Type</th>
            <th style='padding:10px;text-align:left;border-bottom:1px solid #333'>CVE / ID</th>
            <th style='padding:10px;text-align:left;border-bottom:1px solid #333'>Severity</th>
            <th style='padding:10px;text-align:left;border-bottom:1px solid #333'>Installed</th>
            <th style='padding:10px;text-align:left;border-bottom:1px solid #333'>Fixed In</th>
          </tr></thead>
          <tbody style='color:#D0D0D0'>{rows}</tbody>
        </table>
      </div>
    </div>"""

def generate(args, repo, fs, image, aws):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rs  = get_stats(repo)
    fs_ = get_stats(fs)
    is_ = get_stats(image)
    as_ = get_stats(aws)
    tc  = rs["CRITICAL"] + fs_["CRITICAL"] + is_["CRITICAL"] + as_["CRITICAL"]
    th  = rs["HIGH"]     + fs_["HIGH"]     + is_["HIGH"]     + as_["HIGH"]
    gt  = rs["total"]    + fs_["total"]    + is_["total"]    + as_["total"]
    oc  = "#FF4444" if tc>0 else "#FF8800" if th>0 else "#44BB44"
    os_ = "🔴 CRITICAL FOUND" if tc>0 else "🟠 HIGH FOUND" if th>0 else "✅ ALL SCANS CLEAN"

    return f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Trivy Security Report — {args.app_name} #{args.build_number}</title>
<style>
  * {{box-sizing:border-box;margin:0;padding:0}}
  body {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0D1117;color:#C9D1D9;padding:24px}}
  table tr:nth-child(even) {{background:#0F1B2D}}
  table tr:hover {{background:#1C2E4A}}
  a {{text-decoration:none;color:#4A9EFF}}
  a:hover {{text-decoration:underline}}
  code {{background:#0D1526;padding:2px 6px;border-radius:4px}}
</style></head><body>
<div style='max-width:1300px;margin:0 auto'>

  <!-- HEADER -->
  <div style='background:linear-gradient(135deg,#1A2035,#0D1526);border-radius:16px;padding:32px;margin-bottom:24px;border:1px solid #2A3F5F'>
    <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px'>
      <div>
        <div style='color:#4A9EFF;font-size:11px;font-weight:700;letter-spacing:3px;margin-bottom:8px'>TRIVY SECURITY SCAN REPORT</div>
        <h1 style='color:#E0E0FF;font-size:26px;margin-bottom:6px'>{args.app_name}</h1>
        <div style='color:#888;font-size:13px'>
          Build <strong style='color:#C0C0FF'>#{args.build_number}</strong> &nbsp;•&nbsp;
          Image: <code>{args.image_name}</code> &nbsp;•&nbsp; {now}
        </div>
      </div>
      <div style='background:{oc}22;border:2px solid {oc};border-radius:12px;padding:20px 28px;text-align:center'>
        <div style='font-size:12px;color:{oc};font-weight:bold;margin-bottom:4px'>{os_}</div>
        <div style='font-size:42px;font-weight:bold;color:{oc}'>{gt}</div>
        <div style='font-size:11px;color:#888'>Total Issues Found</div>
      </div>
    </div>
  </div>

  <!-- SUMMARY CARDS -->
  <div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:24px'>
    <div style='background:#1A2035;border-radius:12px;padding:20px;border-top:3px solid #4A9EFF'>
      <div style='color:#888;font-size:11px;letter-spacing:1px;margin-bottom:10px'>📦 REPO SCAN</div>
      <div style='font-size:18px;font-weight:bold;color:#FF4444'>{rs["CRITICAL"]} Critical &nbsp;<span style='color:#FF8800'>{rs["HIGH"]} High</span></div>
      <div style='font-size:12px;color:#555;margin-top:6px'>{rs["total"]} total issues</div>
    </div>
    <div style='background:#1A2035;border-radius:12px;padding:20px;border-top:3px solid #4A9EFF'>
      <div style='color:#888;font-size:11px;letter-spacing:1px;margin-bottom:10px'>🗂️ FILESYSTEM SCAN</div>
      <div style='font-size:18px;font-weight:bold;color:#FF4444'>{fs_["CRITICAL"]} Critical &nbsp;<span style='color:#FF8800'>{fs_["HIGH"]} High</span></div>
      <div style='font-size:12px;color:#555;margin-top:6px'>{fs_["total"]} total issues</div>
    </div>
    <div style='background:#1A2035;border-radius:12px;padding:20px;border-top:3px solid #4A9EFF'>
      <div style='color:#888;font-size:11px;letter-spacing:1px;margin-bottom:10px'>🐳 DOCKER IMAGE SCAN</div>
      <div style='font-size:18px;font-weight:bold;color:#FF4444'>{is_["CRITICAL"]} Critical &nbsp;<span style='color:#FF8800'>{is_["HIGH"]} High</span></div>
      <div style='font-size:12px;color:#555;margin-top:6px'>{is_["total"]} total issues</div>
    </div>
    <div style='background:#1A2035;border-radius:12px;padding:20px;border-top:3px solid #555'>
      <div style='color:#888;font-size:11px;letter-spacing:1px;margin-bottom:10px'>☁️ AWS CLOUD SCAN</div>
      <div style='font-size:18px;font-weight:bold;color:#555'>{as_["CRITICAL"]} Critical &nbsp;{as_["HIGH"]} High</div>
      <div style='font-size:12px;color:#555;margin-top:6px'>Skipped in this run</div>
    </div>
  </div>

  <!-- SCAN SECTIONS -->
  {section('Repository Scan (Secrets + IaC + Deps)','📦', rs,  build_rows(repo))}
  {section('Filesystem Scan (Files + Configs)',     '🗂️', fs_, build_rows(fs))}
  {section('Docker Image Scan (OS + Packages)',     '🐳', is_, build_rows(image))}

  <!-- FOOTER -->
  <div style='text-align:center;color:#333;font-size:12px;padding:20px;margin-top:8px'>
    Generated by <strong style='color:#4A9EFF'>Trivy Security Scanner</strong> &nbsp;•&nbsp;
    {args.app_name} Build #{args.build_number} &nbsp;•&nbsp; {now}
  </div>
</div></body></html>"""

if __name__ == "__main__":
    args  = parse_args()
    repo  = load_json(args.repo_report)
    fs    = load_json(args.fs_report)
    image = load_json(args.image_report)
    aws   = load_json(args.aws_report)
    html  = generate(args, repo, fs, image, aws)
    with open(args.output, 'w') as f:
        f.write(html)
    print(f"✅ Report saved: {args.output}")
    for label, data in [("Repo",repo),("FS",fs),("Image",image),("AWS",aws)]:
        s = get_stats(data)
        print(f"  {label}: CRITICAL={s['CRITICAL']} HIGH={s['HIGH']} MEDIUM={s['MEDIUM']} LOW={s['LOW']} Total={s['total']}")
