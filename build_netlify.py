#!/usr/bin/env python3
"""
build_netlify.py - Static Stlite Export Builder for Netlify Deployment
AI-Based Network Intrusion Detection System

Automates the compilation and static export of the Streamlit NIDS application
into a WebAssembly-powered distribution directory (`dist/`) using @stlite/mountable.
Zero external build dependencies required (runs with Python standard library).
"""

import os
import sys
import json
import shutil
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent
DIST_DIR = ROOT_DIR / "dist"

def build():
    print("=" * 70)
    print("[*] AI-BASED NETWORK INTRUSION DETECTION SYSTEM - NETLIFY BUILDER")
    print("=" * 70)

    # 1. Clean and initialize dist directory
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[*] Initialized clean distribution directory: {DIST_DIR}")

    files_map = {}

    # 2. Collect core Python code and configuration files
    core_text_files = [
        "app.py",
        "nids_engine.py",
        "data_manager.py",
        "se_tools_dashboard.py",
        "sample_network_traffic.csv",
        "jira_backlog_import.csv",
        "Dockerfile",
        "README.md",
        ".streamlit/config.toml"
    ]

    # Documentation directories to package into virtual filesystem
    doc_dirs = ["confluence_docs", "figma_specs", "k8s"]

    # Read and copy core text files
    for rel_path_str in core_text_files:
        src_path = ROOT_DIR / rel_path_str
        if src_path.exists():
            dest_path = DIST_DIR / rel_path_str
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)
            try:
                with open(src_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    # Store with forward slashes for Pyodide virtual filesystem
                    vpath = rel_path_str.replace("\\", "/")
                    files_map[vpath] = content
                    print(f"  [+] Packaged file: {vpath} ({len(content):,} chars)")
            except Exception as e:
                print(f"  [!] Warning reading {rel_path_str}: {e}")
        else:
            print(f"  [!] Note: Optional file not found: {rel_path_str}")

    # Read and copy directory assets
    for dname in doc_dirs:
        dir_path = ROOT_DIR / dname
        if dir_path.exists() and dir_path.is_dir():
            for item in dir_path.rglob("*"):
                if item.is_file() and not item.name.startswith("."):
                    rel_p = item.relative_to(ROOT_DIR)
                    dest_p = DIST_DIR / rel_p
                    dest_p.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest_p)
                    try:
                        with open(item, "r", encoding="utf-8") as f:
                            content = f.read()
                            vpath = str(rel_p).replace("\\", "/")
                            files_map[vpath] = content
                            print(f"  [+] Packaged doc: {vpath}")
                    except Exception:
                        pass

    # 3. Handle official User Manual PDF
    manual_filename = "AI-BASED NETWORK INTRUSION DETECTION SYSTEM USER MANUAL.pdf"
    manual_src = ROOT_DIR / manual_filename
    if not manual_src.exists():
        alt = ROOT_DIR / "assets" / manual_filename
        if alt.exists():
            manual_src = alt
        elif (ROOT_DIR / "NIDS_User_Manual.pdf").exists():
            manual_src = ROOT_DIR / "NIDS_User_Manual.pdf"

    if manual_src.exists():
        manual_size = manual_src.stat().st_size
        dest_pdf = DIST_DIR / manual_filename
        dest_pdf.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manual_src, dest_pdf)

        shutil.copy2(manual_src, DIST_DIR / "NIDS_User_Manual.pdf")
        
        assets_dest = DIST_DIR / "assets" / manual_filename
        assets_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manual_src, assets_dest)

        url_encoded_name = manual_filename.replace(" ", "%20")
        files_map[manual_filename] = {"url": f"./{url_encoded_name}"}
        files_map["NIDS_User_Manual.pdf"] = {"url": "./NIDS_User_Manual.pdf"}
        files_map[f"assets/{manual_filename}"] = {"url": f"./{url_encoded_name}"}
        print(f"  [+] Mounted static User Manual PDF: {manual_filename} ({manual_size:,} bytes)")
    else:
        print("  [!] Warning: Official User Manual PDF not found in source directory.")

    # 4. Create Netlify redirect rules file (_redirects)
    redirects_content = "/*    /index.html   200\n"
    with open(DIST_DIR / "_redirects", "w", encoding="utf-8") as f:
        f.write(redirects_content)
    print("  [+] Created Netlify SPA redirect: dist/_redirects")

    # 5. Serialize files mapping safely for HTML inclusion
    json_str = json.dumps(files_map, indent=None)
    # Prevent HTML script tag breakage
    safe_json_str = json_str.replace("</script>", "<\\/script>").replace("<!--", "<\\!--")

    # 6. Generate production index.html powered by @stlite/mountable
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <meta name="theme-color" content="#0b1714" />
  <title>AI-Based Network Intrusion Detection System</title>
  
  <!-- Favicon -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
  
  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@600;700;800&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  
  <!-- @stlite/mountable styling -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@stlite/mountable@0.73.1/build/stlite.css" />
  
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      background-color: #0b1714;
      color: #e0e6ed;
      font-family: 'Plus Jakarta Sans', sans-serif;
      overflow-x: hidden;
      min-height: 100vh;
    }}
    #root {{
      min-height: 100vh;
      background-color: #0b1714;
    }}
    
    /* Executive Emerald & Champagne Gold Preloader */
    #loading-screen {{
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: radial-gradient(circle at 50% 25%, #10332c 0%, #0d2320 40%, #0b1714 85%);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      transition: opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1), visibility 0.6s;
      text-align: center;
      padding: 2rem;
    }}
    .loader-card {{
      background: #102621;
      border: 1.5px solid #e2b96f;
      border-radius: 20px;
      padding: 2.8rem 2.4rem;
      max-width: 580px;
      width: 100%;
      box-shadow: 0 16px 45px rgba(0, 0, 0, 0.7), 0 0 25px rgba(226, 185, 111, 0.25);
      display: flex;
      flex-direction: column;
      align-items: center;
    }}
    .shield-icon {{
      font-size: 3rem;
      margin-bottom: 1.2rem;
      animation: pulse 2s infinite alternate ease-in-out;
    }}
    @keyframes pulse {{
      0% {{ transform: scale(1); filter: drop-shadow(0 0 10px rgba(226, 185, 111, 0.4)); }}
      100% {{ transform: scale(1.08); filter: drop-shadow(0 0 24px rgba(226, 185, 111, 0.8)); }}
    }}
    .spinner-ring {{
      width: 52px;
      height: 52px;
      border: 3.5px solid #1a3c34;
      border-top: 3.5px solid #e2b96f;
      border-radius: 50%;
      animation: spin 0.9s linear infinite;
      margin-bottom: 1.5rem;
    }}
    @keyframes spin {{
      0% {{ transform: rotate(0deg); }}
      100% {{ transform: rotate(360deg); }}
    }}
    .loader-title {{
      font-family: 'Cinzel', serif;
      font-size: 1.35rem;
      font-weight: 800;
      color: #e2b96f;
      letter-spacing: 0.04em;
      margin-bottom: 0.75rem;
      line-height: 1.3;
    }}
    .loader-subtitle {{
      color: #cbd5e1;
      font-size: 0.9rem;
      line-height: 1.6;
      margin-bottom: 1.4rem;
    }}
    .badge-row {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: center;
    }}
    .badge-pill {{
      background: #0d2320;
      border: 1px solid #2d6a4f;
      color: #5eead4;
      font-size: 0.75rem;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 9999px;
      letter-spacing: 0.04em;
    }}
    .badge-pill.gold {{
      border-color: #e2b96f;
      color: #e2b96f;
    }}
  </style>
</head>
<body>
  <!-- Preloader Screen -->
  <div id="loading-screen">
    <div class="loader-card">
      <div class="shield-icon">🛡️</div>
      <div class="spinner-ring"></div>
      <h2 class="loader-title">AI-BASED NETWORK INTRUSION DETECTION SYSTEM</h2>
      <p class="loader-subtitle" id="status-text">
        Initializing WebAssembly Pyodide runtime & compiling Random Forest classifier...
      </p>
      <div class="badge-row">
        <span class="badge-pill gold">⚡ Netlify Edge</span>
        <span class="badge-pill">⚙️ WebAssembly Pyodide</span>
        <span class="badge-pill">🤖 Scikit-Learn</span>
        <span class="badge-pill">🔒 Client-Side RBAC</span>
      </div>
    </div>
  </div>

  <!-- Streamlit Container -->
  <div id="root"></div>

  <!-- Embedded Static Source Files -->
  <script type="application/json" id="stlite-vfs-data">
{safe_json_str}
  </script>

  <!-- Load Stlite Engine -->
  <script src="https://cdn.jsdelivr.net/npm/@stlite/mountable@0.73.1/build/stlite.js"></script>
  
  <script>
    (function() {{
      const statusText = document.getElementById("status-text");
      const loadingScreen = document.getElementById("loading-screen");

      // Parse Virtual Filesystem data
      const filesElement = document.getElementById("stlite-vfs-data");
      let vfsFiles = {{}};
      try {{
        vfsFiles = JSON.parse(filesElement.textContent);
      }} catch (err) {{
        console.error("Error reading Virtual Filesystem:", err);
      }}

      // Periodic check to dismiss preloader as soon as Streamlit finishes mounting
      const dismissInterval = setInterval(() => {{
        const appElem = document.querySelector("#root .stApp") || 
                        document.querySelector("#root [data-testid='stAppViewContainer']");
        if (appElem) {{
          if (loadingScreen) {{
            loadingScreen.style.opacity = "0";
            setTimeout(() => {{
              loadingScreen.style.display = "none";
            }}, 600);
          }}
          clearInterval(dismissInterval);
        }}
      }}, 250);

      // Mount Streamlit via Stlite
      stlite.mount({{
        entrypoint: "app.py",
        requirements: [
          "scikit-learn",
          "pandas",
          "numpy",
          "plotly"
        ],
        files: vfsFiles,
        streamlitConfig: {{
          "theme.primaryColor": "#E2B96F",
          "theme.backgroundColor": "#0B1714",
          "theme.secondaryBackgroundColor": "#102621",
          "theme.textColor": "#E0E6ED"
        }}
      }}, document.getElementById("root")).catch((err) => {{
        console.error("Stlite mount error:", err);
        if (statusText) {{
          statusText.innerHTML = "<span style='color:#ef4444;'>Initialization error. Check console for details.</span>";
        }}
      }});
    }})();
  </script>
</body>
</html>
"""
    with open(DIST_DIR / "index.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("  [+] Generated production Stlite HTML: dist/index.html")

    print("=" * 70)
    print("[SUCCESS] NETLIFY STATIC BUILD COMPLETED SUCCESSFULLY!")
    print(f"[*] Publish directory ready: '{DIST_DIR.name}/'")
    print("=" * 70)

if __name__ == "__main__":
    build()
