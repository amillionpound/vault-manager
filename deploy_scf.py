#!/usr/bin/env python3
"""
Deploy to Tencent Cloud SCF (Serverless Cloud Function).
Called by GitHub Actions workflow.

Reused across projects — each repo has a .scf-deploy.json config:
  {
    "function_name": "vlt-mgr",
    "namespace": "default",
    "region": "ap-guangzhou",
    "files": ["app.py", "index.html", "scf_bootstrap", "requirements.txt", "static/jsqr.js", "static/qrcode.min.js"],
    "deps": ["flask>=3.0", "Werkzeug>=3.0", "Jinja2>=3.1"],
    "runtime": "Python3.10"
  }

Required env vars (from GitHub Secrets):
  TENCENT_SECRET_ID
  TENCENT_SECRET_KEY
"""

import base64
import json
import os
import stat
import subprocess
import sys
import zipfile

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.scf.v20180416 import scf_client
from tencentcloud.scf.v20180416 import models as scf_models


def load_config():
    """Load deploy config from .scf-deploy.json, fall back to env vars."""
    config_path = ".scf-deploy.json"
    cfg = {
        "function_name": os.environ.get("SCF_FUNCTION_NAME", ""),
        "namespace": "default",
        "region": "ap-guangzhou",
        "files": ["app.py", "index.html", "scf_bootstrap"],
        "deps": [],
    }
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            file_cfg = json.load(f)
        cfg.update(file_cfg)

    if not cfg["function_name"]:
        print("ERROR: function_name not set. Create .scf-deploy.json or set SCF_FUNCTION_NAME env var.")
        sys.exit(1)

    return cfg


def install_deps(deps, vendor_dir="vendor"):
    """Install Python dependencies into vendor_dir for bundling."""
    if not deps:
        return
    if os.path.exists(vendor_dir):
        import shutil
        shutil.rmtree(vendor_dir)
    os.makedirs(vendor_dir)
    print(f"Installing dependencies: {', '.join(deps)}")
    subprocess.run(
        [sys.executable, "-m", "pip", "install"] + deps + ["--target", vendor_dir],
        check=True,
        capture_output=True,
    )
    print(f"  Dependencies installed to {vendor_dir}/")


def get_function_info(client, cfg, label=""):
    """Print function details for debugging."""
    try:
        req = scf_models.GetFunctionRequest()
        req.FunctionName = cfg["function_name"]
        req.Namespace = cfg.get("namespace", "default")
        resp = client.GetFunction(req)
        print(f"--- Function Info {label} ---")
        print(f"  Handler: {resp.Handler}")
        print(f"  Runtime: {resp.Runtime}")
        print(f"  Type: {resp.Type}")
        print(f"  Status: {resp.Status}")
        print(f"  CodeSize: {resp.CodeSize}")
    except Exception as e:
        print(f"  GetFunction failed: {e}")


def list_triggers(client, cfg):
    """List API Gateway triggers and their qualifiers."""
    try:
        req = scf_models.ListTriggersRequest()
        req.FunctionName = cfg["function_name"]
        req.Namespace = cfg.get("namespace", "default")
        resp = client.ListTriggers(req)
        print("--- Triggers ---")
        if not resp.Triggers:
            print("  No triggers found")
        for t in resp.Triggers:
            print(f"  Type: {t.Type} | Name: {t.TriggerName} | Qualifier: {getattr(t, 'Qualifier', 'N/A')} | Enable: {t.Enable}")
    except Exception as e:
        print(f"  ListTriggers failed: {e}")


def main():
    secret_id = os.environ.get("TENCENT_SECRET_ID")
    secret_key = os.environ.get("TENCENT_SECRET_KEY")

    if not secret_id or not secret_key:
        print("ERROR: TENCENT_SECRET_ID and TENCENT_SECRET_KEY must be set")
        sys.exit(1)

    cfg = load_config()

    # Install dependencies into vendor/ directory
    install_deps(cfg.get("deps", []))

    # Create deployment zip
    zip_path = "deploy.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in cfg["files"]:
            if os.path.exists(f):
                if f == "scf_bootstrap":
                    # scf_bootstrap needs execute permission (0o755)
                    with open(f, "rb") as fh:
                        data = fh.read()
                    info = zipfile.ZipInfo(f)
                    info.external_attr = (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(info, data)
                    print(f"  Added: {f} (chmod 755)")
                else:
                    z.write(f)
                    print(f"  Added: {f}")
            else:
                print(f"  WARNING: {f} not found, skipping")

        # Add vendored dependencies
        vendor_dir = "vendor"
        if os.path.isdir(vendor_dir):
            for root, dirs, files in os.walk(vendor_dir):
                for fname in files:
                    full_path = os.path.join(root, fname)
                    arc_path = os.path.relpath(full_path, ".")
                    z.write(full_path, arc_path)
            dep_count = sum(len(files) for _, _, files in os.walk(vendor_dir))
            print(f"  Added: {dep_count} dependency files from {vendor_dir}/")

    with open(zip_path, "rb") as f:
        zip_b64 = base64.b64encode(f.read()).decode("utf-8")

    print(f"Deploy package: {os.path.getsize(zip_path)} bytes")
    print(f"Function: {cfg['function_name']} (ns={cfg['namespace']}, region={cfg['region']})")

    try:
        cred = credential.Credential(secret_id, secret_key)
        client = scf_client.ScfClient(cred, cfg["region"])

        get_function_info(client, cfg, "(BEFORE update)")
        list_triggers(client, cfg)

        # Update function code
        # Do NOT set Handler for HTTP-type (Web Function)
        req = scf_models.UpdateFunctionCodeRequest()
        req.FunctionName = cfg["function_name"]
        req.Namespace = cfg["namespace"]
        req.ZipFile = zip_b64

        resp = client.UpdateFunctionCode(req)
        print(f"DEPLOY SUCCESS: RequestId={resp.RequestId}")

        # Wait for function to become Active
        import time
        def wait_active(label, max_retries=12):
            for i in range(max_retries):
                time.sleep(5)
                try:
                    check_req = scf_models.GetFunctionRequest()
                    check_req.FunctionName = cfg["function_name"]
                    check_req.Namespace = cfg["namespace"]
                    check_resp = client.GetFunction(check_req)
                    status = check_resp.Status
                    print(f"  {label} check ({i+1}/{max_retries}): {status}")
                    if status == "Active":
                        return True
                except Exception:
                    pass
            return False

        wait_active("post-code")

        # Update runtime if specified (e.g., upgrade from Python36 to Python310)
        desired_runtime = cfg.get("runtime")
        if desired_runtime:
            try:
                cfg_req = scf_models.UpdateFunctionConfigurationRequest()
                cfg_req.FunctionName = cfg["function_name"]
                cfg_req.Namespace = cfg["namespace"]
                cfg_req.Runtime = desired_runtime
                cfg_resp = client.UpdateFunctionConfiguration(cfg_req)
                print(f"Runtime updated to {desired_runtime}: RequestId={cfg_resp.RequestId}")
                wait_active("post-runtime")
            except Exception as e:
                print(f"Runtime update skipped: {e}")

        get_function_info(client, cfg, "(AFTER update)")

        # Publish a new version
        try:
            ver_req = scf_models.PublishVersionRequest()
            ver_req.FunctionName = cfg["function_name"]
            ver_req.Namespace = cfg["namespace"]
            ver_resp = client.PublishVersion(ver_req)
            print(f"Published version: {ver_resp.FunctionVersion}")
        except Exception as e:
            print(f"Version publish skipped: {e}")

        list_triggers(client, cfg)

    except TencentCloudSDKException as e:
        print(f"DEPLOY FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
