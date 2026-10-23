#!/usr/bin/env python3
"""S23 debug: reproduce the sbsigntool build with the tool's own aux/pre-build seam."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/work/forensics/tools")
import downstream_build_link as bl  # noqa: E402

root = Path("/work/court/tmp/s23x/sbsigntool-0.9.4")
work = Path("/work/court/tmp/s23dbg/sbsigntool")
prefix = Path("/work/forensics/authorities/prefix/openssl-3.6.4-production")
shutil.rmtree(work, ignore_errors=True)
work.mkdir(parents=True)
recipe = bl._RECIPE_BY_FAMILY["sbsigntool"]
aux, err = bl._prepare_aux(recipe, work)
print("aux", aux, err)
aux_root = work / "aux" / "root"
env = dict(os.environ, PKG_CONFIG_PATH=f"{prefix}/lib/pkgconfig",
           CPPFLAGS=f"-I{prefix}/include", LDFLAGS=f"-L{prefix}/lib",
           PATH=str(aux_root / "usr/bin") + ":" + os.environ["PATH"],
           LD_LIBRARY_PATH=f"{prefix}/lib:{aux_root}/usr/lib/x86_64-linux-gnu")
for key, val in (recipe.get("env_extra") or {}).items():
    env[key] = str(val).format(prefix=prefix, root=root, aux=aux_root, repo=bl.REPO_ROOT)
for d in aux.get("include_dirs") or []:
    env["CPPFLAGS"] += f" -I{d}"
for d in aux.get("library_dirs") or []:
    env["LDFLAGS"] += f" -L{d}"
for d in aux.get("pkgconfig_dirs") or []:
    env["PKG_CONFIG_PATH"] = f"{d}:{env['PKG_CONFIG_PATH']}"
for step in recipe.get("pre_build") or []:
    argv = [str(a).format(prefix=prefix, root=root, aux=aux_root, repo=bl.REPO_ROOT)
            for a in step]
    res = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)
    print("PRE", argv[0], res.returncode)
    if res.returncode:
        print(res.stdout[-2000:], res.stderr[-4000:])
        raise SystemExit(1)
conf = subprocess.run(["./configure", f"--prefix={root}/.l7-install"], cwd=root, env=env,
                      capture_output=True, text=True)
print("CONF", conf.returncode)
if conf.returncode:
    print(conf.stdout[-2000:], conf.stderr[-4000:])
    raise SystemExit(1)
mk = subprocess.run(["make", "-j4"], cwd=root, env=env, capture_output=True, text=True)
print("MAKE", mk.returncode)
print(mk.stdout[-3000:])
print(mk.stderr[-8000:])
