#!/usr/bin/env python3
"""用宝塔面板自己的代码登记 license-service 为 Python 项目（等价面板 UI"添加项目"），
   面板接管后旧 systemd unit 停用禁用，避免双管冲突。"""
import sys, os, traceback

sys.path.insert(0, "/www/server/panel/class")
sys.path.insert(0, "/www/server/panel")

VENV = "/www/server/pyporject_evn/venvs/license-service"
VENV_PY = VENV + "/bin/python3"
PROJECT = "/www/wwwroot/license-service"
PORT = "8765"


def main():
    import public
    from mod.project.python.pyenv_tool import EnvironmentManager

    em = EnvironmentManager()

    # 1) 基于面板 3.10.18 创建 venv
    py = None
    for e in em.all_env:
        if "pyporject_evn/versions/3.10.18" in e.bin_path:
            py = e
            break
    if not py:
        print("ERR: 找不到面板的 3.10.18 环境")
        return 1
    if not os.path.isfile(VENV_PY):
        print("创建 venv:", VENV)
        py.create_venv_sync(VENV, ps="license-service 项目环境", call_log=lambda s: print("   ", s))
    else:
        print("venv 已存在:", VENV)

    # 2) 注册环境到面板列表
    r = None
    for cand in (VENV, VENV + "/bin/python"):
        if not os.path.exists(cand):
            continue
        r = EnvironmentManager.add_python_env("venv", cand)
        print("注册环境", cand, "->", r if r else "OK")
        if not r:
            break
    if r:
        print("ERR: 环境注册失败:", r)
        return 1

    # 3) 安装依赖（国内源）
    import subprocess
    req = PROJECT + "/requirements.txt"
    print("安装依赖…")
    pr = subprocess.run(
        [VENV + "/bin/pip", "install", "-r", req,
         "-i", "https://mirrors.aliyun.com/pypi/simple", "--disable-pip-version-check", "-q"],
        capture_output=True, text=True, timeout=600)
    print("pip rc=", pr.returncode, pr.stderr[-300:] if pr.stderr else "")
    if pr.returncode != 0:
        print("ERR: pip 安装失败")
        return 1

    # 4) 等价 UI 的 CreateProject
    from projectModel.pythonModel import main as pyproj
    m = pyproj()

    get = public.dict_obj()
    get.pjname = "license-service"
    get.port = PORT
    get.stype = "command"
    get.path = PROJECT
    get.user = "root"
    get.python_bin = VENV + "/bin/python"
    get.requirement_path = req
    get.env_file = PROJECT + "/.env"
    get.env_list = []
    get.framework = "flask"
    get.project_cmd = f"{VENV}/bin/python -u {PROJECT}/app.py"
    get.initialize = ""
    get.call_app = "app"

    res = m.CreateProject(get)
    print("CreateProject ->", res)
    return 0


try:
    sys.exit(main())
except Exception:
    traceback.print_exc()
    sys.exit(1)
