#!/bin/bash
# license-service 开机自启（本面板版本 Python 项目管理无自启选项，
# 用 cron @reboot 调用面板启动接口，幂等：已在跑则跳过）
sleep 15
ss -tln | grep -q ':8765' && exit 0
/www/server/panel/pyenv/bin/python3 - <<'EOF'
import sys
sys.path.insert(0, "/www/server/panel/class")
sys.path.insert(0, "/www/server/panel")
import public
from projectModel.pythonModel import main as pyproj
m = pyproj()
get = public.dict_obj()
get.name = "license-service"
if m.get_project_find("license-service"):
    m.StartProject(get)
EOF
