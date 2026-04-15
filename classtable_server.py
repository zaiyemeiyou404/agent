"""
西小豆课表查询后端服务
基于 XDYou 项目的课表查询原理实现

使用方法：
1. 安装依赖：pip install flask flask-cors requests pillow numpy pycryptodome
2. 运行服务：python classtable_server.py
3. 服务将在 http://localhost:5000 启动
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re
import json
import base64
import io
from datetime import datetime, timedelta
from html.parser import HTMLParser

# 图像处理
try:
    from PIL import Image
    import numpy as np
    HAS_IMAGE_LIBS = True
except ImportError:
    HAS_IMAGE_LIBS = False
    print("警告: 未安装 pillow/numpy，滑块验证码自动破解不可用")

# AES 加密
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("警告: 未安装 pycryptodome，密码加密不可用")

app = Flask(__name__)
CORS(app)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════
# HTML 表单解析器
# ═══════════════════════════════════════════════════════════════

class HiddenInputParser(HTMLParser):
    """提取 HTML 中所有 hidden input 的 name/value"""
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.pwd_salt = ""

    def handle_starttag(self, tag, attrs):
        if tag != 'input':
            return
        d = dict(attrs)
        if d.get('type') == 'hidden' and 'name' in d:
            self.fields[d['name']] = d.get('value', '')
        if d.get('id') == 'pwdEncryptSalt':
            self.pwd_salt = d.get('value', '')


# ═══════════════════════════════════════════════════════════════
# 滑块验证码破解（NCC 模板匹配，移植自 XDYou）
# ═══════════════════════════════════════════════════════════════

class SliderCaptchaSolver:
    CAPTCHA_URL = "https://ids.xidian.edu.cn/authserver/common/openSliderCaptcha.htl"
    VERIFY_URL = "https://ids.xidian.edu.cn/authserver/common/verifySliderCaptcha.htl"
    PUZZLE_WIDTH = 280

    def __init__(self, session: requests.Session):
        self.session = session

    def solve(self, max_retry: int = 15) -> bool:
        if not HAS_IMAGE_LIBS:
            return False
        for i in range(max_retry):
            try:
                puzzle_data, piece_data = self._get_captcha()
                if puzzle_data is None:
                    continue
                answer = self._calculate_position(puzzle_data, piece_data)
                if answer is not None and self._verify(answer):
                    print(f"  验证码破解成功 (第{i+1}次)")
                    return True
            except Exception as e:
                print(f"  验证码尝试{i+1}失败: {e}")
        return False

    def _get_captcha(self):
        resp = self.session.get(
            self.CAPTCHA_URL,
            params={'_': str(int(datetime.now().timestamp() * 1000))},
            timeout=10, verify=False
        )
        data = resp.json()
        b = data.get("bigImage", "")
        s = data.get("smallImage", "")
        if not b or not s:
            return None, None
        return base64.b64decode(b), base64.b64decode(s)

    def _calculate_position(self, puzzle_data, piece_data, border=24):
        puzzle = Image.open(io.BytesIO(puzzle_data)).convert('RGBA')
        piece = Image.open(io.BytesIO(piece_data)).convert('RGBA')
        piece_np = np.array(piece)

        alpha = piece_np[:, :, 3]
        rows = np.any(alpha == 255, axis=1)
        cols = np.any(alpha == 255, axis=0)
        if not rows.any() or not cols.any():
            return None

        yT, yB = np.where(rows)[0][[0, -1]]
        xL, xR = np.where(cols)[0][[0, -1]]
        xL += border; yT += border; xR -= border; yB -= border
        if xL >= xR or yT >= yB:
            return None

        w, h = xR - xL, yB - yT
        puzzle_gray = np.array(puzzle.convert('L'), dtype=np.float64)
        piece_gray = np.array(piece.convert('L'), dtype=np.float64)

        template = piece_gray[yT:yB, xL:xR]
        template_norm = template - np.mean(template)

        best_score, best_x = -1, 0
        width_g = puzzle.width - piece.width + w - 1

        for x in range(xL + 1, width_g - w, 2):
            window = puzzle_gray[yT:yB, x:x + w]
            window_norm = window - np.mean(window)
            ncc = np.sum(window_norm * template_norm) / (np.sqrt(np.sum(window_norm ** 2)) + 1e-6)
            if ncc > best_score:
                best_score = ncc
                best_x = x

        return (best_x - xL - 1) / puzzle.width

    def _verify(self, answer):
        move = int(answer * self.PUZZLE_WIDTH)
        resp = self.session.post(
            self.VERIFY_URL,
            data=f"canvasLength={self.PUZZLE_WIDTH}&moveLength={move}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
                "Origin": "https://ids.xidian.edu.cn",
                "Referer": "https://ids.xidian.edu.cn/authserver/login"
            },
            timeout=10, verify=False
        )
        return resp.json().get("errorCode") == 1


# ═══════════════════════════════════════════════════════════════
# AES 密码加密（与 XDYou ids_session.dart 一致）
# ═══════════════════════════════════════════════════════════════

def aes_encrypt(password: str, salt: str) -> str:
    """AES-CBC 加密密码，IV 固定为 xidianscriptsxdu"""
    if not HAS_CRYPTO or not salt:
        return password
    try:
        iv = b"xidianscriptsxdu"
        key = salt.encode('utf-8')
        # 前缀与 XDYou 一致
        prefix = "xidianscriptsxdu" * 4
        data = (prefix + password).encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"  AES加密失败: {e}，使用明文")
        return password


# ═══════════════════════════════════════════════════════════════
# IDS 统一身份认证（完整移植 XDYou 流程）
# ═══════════════════════════════════════════════════════════════

class IDSSession:
    IDS_LOGIN_URL = "https://ids.xidian.edu.cn/authserver/login"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/130.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
        })
        self.session.verify = False

    def login(self, username: str, password: str, service: str = None) -> dict:
        """完整 IDS 登录流程"""
        try:
            login_url = self.IDS_LOGIN_URL
            if service:
                login_url = f"{self.IDS_LOGIN_URL}?service={service}"

            print(f"[IDS] 获取登录页面: {login_url}")
            resp = self.session.get(login_url, timeout=15, allow_redirects=False)
            print(f"[IDS] 响应状态码: {resp.status_code}")

            # 如果直接 302，说明已有有效 session
            if resp.status_code in (301, 302):
                location = resp.headers.get('Location', '')
                print(f"[IDS] 已有session，直接跳转: {location}")
                self._follow_redirects(location)
                return {"success": True, "message": "登录成功"}

            if resp.status_code == 401:
                return {"success": False, "message": "账号或密码错误"}

            # 解析登录页面
            html = resp.text
            parser = HiddenInputParser()
            parser.feed(html)

            print(f"[IDS] 加密盐: {parser.pwd_salt[:8]}... (长度:{len(parser.pwd_salt)})")
            print(f"[IDS] 表单字段: {list(parser.fields.keys())}")

            # AES 加密密码
            encrypted_pwd = aes_encrypt(password, parser.pwd_salt)
            print(f"[IDS] 密码已加密，长度: {len(encrypted_pwd)}")

            # 构造登录表单
            form_data = parser.fields.copy()
            form_data.update({
                'username': username,
                'password': encrypted_pwd,
                'rememberMe': 'true',
                'cllt': 'userNameLogin',
                'dllt': 'generalLogin',
                '_eventId': 'submit',
            })

            # 西电 IDS 总是需要滑块验证码
            print(f"[IDS] 获取滑块验证码...")
            solver = SliderCaptchaSolver(self.session)
            if not solver.solve():
                return {"success": False, "message": "验证码破解失败，请稍后重试"}

            # 提交登录
            print(f"[IDS] 提交登录表单...")
            resp = self.session.post(
                login_url,
                data=form_data,
                allow_redirects=False,
                timeout=20
            )
            print(f"[IDS] 登录响应状态码: {resp.status_code}")

            # 检查结果
            if resp.status_code in (301, 302):
                location = resp.headers.get('Location', '')
                print(f"[IDS] 登录成功，跟随重定向: {location[:80]}...")
                self._follow_redirects(location)
                return {"success": True, "message": "登录成功"}

            if resp.status_code == 401:
                # 尝试解析具体错误信息
                text = resp.text
                if "showErrorTip" in text:
                    import re
                    match = re.search(r'id="showErrorTip"[^>]*>([^<]+)', text)
                    if match:
                        error_msg = match.group(1).strip()
                        print(f"[IDS] 错误信息: {error_msg}")
                        return {"success": False, "message": error_msg}
                return {"success": False, "message": "账号或密码错误"}

            # 200 - 检查页面内容
            text = resp.text
            print(f"[IDS] 响应内容长度: {len(text)}")

            # 检查错误提示
            if "showErrorTip" in text:
                import re
                match = re.search(r'id="showErrorTip"[^>]*>([^<]+)', text)
                if match:
                    error_msg = match.group(1).strip()
                    print(f"[IDS] 页面错误信息: {error_msg}")
                    return {"success": False, "message": error_msg}

            if "认证失败" in text or "密码错误" in text or "用户不存在" in text:
                return {"success": False, "message": "账号或密码错误"}

            if 'id="continue"' in text:
                # 需要再次提交 continue 表单
                print(f"[IDS] 检测到 continue 表单，重新解析...")
                continue_parser = HiddenInputParser()
                continue_parser.feed(text)
                continue_data = continue_parser.fields.copy()

                print(f"[IDS] 提交 continue 表单...")
                resp = self.session.post(
                    self.IDS_LOGIN_URL,
                    data=continue_data,
                    allow_redirects=False,
                    timeout=20
                )
                print(f"[IDS] continue 响应状态码: {resp.status_code}")
                if resp.status_code in (301, 302):
                    self._follow_redirects(resp.headers.get('Location', ''))
                    return {"success": True, "message": "登录成功"}

            # 保存响应内容用于调试
            print(f"[IDS] 未知响应，前500字符: {text[:500]}")
            return {"success": False, "message": "登录失败，请查看服务器日志"}

        except requests.Timeout:
            return {"success": False, "message": "连接超时"}
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "message": f"登录异常: {str(e)}"}

    def _follow_redirects(self, url: str, max_hops: int = 10):
        """手动跟随重定向链（模拟 XDYou 的 followRedirects=false 行为）"""
        for _ in range(max_hops):
            if not url:
                break
            print(f"  -> {url[:80]}...")
            resp = self.session.get(url, allow_redirects=False, timeout=15, verify=False)
            if resp.status_code in (301, 302):
                url = resp.headers.get('Location', '')
            else:
                break

    def _check_need_captcha(self, username: str) -> bool:
        try:
            resp = self.session.get(
                f"https://ids.xidian.edu.cn/authserver/needCaptcha.html?username={username}",
                timeout=5, verify=False
            )
            return resp.text.strip().lower() == "true"
        except:
            return False


# ═══════════════════════════════════════════════════════════════
# Ehall 本科生课表获取（完整移植 XDYou 流程）
# ═══════════════════════════════════════════════════════════════

class EhallClassTable:
    """本科生教务系统课表查询"""

    EHALL_REFERER = "http://ehall.xidian.edu.cn/new/index_xd.html"
    EHALL_HOST = "ehall.xidian.edu.cn"

    def __init__(self, session: requests.Session):
        self.session = session
        self._setup_headers()

    def _setup_headers(self):
        """设置 Ehall 请求头"""
        self.session.headers.update({
            "Referer": self.EHALL_REFERER,
            "Host": self.EHALL_HOST,
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "Keep-Alive",
        })

    def _parse_json(self, response) -> dict:
        """解析 JSON，处理 UTF-8 BOM"""
        text = response.content.decode('utf-8-sig')
        return json.loads(text)

    def fetch(self, username: str) -> dict:
        """获取本科生课表"""
        try:
            # 1. 激活课表应用
            print("[Ehall] 激活课表应用...")
            app_url = self._activate_app()
            if not app_url:
                raise Exception("无法激活课表应用")

            # 2. 初始化应用 session
            print(f"[Ehall] 初始化应用: {app_url[:80]}...")
            self.session.post(app_url, timeout=15, verify=False)

            # 3. 获取学期代码
            print("[Ehall] 获取学期信息...")
            semester_code = self._get_semester()
            if not semester_code:
                raise Exception("无法获取学期信息")

            # 4. 获取开学日期
            print("[Ehall] 获取开学日期...")
            term_start_day = self._get_term_start(semester_code)

            # 5. 获取课表数据
            print("[Ehall] 获取课表数据...")
            rows = self._get_class_data(semester_code, username)

            return self._parse_class_table(rows, semester_code, term_start_day)

        except Exception as e:
            raise Exception(f"获取课表失败: {str(e)}")

    def _activate_app(self) -> str:
        """激活课表应用，返回应用入口 URL"""
        try:
            # 调用 appShow 激活应用
            resp = self.session.get(
                "https://ehall.xidian.edu.cn/appShow?appId=4770397878132218",
                allow_redirects=False,
                timeout=15,
                verify=False
            )

            if resp.status_code in (301, 302):
                location = resp.headers.get('Location', '')
                # 移除 jsessionid 参数
                location = re.sub(r';jsessionid=(.*)\?', '?', location)
                return location

            return None
        except Exception as e:
            print(f"  激活应用失败: {e}")
            return None

    def _get_semester(self) -> str:
        """获取当前学期代码"""
        try:
            resp = self.session.post(
                "https://ehall.xidian.edu.cn/jwapp/sys/wdkb/modules/jshkcb/dqxnxq.do",
                timeout=15,
                verify=False
            )
            data = self._parse_json(resp)
            return data.get("datas", {}).get("dqxnxq", {}).get("rows", [{}])[0].get("DM", "")
        except Exception as e:
            print(f"  获取学期失败: {e}")
            return ""

    def _get_term_start(self, semester_code: str) -> str:
        """获取学期开始日期"""
        try:
            parts = semester_code.split("-")
            resp = self.session.post(
                "https://ehall.xidian.edu.cn/jwapp/sys/wdkb/modules/jshkcb/cxjcs.do",
                data={
                    "XN": f"{parts[0]}-{parts[1]}",
                    "XQ": parts[2] if len(parts) > 2 else "1"
                },
                timeout=15,
                verify=False
            )
            data = self._parse_json(resp)
            return data.get("datas", {}).get("cxjcs", {}).get("rows", [{}])[0].get("XQKSRQ", "")
        except Exception as e:
            print(f"  获取开学日期失败: {e}")
            return ""

    def _get_class_data(self, semester_code: str, username: str) -> list:
        """获取课表数据"""
        try:
            resp = self.session.post(
                "https://ehall.xidian.edu.cn/jwapp/sys/wdkb/modules/xskcb/xskcb.do",
                data={
                    "XNXQDM": semester_code,
                    "XH": username
                },
                timeout=15,
                verify=False
            )
            data = self._parse_json(resp)

            # 检查返回状态
            ext = data.get("datas", {}).get("xskcb", {}).get("extParams", {})
            if ext.get("code") != 1:
                msg = ext.get("msg", "获取课表失败")
                if "课程未发布" in msg:
                    return []
                raise Exception(msg)

            return data.get("datas", {}).get("xskcb", {}).get("rows", [])
        except Exception as e:
            print(f"  获取课表数据失败: {e}")
            raise

    def _parse_class_table(self, rows: list, semester_code: str, term_start_day: str) -> dict:
        """解析课表数据"""
        class_detail = []
        time_arrangement = []
        semester_length = 1

        for row in rows:
            detail = {
                "name": row.get("KCM", "未知课程"),
                "code": row.get("KCH", ""),
                "number": row.get("KXH", "")
            }

            # 查找或添加课程
            detail_index = -1
            for i, d in enumerate(class_detail):
                if d["name"] == detail["name"] and d["code"] == detail["code"]:
                    detail_index = i
                    break

            if detail_index == -1:
                class_detail.append(detail)
                detail_index = len(class_detail) - 1

            # 解析周次
            skzc = str(row.get("SKZC", ""))
            week_list = [c == "1" for c in skzc]

            if len(skzc) > semester_length:
                semester_length = len(skzc)

            arrangement = {
                "index": detail_index,
                "weekList": week_list,
                "teacher": row.get("SKJS", ""),
                "day": int(row.get("SKXQ", 1)),
                "start": int(row.get("KSJC", 1)),
                "stop": int(row.get("JSJC", 1)),
                "classroom": row.get("JASMC", ""),
                "source": "school"
            }
            time_arrangement.append(arrangement)

        return {
            "semesterCode": semester_code,
            "termStartDay": term_start_day[:10] if term_start_day else "",
            "semesterLength": semester_length,
            "classDetail": class_detail,
            "timeArrangement": time_arrangement,
            "notArranged": [],
            "classChanges": []
        }


# ═══════════════════════════════════════════════════════════════
# API 路由
# ═══════════════════════════════════════════════════════════════

@app.route('/api/classtable', methods=['POST'])
def get_classtable():
    """获取课表 API"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        user_type = data.get('type', 'undergraduate')

        if not username or not password:
            return jsonify({"success": False, "message": "请输入学号和密码"})

        print(f"\n{'='*60}")
        print(f"[API] 开始查询课表: {username} ({user_type})")
        print(f"{'='*60}")

        # IDS 登录
        ids = IDSSession()
        service = "https://ehall.xidian.edu.cn/login?service=https://ehall.xidian.edu.cn/new/index.html"

        login_result = ids.login(username, password, service)
        if not login_result["success"]:
            return jsonify({"success": False, "message": login_result["message"]})

        # 获取课表
        ehall = EhallClassTable(ids.session)
        class_data = ehall.fetch(username)

        print(f"[API] 查询成功！共 {len(class_data['classDetail'])} 门课程")
        print(f"{'='*60}\n")

        return jsonify({"success": True, "data": class_data})

    except Exception as e:
        print(f"[API] 查询失败: {str(e)}")
        return jsonify({"success": False, "message": str(e)})


@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "service": "classtable-server"})


# ═══════════════════════════════════════════════════════════════
# 启动服务
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  西小豆课表查询后端服务")
    print("  基于 XDYou 项目原理实现")
    print("="*60)
    print()
    print("  服务地址: http://localhost:5000")
    print("  API 端点:")
    print("    POST /api/classtable - 获取课表")
    print("    GET  /api/health     - 健康检查")
    print()
    print("  依赖库状态:")
    if HAS_IMAGE_LIBS:
        print("    ✓ pillow, numpy - 已安装（滑块验证码破解可用）")
    else:
        print("    ✗ pillow, numpy - 未安装")
    if HAS_CRYPTO:
        print("    ✓ pycryptodome - 已安装（密码加密可用）")
    else:
        print("    ✗ pycryptodome - 未安装")
    print()
    print("  安装依赖:")
    print("    pip install flask flask-cors requests pillow numpy pycryptodome")
    print()
    print("="*60 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False)

