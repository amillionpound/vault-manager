# -*- coding: utf-8 -*-
"""
工程账本 (vault-manager) — SCF Web 函数后端 (v3.1)
零知识：SCF 只做「鉴权 + 存取密文」，绝不接触明文密码 / 保险库密钥 / DEK。
所有对称加密（PBKDF2 / AES-GCM / 信封加密）都在浏览器端用 Web Crypto 完成。
后端仅用 SHA-256 比对密码哈希 + HMAC 签发会话令牌 + COS 原生签名存取对象。

COS 对象：
  auth.json      客户端加密参数 + 登录哈希（salts/wraps/recoveryHash/recoveryId）
  sys.json       服务端私有：登录失败计数 / 锁定时间 / 登录 IP 日志（不暴露给客户端）
  vault.json     普通区密文（DEK_normal 加密）
  secret.json    绝密区密文（DEK_secret 加密，与 vault 物理隔离）
  uploads/<id>.bin  图片密文
  shares/<id>    单条只读分享密文
"""
import os
import re
import sys
import json
import time
import base64
import hashlib
import hmac
import secrets
import struct
from flask import Flask, request, jsonify, Response

# COS Python SDK（腾讯云官方）：负责签名 + PUT/GET/DELETE/LIST，已随包打包进 vendor/。
# 相比此前手写的 urllib 签名客户端，官方 SDK 在 SCF 出网环境下对 PUT 带 body 的请求更稳健。
try:
    from qcloud_cos import CosConfig, CosS3Client
    from qcloud_cos.cos_exception import CosServiceError
    _COS_OK = True
except Exception:
    CosConfig = CosS3Client = CosServiceError = None
    _COS_OK = False

VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor')
if os.path.isdir(VENDOR):
    sys.path.insert(0, VENDOR)

app = Flask(__name__)

# CORS：前端托管在 GitHub Pages / CloudStudio（与 SCF 不同源）
@app.after_request
def _cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return resp


# ------------------------- 配置（来自 SCF 环境变量，只放永不变的） -------------------------
ADMIN_PWD_HASH = os.environ.get('ADMIN_PWD', '').strip().lower()   # 仅首次引导：密码的 SHA-256 hex
SESSION_SECRET = os.environ.get('SESSION_SECRET', 'change-me-please')
COS_BUCKET = os.environ.get('COS_BUCKET', '')
COS_REGION = os.environ.get('COS_REGION', 'ap-guangzhou')
COS_SECRET_ID = os.environ.get('COS_SECRET_ID', '')
COS_SECRET_KEY = os.environ.get('COS_SECRET_KEY', '')
ADMIN_TOTP_SECRET = os.environ.get('ADMIN_TOTP_SECRET', '').strip().upper()  # 可选 TOTP

AUTH_KEY = 'auth.json'
SYS_KEY = 'sys.json'
VAULT_KEY = 'vault.json'
SECRET_KEY = 'secret.json'
UPLOAD_PREFIX = 'uploads/'
SHARE_PREFIX = 'shares/'
_FILE_ID_RE = re.compile(r'^[A-Za-z0-9_\-]{4,48}$')
_MAX_FAILS = 5
_LOCK_SECONDS = 900          # 连续失败锁定 15 分钟
_RECOVER_MAX_FAILS = 10
_RECOVER_LOCK_SECONDS = 3600  # 应急恢复暴力尝试锁定 1 小时

# 前端用 url-safe base64（b64u）编码密文，后端须对应解码
def b64u_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).decode('ascii')


# ------------------------- COS 客户端（官方 SDK） -------------------------
_cos_client = None


def _get_cos():
    """惰性创建 COS 客户端（全局单例，避免重复初始化）。"""
    global _cos_client
    if _cos_client is None and COS_SECRET_ID and COS_SECRET_KEY and COS_BUCKET:
        cfg = CosConfig(Region=COS_REGION, SecretId=COS_SECRET_ID, SecretKey=COS_SECRET_KEY)
        _cos_client = CosS3Client(cfg)
    return _cos_client


def cos_get(key):
    """读取对象；不存在返回 None；其他异常也返回 None（避免 500，由调用方决定行为）。"""
    c = _get_cos()
    if not c:
        return None
    try:
        resp = c.get_object(Bucket=COS_BUCKET, Key=key)
        body = resp['Body']
        try:
            return body.get_raw_stream().read()
        except Exception:
            return body.read()
    except CosServiceError as e:
        if e.get_status_code() == 404:
            return None
        return None
    except Exception:
        return None


def cos_put(key, data, ctype='application/json'):
    c = _get_cos()
    if not c:
        raise RuntimeError('COS 未配置（缺少 COS_SECRET_ID/KEY/BUCKET）')
    c.put_object(Bucket=COS_BUCKET, Body=data, Key=key, ContentType=ctype)


def cos_delete(key):
    c = _get_cos()
    if not c:
        return
    try:
        c.delete_object(Bucket=COS_BUCKET, Key=key)
    except Exception:
        pass


def cos_list(prefix):
    """列出某前缀下的对象 Key（用于批量删除）。"""
    c = _get_cos()
    if not c:
        return []
    keys = []
    marker = ''
    while True:
        resp = c.list_objects(Bucket=COS_BUCKET, Prefix=prefix, Marker=marker)
        for item in resp.get('Contents', []):
            keys.append(item['Key'])
        if resp.get('IsTruncated') == 'true':
            marker = resp.get('NextMarker', '') or (keys[-1] if keys else '')
            if not marker:
                break
        else:
            break
    return keys


def delete_prefix(prefix):
    for k in cos_list(prefix):
        cos_delete(k)


# ------------------------- 服务端状态（sys.json） -------------------------
def load_sys():
    raw = cos_get(SYS_KEY)
    if raw:
        try:
            o = json.loads(raw)
            o.setdefault('fails', 0)
            o.setdefault('lockedUntil', 0)
            o.setdefault('recoveryFails', 0)
            o.setdefault('recoveryLockUntil', 0)
            o.setdefault('loginLog', [])
            return o
        except Exception:
            pass
    return {'fails': 0, 'lockedUntil': 0, 'recoveryFails': 0, 'recoveryLockUntil': 0, 'loginLog': []}


def save_sys(o):
    cos_put(SYS_KEY, json.dumps(o).encode('utf-8'))


def load_auth():
    try:
        raw = cos_get(AUTH_KEY)
        if raw:
            return json.loads(raw)
    except Exception:
        return None
    return None


def save_auth(o):
    cos_put(AUTH_KEY, json.dumps(o).encode('utf-8'))


def get_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.headers.get('X-Real-IP', request.remote_addr or 'unknown')


# ------------------------- 会话 token（HMAC，无外部依赖） -------------------------
def make_token(exp_seconds, typ):
    now = int(time.time())
    payload = base64.urlsafe_b64encode(json.dumps({'exp': now + exp_seconds, 'typ': typ, 'v': 1}).encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return '{payload}.{sig}'.format(payload=payload, sig=sig)


def check_token(t, typ=None):
    try:
        payload_b64, sig = t.split('.')
        expect = hmac.new(SESSION_SECRET.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        if payload.get('exp', 0) < int(time.time()):
            return None
        if typ and payload.get('typ') != typ:
            return None
        return payload
    except Exception:
        return None


def auth_payload():
    h = request.headers.get('Authorization', '')
    if h.startswith('Bearer '):
        return check_token(h[7:])
    return None


# ------------------------- TOTP（RFC6238，无外部依赖） -------------------------
def totp_verify(secret, code, window=1):
    if not secret:
        return True
    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30
    for w in range(-window, window + 1):
        msg = struct.pack('>Q', counter + w)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[-1] & 0x0f
        otp = (struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000
        if '{:06d}'.format(otp) == code:
            return True
    return False


# ------------------------- 通用工具 -------------------------
def get_json():
    return request.get_json(force=True, silent=True) or {}


def client_auth_fields(auth):
    return {k: auth.get(k) for k in
            ('saltM', 'saltR', 'saltS', 'wrapNormalByMaster', 'wrapNormalByRecovery',
             'wrapSecretBySecret', 'recoveryId', 'recoveryHash') if k in auth}


# ------------------------- 路由 -------------------------
@app.route('/', methods=['GET', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'OPTIONS'])
def root(path=''):
    if request.method == 'OPTIONS':
        return ('', 204)
    return jsonify({
        'code': 0,
        'service': 'vault-manager-api',
        'version': '3.1',
        'note': 'API 服务。前端请访问部署在 GitHub Pages / CloudStudio 的静态页面。'
    })


@app.route('/api/<path:path>', methods=['OPTIONS'])
def api_options(path=''):
    return ('', 204)


@app.route('/api/health')
def health():
    out = {
        'code': 0, 'ok': True,
        'cos': bool(COS_BUCKET and COS_SECRET_ID and COS_SECRET_KEY),
        'cos_sdk': _COS_OK,
        'initialized': load_auth() is not None,
        'totp': bool(ADMIN_TOTP_SECRET),
    }
    c = _get_cos()
    if not c:
        out['cos_err'] = 'COS 未配置（缺少 COS_SECRET_ID / COS_SECRET_KEY / COS_BUCKET 环境变量）'
        return jsonify(out)
    # GET 探测：404 视为正常（桶可达、权限 OK）
    try:
        c.get_object(Bucket=COS_BUCKET, Key='__probe_get__')
        out['cos_get'] = 'ok'
    except CosServiceError as e:
        if e.get_status_code() == 404:
            out['cos_get'] = 'ok_or_404'
        else:
            out['cos_get_err'] = str(e)[:200]
    except Exception as e:
        out['cos_get_err'] = str(e)[:200]
    # PUT 探测：写一条再删，验证写入链路
    try:
        c.put_object(Bucket=COS_BUCKET, Body=b'1', Key='__probe__', ContentType='application/octet-stream')
        c.delete_object(Bucket=COS_BUCKET, Key='__probe__')
        out['cos_write'] = True
    except Exception as e:
        out['cos_write'] = False
        out['cos_err'] = str(e)[:300]
    return jsonify(out)


# ---------- 首次引导：环境 ADMIN_PWD 防陌生人抢注，写入 auth.json 后环境哈希即失效 ----------
@app.route('/api/bootstrap', methods=['POST'])
def bootstrap():
    if not ADMIN_PWD_HASH:
        return jsonify({'code': 3, 'msg': 'SCF 未配置 ADMIN_PWD 环境变量，无法初始化（请用自算密钥工具对管理员密码算 SHA-256 hex 后填入）'}), 400
    if load_auth() is not None:
        return jsonify({'code': 5, 'msg': '已初始化，无需再次引导'}), 400
    d = get_json()
    pw = (d.get('loginHash') or '').strip().lower()
    if pw != ADMIN_PWD_HASH:
        return jsonify({'code': 1, 'msg': '环境 ADMIN_PWD 不匹配'}), 403
    fields = ('loginHash', 'saltM', 'saltR', 'saltS', 'wrapNormalByMaster', 'wrapNormalByRecovery', 'wrapSecretBySecret', 'recoveryId', 'recoveryHash')
    obj = {k: d[k] for k in fields if k in d}
    obj['updatedAt'] = int(time.time())
    save_auth(obj)
    save_sys(load_sys())
    token = make_token(86400, 'a')
    refresh = make_token(7 * 86400, 'r')
    return jsonify({'code': 0, 'token': token, 'refreshToken': refresh, 'totp_required': bool(ADMIN_TOTP_SECRET)})


# ---------- 登录：SHA-256 比对 + 限流锁定 + IP 记录 + 双令牌 ----------
@app.route('/api/login', methods=['POST'])
def login():
    sys = load_sys()
    now = int(time.time())
    if sys.get('lockedUntil', 0) > now:
        return jsonify({'code': 6, 'msg': '尝试次数过多已被锁定', 'retry_after': sys['lockedUntil'] - now}), 429
    d = get_json()
    pw = (d.get('pwHash') or '').strip().lower()
    if not pw:
        return jsonify({'code': 1, 'msg': '缺少密码哈希'}), 400
    auth = load_auth()
    if auth is None:
        # 尚未初始化：若环境哈希匹配，提示前端走引导流程
        if ADMIN_PWD_HASH and pw == ADMIN_PWD_HASH:
            return jsonify({'code': 4, 'msg': '首次使用，请初始化', 'need_setup': True})
        return jsonify({'code': 1, 'msg': '密码错误'}), 401
    if pw != auth.get('loginHash', ''):
        sys['fails'] = sys.get('fails', 0) + 1
        if sys['fails'] >= _MAX_FAILS:
            sys['lockedUntil'] = now + _LOCK_SECONDS
        save_sys(sys)
        lock = sys.get('lockedUntil', 0) > now
        return jsonify({'code': 1, 'msg': '密码错误', 'lock': lock,
                        'retry_after': max(0, sys.get('lockedUntil', 0) - now)}), 401
    if ADMIN_TOTP_SECRET and not totp_verify(ADMIN_TOTP_SECRET, d.get('totp', '') or ''):
        return jsonify({'code': 2, 'msg': '动态码错误'}), 401
    # 成功
    sys['fails'] = 0
    sys.setdefault('loginLog', []).append({'ip': get_ip(), 'ts': now})
    sys['loginLog'] = sys['loginLog'][-200:]
    save_sys(sys)
    token = make_token(86400, 'a')
    refresh = make_token(7 * 86400, 'r')
    return jsonify({'code': 0, 'token': token, 'refreshToken': refresh,
                    'totp_required': bool(ADMIN_TOTP_SECRET), 'auth': client_auth_fields(auth)})


# ---------- 刷新 access token（双令牌：refresh 7 天，access 1 天） ----------
@app.route('/api/refresh', methods=['POST'])
def refresh():
    d = get_json()
    rt = d.get('refreshToken', '')
    if not check_token(rt, typ='r'):
        return jsonify({'code': 1, 'msg': '会话已过期，请重新登录'}), 401
    return jsonify({'code': 0, 'token': make_token(86400, 'a')})


# ---------- 更新 auth.json（改主密码重包 / 启用应急恢复，需已登录） ----------
@app.route('/api/auth', methods=['PUT'])
def update_auth():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    d = get_json()
    auth = load_auth()
    if auth is None:
        return jsonify({'code': 4, 'msg': '未初始化'}), 400
    allowed = ('loginHash', 'saltM', 'saltR', 'saltS', 'wrapNormalByMaster',
               'wrapNormalByRecovery', 'wrapSecretBySecret', 'recoveryId', 'recoveryHash')
    for k in allowed:
        if k in d:
            auth[k] = d[k]
    auth['updatedAt'] = int(time.time())
    save_auth(auth)
    return jsonify({'code': 0, 'ok': True})


@app.route('/api/auth', methods=['GET'])
def get_auth():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    auth = load_auth()
    if auth is None:
        return jsonify({'code': 4, 'msg': '未初始化'}), 400
    return jsonify({'code': 0, 'auth': client_auth_fields(auth)})


# ---------- 普通区 / 绝密区 密文存取（令牌门控，服务器只存密文） ----------
@app.route('/api/vault', methods=['GET'])
def get_vault():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    data = cos_get(VAULT_KEY)
    return jsonify({'code': 0, 'cipher': b64u_encode(data) if data else None})


@app.route('/api/vault', methods=['PUT'])
def put_vault():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    d = get_json()
    cipher_b64 = d.get('cipher', '')
    if not cipher_b64:
        return jsonify({'code': 2, 'msg': '缺少密文'}), 400
    cos_put(VAULT_KEY, b64u_decode(cipher_b64))
    return jsonify({'code': 0, 'ok': True})


@app.route('/api/secret', methods=['GET'])
def get_secret():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    data = cos_get(SECRET_KEY)
    return jsonify({'code': 0, 'cipher': b64u_encode(data) if data else None})


@app.route('/api/secret', methods=['PUT'])
def put_secret():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    d = get_json()
    cipher_b64 = d.get('cipher', '')
    if not cipher_b64:
        return jsonify({'code': 2, 'msg': '缺少密文'}), 400
    cos_put(SECRET_KEY, b64u_decode(cipher_b64))
    return jsonify({'code': 0, 'ok': True})


# ---------- 图片：客户端 AES-GCM 加密后上传，SCF 只存密文 ----------
@app.route('/api/upload', methods=['PUT'])
def upload_file():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    fid = request.args.get('id', '')
    if not _FILE_ID_RE.match(fid):
        return jsonify({'code': 2, 'msg': '无效文件ID'}), 400
    data = request.get_data()
    if not data:
        return jsonify({'code': 3, 'msg': '空文件'}), 400
    cos_put(UPLOAD_PREFIX + fid + '.bin', data, ctype='application/octet-stream')
    return jsonify({'code': 0, 'ok': True})


@app.route('/api/file', methods=['GET', 'DELETE'])
def file_op():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    fid = request.args.get('id', '')
    if not _FILE_ID_RE.match(fid):
        return jsonify({'code': 2, 'msg': '无效文件ID'}), 400
    key = UPLOAD_PREFIX + fid + '.bin'
    if request.method == 'DELETE':
        cos_delete(key)
        return jsonify({'code': 0, 'ok': True})
    data = cos_get(key)
    if data is None:
        return 'not found', 404
    return Response(data, mimetype='application/octet-stream')


# ---------- 按条目只读分享（密钥在 URL # 片段，服务端只存密文） ----------
@app.route('/api/share', methods=['POST'])
def create_share():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    d = get_json()
    cipher = d.get('cipher', '')
    if not cipher:
        return jsonify({'code': 2, 'msg': '缺少密文'}), 400
    sid = secrets.token_hex(8)
    obj = {'entryId': d.get('entryId', ''), 'cipher': cipher,
           'expiresAt': int(d.get('expiresAt', 0) or 0), 'createdAt': int(time.time())}
    cos_put(SHARE_PREFIX + sid, json.dumps(obj).encode('utf-8'))
    return jsonify({'code': 0, 'id': sid})


@app.route('/api/share/<sid>', methods=['GET'])
def read_share(sid):
    if not _FILE_ID_RE.match(sid):
        return jsonify({'code': 2, 'msg': '无效分享ID'}), 400
    data = cos_get(SHARE_PREFIX + sid)
    if data is None:
        return jsonify({'code': 4, 'msg': '分享不存在或已删除'}), 404
    obj = json.loads(data)
    if obj.get('expiresAt') and obj['expiresAt'] < int(time.time()):
        return jsonify({'code': 5, 'msg': '分享已过期'}), 410
    return jsonify({'code': 0, 'cipher': obj['cipher'], 'entryId': obj.get('entryId', '')})


# ---------- 应急恢复（数字遗产）：公开链接 + 恢复密码 R ----------
@app.route('/api/recover/verify', methods=['POST'])
def recover_verify():
    sys = load_sys()
    now = int(time.time())
    if sys.get('recoveryLockUntil', 0) > now:
        return jsonify({'code': 6, 'msg': '恢复尝试过多已锁定', 'retry_after': sys['recoveryLockUntil'] - now}), 429
    d = get_json()
    rid = (d.get('recoveryId') or '').strip()
    R = (d.get('R') or '').strip()
    auth = load_auth()
    if not auth or not auth.get('recoveryId') or auth.get('recoveryId') != rid or not auth.get('recoveryHash'):
        sys['recoveryFails'] = sys.get('recoveryFails', 0) + 1
        if sys['recoveryFails'] >= _RECOVER_MAX_FAILS:
            sys['recoveryLockUntil'] = now + _RECOVER_LOCK_SECONDS
        save_sys(sys)
        return jsonify({'code': 1, 'msg': '无效或不可用的恢复链接'}), 403
    if hashlib.sha256(R.encode('utf-8')).hexdigest() != auth['recoveryHash']:
        sys['recoveryFails'] = sys.get('recoveryFails', 0) + 1
        if sys['recoveryFails'] >= _RECOVER_MAX_FAILS:
            sys['recoveryLockUntil'] = now + _RECOVER_LOCK_SECONDS
        save_sys(sys)
        return jsonify({'code': 1, 'msg': '恢复密码错误'}), 403
    sys['recoveryFails'] = 0
    save_sys(sys)
    return jsonify({'code': 0, 'saltR': auth['saltR'], 'wrapNormalByRecovery': auth['wrapNormalByRecovery']})


@app.route('/api/recover/setnew', methods=['POST'])
def recover_setnew():
    d = get_json()
    rid = (d.get('recoveryId') or '').strip()
    R = (d.get('R') or '').strip()
    auth = load_auth()
    if not auth or auth.get('recoveryId') != rid or not auth.get('recoveryHash'):
        return jsonify({'code': 1, 'msg': '无效或不可用的恢复链接'}), 403
    if hashlib.sha256(R.encode('utf-8')).hexdigest() != auth['recoveryHash']:
        return jsonify({'code': 1, 'msg': '恢复密码错误'}), 403
    # DEK_normal 保持不变；只更新主密码相关包裹 + 恢复密码哈希
    for k in ('loginHash', 'saltM', 'wrapNormalByMaster', 'wrapNormalByRecovery', 'saltR', 'recoveryHash'):
        if k in d:
            auth[k] = d[k]
    auth['updatedAt'] = int(time.time())
    save_auth(auth)
    return jsonify({'code': 0, 'ok': True})


# ---------- 系统重置（factory wipe）：需手输 DELETE ----------
@app.route('/api/reset', methods=['POST'])
def reset():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    d = get_json()
    if (d.get('confirm') or '') != 'DELETE':
        return jsonify({'code': 1, 'msg': '需输入 DELETE 确认'}), 400
    for k in (AUTH_KEY, SYS_KEY, VAULT_KEY, SECRET_KEY):
        cos_delete(k)
    delete_prefix(UPLOAD_PREFIX)
    delete_prefix(SHARE_PREFIX)
    return jsonify({'code': 0, 'ok': True})


# ---------- 登录日志（服务端 IP 记录，供统计面板） ----------
@app.route('/api/logs', methods=['GET'])
def logs():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    sys = load_sys()
    return jsonify({'code': 0, 'loginLog': sys.get('loginLog', [])})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '9000'))
    app.run(host='0.0.0.0', port=port)
