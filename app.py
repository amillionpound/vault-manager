# -*- coding: utf-8 -*-
"""
工程账本 (vault-manager) — SCF Web 函数后端骨架
模型 A：客户端零知识。SCF 只做「鉴权 + 存取密文」，绝不接触明文密码/保险库密钥。
加密/解密全部在浏览器端用 Web Crypto (PBKDF2 + AES-GCM) 完成。
依赖：Flask 1.x（SCF Py3.6，vendor 内打包）。COS 用原生签名，无额外 SDK。
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
import urllib.request
import urllib.error
from flask import Flask, request, jsonify, send_file, Response

# SCF 部署：把 vendor 加入路径（Flask 等依赖打包在此）
VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor')
if os.path.isdir(VENDOR):
    sys.path.insert(0, VENDOR)

app = Flask(__name__)

# CORS：前端托管在 CloudStudio / GitHub Pages（与 SCF 不同源），必须允许跨域
@app.after_request
def _cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return resp

# ------------------------- 配置（来自 SCF 环境变量） -------------------------
ADMIN_PWD_HASH = os.environ.get('ADMIN_PWD', '').strip().lower()   # 密码的 SHA-256 hex（hash 模式）
SESSION_SECRET = os.environ.get('SESSION_SECRET', 'change-me-please')
COS_BUCKET = os.environ.get('COS_BUCKET', '')
COS_REGION = os.environ.get('COS_REGION', 'ap-guangzhou')
COS_SECRET_ID = os.environ.get('COS_SECRET_ID', '')
COS_SECRET_KEY = os.environ.get('COS_SECRET_KEY', '')
COS_HOST = '{bucket}.cos.{region}.myqcloud.com'.format(bucket=COS_BUCKET, region=COS_REGION)
ADMIN_TOTP_SECRET = os.environ.get('ADMIN_TOTP_SECRET', '').strip().upper()  # 可选 TOTP

VAULT_KEY = 'vault.json'
META_KEY = 'vault_meta.json'


# ------------------------- COS 原生签名（复用 word-dictation 的写法） -------------------------
def cos_sign(method, uri):
    now = int(time.time())
    key_time = '{now}-{end}'.format(now=now - 60, end=now + 600)
    sign_key = hmac.new(COS_SECRET_KEY.encode('utf-8'), key_time.encode('utf-8'), hashlib.sha1).hexdigest()
    fmt = '{method}\n{uri}\n\nhost={host}\n'.format(method=method.lower(), uri=uri, host=COS_HOST)
    digest = hashlib.sha1(fmt.encode('utf-8')).hexdigest()
    sts = 'sha1\n{key_time}\n{digest}\n'.format(key_time=key_time, digest=digest)
    sig = hmac.new(sign_key.encode('utf-8'), sts.encode('utf-8'), hashlib.sha1).hexdigest()
    return ('q-sign-algorithm=sha1&q-ak={ak}&q-sign-time={kt}&q-key-time={kt}'
            '&q-header-list=host&q-url-param-list=&q-signature={sig}').format(
        ak=COS_SECRET_ID, kt=key_time, sig=sig)


def _cos_req(method, key, data=None, ctype='application/json'):
    uri = '/' + key
    auth = cos_sign(method, uri)
    url = 'https://{host}{uri}?{auth}'.format(host=COS_HOST, uri=uri, auth=auth)
    headers = {'Host': COS_HOST, 'Content-Type': ctype}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    return urllib.request.urlopen(req, timeout=10)


def cos_get(key):
    try:
        with _cos_req('get', key) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def cos_put(key, data, ctype='application/json'):
    with _cos_req('put', key, data=data, ctype=ctype) as r:
        return r.read()


def cos_delete(key):
    try:
        with _cos_req('delete', key) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


UPLOAD_PREFIX = 'uploads/'
_FILE_ID_RE = re.compile(r'^[A-Za-z0-9_\-]{4,48}$')


# ------------------------- 会话 token（HMAC 签名，无外部依赖） -------------------------
def make_token():
    payload = base64.urlsafe_b64encode(json.dumps({'exp': int(time.time()) + 3600, 'v': 1}).encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return '{payload}.{sig}'.format(payload=payload, sig=sig)


def check_token(t):
    try:
        payload_b64, sig = t.split('.')
        expect = hmac.new(SESSION_SECRET.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        if payload.get('exp', 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def auth_payload():
    h = request.headers.get('Authorization', '')
    if h.startswith('Bearer '):
        return check_token(h[7:])
    return None


# ------------------------- TOTP（手动 RFC6238，无外部依赖） -------------------------
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


# ------------------------- 路由 -------------------------
# 重要：SCF 只做 API 服务。HTML 前端托管在 CloudStudio / GitHub Pages（与 SCF 不同源），
# 直接让 SCF 返回 HTML 会被 API 网关当成附件下载（已踩过的坑），所以这里不提供任何 HTML/静态文件服务。
@app.route('/', methods=['GET', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'OPTIONS'])
def root(path=''):
    if request.method == 'OPTIONS':
        return ('', 204)
    return jsonify({
        'code': 0,
        'service': 'vault-manager-api',
        'note': '这是 API 服务。前端请访问部署在 CloudStudio / GitHub Pages 的静态页面。'
    })


# ---------- 图片：客户端 AES-GCM 加密后上传，SCF 只存密文（零知识） ----------
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


@app.route('/api/health')
def health():
    return jsonify({'code': 0, 'ok': True, 'cos': bool(COS_BUCKET), 'totp': bool(ADMIN_TOTP_SECRET)})


@app.route('/api/login', methods=['POST'])
def login():
    if not ADMIN_PWD_HASH:
        return jsonify({'code': 3, 'msg': 'SCF 未配置 ADMIN_PWD（请用自算密钥工具对管理员密码算 SHA-256 hex 后填入环境变量）'})
    d = request.get_json(force=True, silent=True) or {}
    pw_hash = (d.get('pwHash') or '').strip().lower()
    totp = d.get('totp', '')
    # 零知识：浏览器已把密码算成 SHA-256 hex 发来，SCF 只比对哈希，永不接触明文
    if pw_hash != ADMIN_PWD_HASH:
        return jsonify({'code': 1, 'msg': '密码错误'})
    if ADMIN_TOTP_SECRET and not totp_verify(ADMIN_TOTP_SECRET, totp or ''):
        return jsonify({'code': 2, 'msg': '动态码错误'})
    return jsonify({'code': 0, 'token': make_token(), 'totp_required': bool(ADMIN_TOTP_SECRET)})


@app.route('/api/meta', methods=['GET'])
def get_meta():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    data = cos_get(META_KEY)
    if data is None:
        return jsonify({'code': 0, 'meta': None})
    return jsonify({'code': 0, 'meta': json.loads(data)})


@app.route('/api/vault', methods=['GET'])
def get_vault():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    data = cos_get(VAULT_KEY)
    if data is None:
        return jsonify({'code': 0, 'cipher': None})
    return jsonify({'code': 0, 'cipher': base64.b64encode(data).decode('utf-8')})


@app.route('/api/vault', methods=['PUT'])
def put_vault():
    if not auth_payload():
        return jsonify({'code': 1, 'msg': '未登录'}), 401
    d = request.get_json(force=True, silent=True) or {}
    cipher_b64 = d.get('cipher', '')
    meta = d.get('meta')
    if not cipher_b64:
        return jsonify({'code': 2, 'msg': '缺少密文'}), 400
    raw = base64.b64decode(cipher_b64)
    cos_put(VAULT_KEY, raw)
    if meta:
        cos_put(META_KEY, json.dumps(meta).encode('utf-8'))
    return jsonify({'code': 0, 'ok': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
