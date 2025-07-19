from flask import Flask, render_template, request, session, redirect, abort, jsonify, send_file,  send_from_directory, url_for, flash
import datetime
from datetime import timedelta
from user_agents import parse
import sqlite3
import randomstring
import ipaddress
from toss import tossim
import requests
import discord, os
from utils import *
import threading
import websocket
import json, pytz, random
import sys
import secrets, ssl
import string
import aiohttp
import time
import uuid
import re
from binance.client import Client
from forex_python.converter import CurrencyRates
from discord_webhook import DiscordWebhook, DiscordEmbed
try:
    import thread
except ImportError:
    import _thread as thread

import re

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())
client = discord.Client(intents=discord.Intents.all())
allowed_ip = ["", ""]

def getip():
    return request.headers.get("CF-Connecting-IP", request.remote_addr)

def parse_bank_text(text: str):
    name = re.split(r"\s+", text)

    def filter_name(e: str):
        return e == re.sub(r"[^ㄱ-ㅎㅏ-ㅣ가-힣]|(잔액|농협|입금|입출금|출금|계좌)", "", e)
    name = list(filter(filter_name, name))

    amount = re.sub(
        r"(\d*[!?@#$%^&*():;+\-=~{}<>_[\]|\\\"'./`₩]+\d*)*", "", text)
    amount = re.sub(r"[^0-9\s]", "", amount).strip()
    amount = re.split(r"\s+", amount)

    def strarr_to_numarr(strarr):
        numarr = []
        for i in strarr:
            try:
                numarr.append(int(i))
            except:
                pass
        if len(numarr) == 0:
            return [0]
        return numarr

    amount = min(strarr_to_numarr(amount))

    if len(name) != 1 or amount == 0:
        return {"success": False}
    return {"success": True, "name": name[0], "amount": amount}

def get_db_connection():
    conn = sqlite3.connect('iplist.db')
    conn.row_factory = sqlite3.Row  # 결과를 딕셔너리처럼 사용할 수 있도록 설정
    return conn

def is_blacklisted(user_id=None, ip=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute('''
            SELECT COUNT(*) FROM blacklist_id WHERE id = ?
        ''', (user_id,))
        user_count = cursor.fetchone()[0]
        if user_count > 0:
            conn.close()
            return True
    
    if ip:
        cursor.execute('''
            SELECT COUNT(*) FROM blacklist_ip WHERE ip = ?
        ''', (ip,))
        ip_count = cursor.fetchone()[0]
        if ip_count > 0:
            conn.close()
            return True
    
    conn.close()
    return False

proxycheck_key = "99y2r6-851t04-42571r-o0o517"
db_file = "iplist.db"

def insert_ip(ip, proxy, type, vpn=None, asn=None, provider=None, country=None, isocode=None,
              region=None, regioncode=None, timezone=None, city=None,
              latitude=None, longitude=None, update_missing=False):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    print(f"[DEBUG] Saving to DB - IP: {ip}, Proxy: {proxy}, VPN: {vpn}")

    if update_missing:
        update_query = '''
            UPDATE iplist SET
            proxy = COALESCE(?, proxy),
            vpn = COALESCE(?, vpn),
            type = COALESCE(?, type),
            asn = COALESCE(?, asn),
            provider = COALESCE(?, provider),
            country = COALESCE(?, country),
            isocode = COALESCE(?, isocode),
            region = COALESCE(?, region),
            regioncode = COALESCE(?, regioncode),
            timezone = COALESCE(?, timezone),
            city = COALESCE(?, city),
            latitude = COALESCE(?, latitude),
            longitude = COALESCE(?, longitude)
            WHERE ip = ?;
        '''
        cursor.execute(update_query, (proxy, type, asn, provider, country, isocode,
                                      region, regioncode, timezone, city,
                                      latitude, longitude, ip))
    else:
        insert_query = '''
            INSERT OR IGNORE INTO iplist (ip, proxy, type, asn, provider, country, isocode,
                                          region, regioncode, timezone, city, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        '''
        cursor.execute(insert_query, (ip, proxy, type, asn, provider, country, isocode,
                                      region, regioncode, timezone, city,
                                      latitude, longitude))

    conn.commit()
    conn.close()

def fetch_proxycheck_data(ip):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'  # 여기에 사용할 유저 에이전트를 넣어주세요
        }
        response = requests.get(
            f"https://proxycheck.io/apiproxy/{ip}?key={proxycheck_key}&vpn=1&asn=1&tag=proxycheck.io",
            headers=headers
        )
        response.raise_for_status()
        data = response.json()
        print(data)
        return data.get(ip, {})
    except requests.RequestException as e:
        print(f"Error fetching data for IP {ip}: {e}")
        return {}

def update_ip(ip):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    proxy_data = fetch_proxycheck_data(ip)
    
    cursor.execute('''
        UPDATE iplist
        SET proxy = COALESCE(proxy, ?),
            type = COALESCE(type, ?),
            asn = COALESCE(asn, ?),
            provider = COALESCE(provider, ?),
            country = COALESCE(country, ?),
            isocode = COALESCE(isocode, ?),
            region = COALESCE(region, ?),
            regioncode = COALESCE(regioncode, ?),
            timezone = COALESCE(timezone, ?),
            city = COALESCE(city, ?),
            latitude = COALESCE(latitude, ?),
            longitude = COALESCE(longitude, ?)
        WHERE ip = ?
    ''', (
        proxy_data.get('proxy', 'no'),
        proxy_data.get('type', 'unknown'),
        proxy_data.get('asn', 'unknown'),
        proxy_data.get('provider', 'unknown'),
        proxy_data.get('country', 'unknown'),
        proxy_data.get('isocode', 'unknown'),
        proxy_data.get('region', 'unknown'),
        proxy_data.get('regioncode', 'unknown'),
        proxy_data.get('timezone', 'unknown'),
        proxy_data.get('city', 'unknown'),
        proxy_data.get('latitude', 'unknown'),
        proxy_data.get('longitude', 'unknown'),
        ip
    ))
    conn.commit()
    conn.close()

    
def is_ip_in_subnet(ip, subnets):
    ip = ipaddress.ip_address(ip)
    for subnet in subnets:
        if ip in ipaddress.ip_network(subnet[0]):
            return subnet[1]  # 서브넷의 타입을 반환
    return None

def lolip(ip):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('SELECT subnet, type FROM subnet')
    subnets = cursor.fetchall()
    cursor.execute('SELECT mobile, type FROM mobile')
    mobiles = cursor.fetchall()
    conn.close()

    subnet_type = is_ip_in_subnet(ip, subnets)
    mobile_type = is_ip_in_subnet(ip, mobiles)
    
    try:
        response = requests.get(
            f"https://proxycheck.io/v2/{ip}?key={proxycheck_key}&vpn=1&asn=1&tag=proxycheck.io"
        )
        response.raise_for_status()
        api_result = response.json().get(ip, {})
    except requests.RequestException as e:
        print(f"Error fetching data for IP {ip}: {e}")
        api_result = {}

    if subnet_type:
        api_result["type"] = subnet_type
        api_result["proxy"] = "yes"

    if mobile_type:
        api_result["type"] = mobile_type
        api_result["proxy"] = "no"

    result = {
        "ip": ip,
        "proxy": api_result.get("proxy", "unknown"),
        "type": api_result.get("type", "unknown"),
        "asn": str(api_result.get("asn", "unknown")),
        "provider": api_result.get("provider", "unknown"),
        "country": api_result.get("country", "unknown"),
        "isocode": api_result.get("isocode", "unknown"),
        "region": api_result.get("region", "unknown"),
        "regioncode": api_result.get("regioncode", "unknown"),
        "timezone": api_result.get("timezone", "unknown"),
        "city": api_result.get("city", "unknown"),
        "latitude": str(api_result.get("latitude", "unknown")),
        "longitude": str(api_result.get("longitude", "unknown")),
    }

    return result

@app.route('/check_proxy/<ip>', methods=['GET'])
def check_proxy(ip):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM iplist WHERE ip = ?', (ip,))
    db_result = cursor.fetchone()
    
    if db_result:
        db_result_dict = {column: value for column, value in zip([column[0] for column in cursor.description], db_result)}
        missing_fields = {key: value for key, value in db_result_dict.items() if value is None}
        
        if missing_fields:
            updated_info = lolip(ip)
            for field in missing_fields:
                if field in updated_info and updated_info[field] is not None:
                    db_result_dict[field] = updated_info[field]
            
            update_query_parts = [f"{field} = ?" for field in missing_fields]
            update_query = f"UPDATE iplist SET {', '.join(update_query_parts)} WHERE ip = ?"
            cursor.execute(update_query, (*[db_result_dict[field] for field in missing_fields], ip))
            conn.commit()
        
        response_data = {field: db_result_dict[field] if db_result_dict[field] is not None else "unknown" for field in db_result_dict}
    else:
        response_data = lolip(ip)
        if response_data:
            response_data.pop('ip', None)
            insert_ip(ip, **response_data)
        else:
            response_data = {field: "unknown" for field in cursor.description}
    
    conn.close()
    return jsonify(response_data)

@app.route('/find_sub_accounts/<user_id>', methods=['GET'])
def find_sub_accounts(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT DISTINCT ip FROM ip_req WHERE id = ?
    ''', (user_id,))
    ips = [row['ip'] for row in cursor.fetchall()]
    
    sub_accounts = set()
    visited_ips = set()
    visited_ids = set()

    visited_ids.add(user_id)
    
    while True:
        new_sub_accounts = set()
        new_ips = set()
        
        for ip in ips:
            if ip not in visited_ips:
                visited_ips.add(ip)
                cursor.execute('''
                    SELECT DISTINCT id FROM ip_req WHERE ip = ?
                ''', (ip,))
                ids = [row['id'] for row in cursor.fetchall()]
                
                for found_id in ids:
                    if found_id not in visited_ids and found_id != user_id:
                        new_sub_accounts.add(found_id)
                        visited_ids.add(found_id)
                    
                    cursor.execute('''
                        SELECT DISTINCT ip FROM ip_req WHERE id = ?
                    ''', (found_id,))
                    new_ips.update([row['ip'] for row in cursor.fetchall()])

        ips = list(new_ips)

        if not new_sub_accounts and not new_ips:
            break
        
        sub_accounts.update(new_sub_accounts)
    
    blacklisted_id = None
    blacklisted_ip = None
    for found_id in sub_accounts:
        if is_blacklisted(found_id, None):
            blacklisted_id = found_id
            break
    
    if not blacklisted_id:
        for ip in ips:
            if is_blacklisted(None, ip):
                blacklisted_ip = ip
                break
    
    conn.close()

    sub_accounts.discard(user_id)

    return jsonify({
        'user_id': user_id,
        'found': bool(sub_accounts),
        'sub_accounts': [str(account_id) for account_id in sub_accounts],
        'blacklisted': bool(blacklisted_id or blacklisted_ip),
        'found_id': blacklisted_id,
        'found_ip': blacklisted_ip
    })

@app.route('/check/ip', methods=['POST'])
def iplist12():
    data = request.json
    ip = data.get('ip')
    user_id = data.get('id')

    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ipv4_pattern.match(ip):
        return '', 204

    api_url = f'http://127.0.0.1:5032/check_proxy/{ip}'
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            proxy_data = response.json()
            if proxy_data.get('proxy') == 'yes' or proxy_data.get('type') == 'mobiledata':
                return '', 204
        else:
            return '', 204
    except requests.RequestException:
        return '', 204

    # 데이터베이스에 저장
    conn = sqlite3.connect('iplist.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ip_req VALUES (?, ?)", (ip, user_id))
    conn.commit()
    conn.close()

    return jsonify({'result': True, 'reason': '요청이 확인되었습니다.'}), 200

@app.route("/api/ios/license/serch", methods=["POST"])
def plan():
    serverid = request.json.get('id')
    if request.json.get('key') != '':
        return jsonify({'result': False, 'reason': "라이센스 키가 올바르지 않습니다."}), 403
    
    con = sqlite3.connect("API.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM iosapi WHERE server_id = ?", (serverid,)).fetchone()

    if data is None:
        con.close()
        return jsonify({'result': False, 'reason': "해당 서버 ID를 찾을 수 없습니다."}), 404
    
    license_value = data[2]

    request_count = cur.execute("SELECT COUNT(*) FROM requests WHERE server_id = ?", (serverid,)).fetchone()[0]

    con.close()

    return jsonify({
        'date': license_value,
        'request_count': request_count
    }), 200


@app.route('/bank/ios/charge', methods=['POST'])
def charge_requestwr():
    conn = sqlite3.connect('API.db')
    cursor = conn.cursor()
    data = request.json
    server_id = data.get('server_id')
    license = data.get('license')
    name = data.get('name')
    amount = data.get('amount')
    bank = data.get('bank')
    print(license)

    cursor.execute("SELECT * FROM iosapi WHERE license = ?", (license,))
    valid_license = cursor.fetchone()

    if not valid_license:
        return jsonify({'result': False, 'reason': '존재하지 않는 라이센스 입니다.'}), 403

    cursor.execute("SELECT * FROM iosapi WHERE server_id = ? AND license = ?", (server_id, license))
    valid_combo = cursor.fetchone()

    if not valid_combo:
        return jsonify({'result': False, 'reason': '라이센스가 올바르지 않습니다.'}), 403

    # 30분 이내에 동일한 요청이 있는지 확인
    # 가장 최신의 time 값을 가져오도록 쿼리 수정
    cursor.execute("SELECT time FROM requests WHERE name = ? AND amount = ? AND bank = ? AND state = ? ORDER BY time DESC LIMIT 1", 
                   (name, amount, bank, "False"))
    existing_request = cursor.fetchone()

    if existing_request:
        request_time = datetime.datetime.strptime(existing_request[0], "%Y-%m-%d %H:%M:%S")
        current_time = datetime.datetime.now()

        # 30분이 지났는지 확인
        if current_time - request_time < datetime.timedelta(minutes=10):
            return jsonify({'result': False, 'reason': '최근 10분 이내로 일치한 요청이 있습니다.'}), 403

    # 요청을 새로 추가
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("INSERT INTO requests (server_id, license, name, amount, bank, time, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (server_id, license, name, amount, bank, current_time, 'False'))
    conn.commit()
    conn.close()


    return jsonify({'result': True, 'reason': '성공적으로 처리 되었습니다.'}), 200


@app.route('/ios_charge_check', methods=['POST'])
def ios_charge_check():
    data = request.json
    print(data)
    name = data.get('name')
    amount = data.get('money')
    server_id = data.get('server_id')
    license = data.get('license')
    bank = data.get('bank')


    conn = sqlite3.connect('API.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM iosapi WHERE license = ?", (license,))
    valid_license = cursor.fetchone()

    if not valid_license:
        return jsonify({'result': False, 'reason': '존재하지 않는 라이센스 입니다.'}), 403

    cursor.execute("SELECT * FROM iosapi WHERE server_id = ? AND license = ?", (server_id, license))
    valid_combo = cursor.fetchone()

    if not valid_combo:
        return jsonify({'result': False, 'reason': '라이센스가 올바르지 않습니다.'}), 403


    cursor.execute("SELECT * FROM requests WHERE name = ? AND amount = ? AND bank = ? AND (state = 'False' OR state = 'wait')", (name, amount, bank))
    existing_request = cursor.fetchone()

    if not existing_request:
        conn.close()
        return jsonify({'result': False, 'reason': '일치한 요청이 없습니다.'}), 404
    else:
        cursor.execute("DELETE FROM requests WHERE name = ? AND amount = ? AND bank = ? AND (state = 'False' OR state = 'wait')", (name, amount, bank))
        conn.commit()
        conn.close()
        return jsonify({'result': True, 'reason': '요청이 확인 되었습니다.'}), 200

@app.route('/ios_kakao', methods=['POST'])
def charge_requestsex():
    msg = request.json.get('msg')
    license = request.json.get('license')
    server_id = request.json.get('server_id')
    print(f"{msg} {license} {server_id}")

    # 입금 금액 추출
    amount_match = re.search(r'입금 (\d{1,3}(,\d{3})*)원', msg)
    amount = amount_match.group(1).replace(",", "") if amount_match else None
    print(amount)

    # 이름 추출
    name_pattern = r'입금 \d{1,3}(,\d{3})*원\n([^\n]+)'
    name_match = re.search(name_pattern, msg)
    name = name_match.group(2) if name_match else None
    print(name)

    # 라이센스와 서버 ID 추출
    license_match = re.search(r'(Star-[a-zA-Z0-9]+)', msg)
    license = license_match.group(1) if license_match else license

    server_id_match = re.search(r'\d{15,}', msg)
    server_id = server_id_match.group(0) if server_id_match else server_id

    print(f"Extracted License: {license}")
    print(f"Extracted Server ID: {server_id}")

    conn = sqlite3.connect('API.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM iosapi WHERE license = ?", (license,))
    valid_license = cursor.fetchone()

    if not valid_license:
        conn.close()
        return 'Invalid license', 400
    
    cursor.execute("SELECT * FROM iosapi WHERE server_id = ? AND license = ?", (server_id, license))
    valid_combo = cursor.fetchone()

    if not valid_combo:
        conn.close()
        return 'Invalid server ID', 400

    if not license.startswith('Star') or not server_id.isdigit():
        conn.close()
        return 'Invalid license or server ID', 400

    cursor.execute("SELECT time FROM requests WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ? ORDER BY time DESC LIMIT 1", 
                   (server_id, license, name, amount, "카카오뱅크", "False"))
    existing_request = cursor.fetchone()

    if existing_request:
        request_time = datetime.datetime.strptime(existing_request[0], "%Y-%m-%d %H:%M:%S")
        current_time = datetime.datetime.now()

        # 10분이 지났는지 확인
        if current_time - request_time < datetime.timedelta(minutes=10):
            cursor.execute("UPDATE requests SET state = 'wait' WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ?", 
                           (server_id, license, name, amount, "카카오뱅크", "False"))
            conn.commit()

    conn.close()
    return 'OK', 200

# @app.route('/ios_hana', methods=['POST']) # 이거 작동 안해서 약간 수리 필요함
# def charge_requestsex3():
#     msg = request.json.get('msg')
#     license = request.json.get('license')
#     server_id = request.json.get('server_id')
#     print(f"{msg} {license} {server_id}")


#     amount_match = re.search(r'입금(\d{1,3}(?:,\d{3})*)원', msg)
#     amount = amount_match.group(1).replace(",", "") if amount_match else None
#     print(amount)

#     print(f"Extracted Amount: {amount}")

#     # 라이센스와 서버 ID 추출
#     license_match = re.search(r'(Star-[a-zA-Z0-9]+)', msg)
#     license = license_match.group(1) if license_match else license

#     server_id_match = re.search(r'\d{15,}', msg)
#     server_id = server_id_match.group(0) if server_id_match else server_id

#     print(f"Extracted License: {license}")
#     print(f"Extracted Server ID: {server_id}")

#     conn = sqlite3.connect('API.db')
#     cursor = conn.cursor()

#     cursor.execute("SELECT * FROM iosapi WHERE license = ?", (license,))
#     valid_license = cursor.fetchone()

#     if not valid_license:
#         conn.close()
#         return 'Invalid license', 400
    
#     cursor.execute("SELECT * FROM iosapi WHERE server_id = ? AND license = ?", (server_id, license))
#     valid_combo = cursor.fetchone()

#     if not valid_combo:
#         conn.close()
#         return 'Invalid server ID', 400

#     if not license.startswith('Star') or not server_id.isdigit():
#         conn.close()
#         return 'Invalid license or server ID', 400

#     cursor.execute("SELECT time FROM requests WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ? ORDER BY time DESC LIMIT 1", 
#                    (server_id, license, name, amount, "케이뱅크", "False"))
#     existing_request = cursor.fetchone()

#     if existing_request:
#         request_time = datetime.datetime.strptime(existing_request[0], "%Y-%m-%d %H:%M:%S")
#         current_time = datetime.datetime.now()

#         # 10분이 지났는지 확인
#         if current_time - request_time < datetime.timedelta(minutes=10):
#             cursor.execute("UPDATE requests SET state = 'wait' WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ?", 
#                            (server_id, license, name, amount, "케이뱅크", "False"))
#             conn.commit()

#     conn.close()
#     return 'OK', 200

@app.route('/ios_kbank', methods=['POST'])
def charge_requestsex2():
    msg = request.json.get('msg')
    license = request.json.get('license')
    server_id = request.json.get('server_id')
    print(f"{msg} {license} {server_id}")

    # 입금 금액 추출
    amount_match = re.search(r'입금 (\d{1,3}(,\d{3})*)원', msg)
    amount = amount_match.group(1).replace(",", "") if amount_match else None
    print(amount)

    # 이름 추출
    name_pattern = r'잔액 [^\n]+\n([^\n]+)$'
    name_match = re.search(name_pattern, msg)
    name = name_match.group(1).strip() if name_match else None
    print(name)

    # 라이센스와 서버 ID 추출
    license_match = re.search(r'(Star-[a-zA-Z0-9]+)', msg)
    license = license_match.group(1) if license_match else license

    server_id_match = re.search(r'\d{15,}', msg)
    server_id = server_id_match.group(0) if server_id_match else server_id

    print(f"Extracted License: {license}")
    print(f"Extracted Server ID: {server_id}")

    conn = sqlite3.connect('API.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM iosapi WHERE license = ?", (license,))
    valid_license = cursor.fetchone()

    if not valid_license:
        conn.close()
        return 'Invalid license', 400
    
    cursor.execute("SELECT * FROM iosapi WHERE server_id = ? AND license = ?", (server_id, license))
    valid_combo = cursor.fetchone()

    if not valid_combo:
        conn.close()
        return 'Invalid server ID', 400

    if not license.startswith('Star') or not server_id.isdigit():
        conn.close()
        return 'Invalid license or server ID', 400

    cursor.execute("SELECT time FROM requests WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ? ORDER BY time DESC LIMIT 1", 
                   (server_id, license, name, amount, "케이뱅크", "False"))
    existing_request = cursor.fetchone()

    if existing_request:
        request_time = datetime.datetime.strptime(existing_request[0], "%Y-%m-%d %H:%M:%S")
        current_time = datetime.datetime.now()

        # 10분이 지났는지 확인
        if current_time - request_time < datetime.timedelta(minutes=10):
            cursor.execute("UPDATE requests SET state = 'wait' WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ?", 
                           (server_id, license, name, amount, "케이뱅크", "False"))
            conn.commit()

    conn.close()
    return 'OK', 200

@app.route('/api/ios/bank/check', methods=['POST'])
def ioscharge():
    conn = sqlite3.connect('API.db')
    cursor = conn.cursor()
    data = request.json
    print(data)
    server_id = data.get('server_id')
    license = data.get('license')
    name = data.get('name')
    amount = data.get('amount')
    bank = data.get('bank')

    cursor.execute("SELECT * FROM iosapi WHERE license = ?", (license,))
    valid_license = cursor.fetchone()

    if not valid_license:
        return jsonify({'result': False, 'reason': '존재하지 않는 라이센스 입니다.'}), 403

    cursor.execute("SELECT * FROM iosapi WHERE server_id = ? AND license = ?", (server_id, license))
    valid_combo = cursor.fetchone()

    if not valid_combo:
        return jsonify({'result': False, 'reason': '라이센스가 올바르지 않습니다.'}), 403
    
    cursor.execute("SELECT * FROM requests WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ? ORDER BY time DESC LIMIT 1", 
                   (server_id, license, name, amount, bank, "wait"))
    existing_request = cursor.fetchone()

    if not existing_request:
        return jsonify({'result': False, 'reason': '입금 내역이 확인되지 않습니다.'}), 403

    if existing_request:
        cursor.execute("UPDATE requests SET state = 'True' WHERE server_id = ? AND license = ? AND name = ? AND amount = ? AND bank = ? AND state = ?", 
                       (server_id, license, name, amount, bank, "wait"))
        conn.commit()

    conn.close()
    return jsonify({'result': True, 'reason': '정상적으로 처리 되었습니다.', 'amount': amount, 'bank': bank}), 200

@app.route('/api/create_coin_request', methods=['POST'])
def create_coin_request():
    data = request.get_json()
    print(data)
    token = data.get('token', '')
    money = data.get('money', '')
    adder = data.get('adder', '')
    user_ip = getip()

    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    c.execute("SELECT * FROM license WHERE token = ? AND IP = ?", (token, user_ip))
    existing_request = c.fetchone()
    conn.close()
    
    if existing_request:
        conn = sqlite3.connect('request_list.db')
        c = conn.cursor()

        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute("SELECT * FROM request_list WHERE adder = ? AND money = ? AND end = ?", (adder, money, 'False'))
        existing_request = c.fetchone()

        if existing_request is None:
            new_money = float(money)
            c.execute("INSERT INTO request_list VALUES (?, ?, ?, ?)", (adder, money, current_time, 'False'))
        else:
            if existing_request[3] == 'True':
                new_money = float(money)
                c.execute("INSERT INTO request_list VALUES (?, ?, ?, ?)", (adder, money, current_time, 'False'))
            else:
                new_money = "{:.8f}".format(float(money) + random.uniform(0.00000001, 0.00000999))
                c.execute("INSERT INTO request_list VALUES (?, ?, ?, ?)", (adder, str(new_money), current_time, 'False'))

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': '요청 생성 성공', 'money' : new_money, 'adder' : adder}), 200
    else:
        return jsonify({'success': False, 'message': '라이센스 검증 실패'}), 403

@app.route('/api/check_coin_request', methods=['POST'])
def check_coin_request():
    data = request.get_json()
    token = data.get('token', '')
    txid = data.get('txid', '')
    type = data.get('type', '')
    adder = data.get('adder', '')
    user_ip = getip()

    con = sqlite3.connect('license.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM license WHERE token = ? AND IP = ?", (token, user_ip))
    existing_request = cur.fetchone()
    con.close()
    
    if existing_request:
        con = sqlite3.connect('request_list.db')
        cur = con.cursor()
        cur.execute("SELECT * FROM txid WHERE txid = ?;", (txid,))
        txid_serch = cur.fetchone()
        if txid_serch:
            return jsonify({'success': False, 'message': '이미 처리된 TXID 입니다.', 'txid' : txid}), 403

        url = f"https://api.blockcypher.com/v1/{type}/main/txs/{txid}"
        response = requests.get(url)
        if response.status_code == 200:
            print(response.status_code)
            tx_data = response.json()
            total_amount = sum(output['value'] for output in tx_data.get("outputs", [])) / 1e8
            sender = tx_data.get("inputs", [{"addresses": ["정보 없음"]}])[0]["addresses"][0]
            receiver = tx_data.get("outputs", [{"addresses": ["정보 없음"]}])[0]["addresses"][0] 
            print(total_amount, sender, receiver)

            cur.execute("SELECT * FROM request_list WHERE adder = ? AND money = ? AND end = ?", (receiver, total_amount, 'False'))
            result = cur.fetchone()

            if result:
                cur.execute("UPDATE request_list SET end = 'True' WHERE adder = ? AND money = ? AND end = 'False'", (adder, total_amount))
                con.commit()
                con.close()
                return jsonify({'success': True, 'message': '충전성공', 'txid' : txid, 'send_adder' : sender, 'get_adder': receiver, 'amount': total_amount}), 200
            else:
                con.close()
                return jsonify({'success': False, 'message': '올바르지 않는 TXID 입니다.'}), 403
        else:
            return jsonify({'success': False, 'message': '올바르지 않는 TXID 입니다.'}), 403
    else:
        return jsonify({'success': False, 'message': '라이센스 검증 실패'}), 403

@app.route("/api/fee", methods=["POST"])
def fee():
    data = request.get_json()
    money = int(data.get('money', 0))
    unit = data.get('unit')
    
    with open('proxies.txt', 'r') as f:
        lines = f.readlines()
        r = random.choice(lines).strip()
        
    proxies = {
        'http': r,
    }
    
    response = requests.get("https://api.exchangerate-api.com/v4/latest/USD")
    data = response.json()
    rate = data['rates']["KRW"]
    m = round(money / rate, 2)
    print(m)
    
    ltc_price = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=krw",proxies=proxies).json().get("litecoin", {}).get("krw")
    trx_price = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=tron&vs_currencies=krw",proxies=proxies).json().get("tron", {}).get("krw")
    btc_price = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=krw",proxies=proxies).json().get("bitcoin", {}).get("krw")
    eth_price = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=krw",proxies=proxies).json().get("ethereum", {}).get("krw")
    doge_price = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=dogecoin&vs_currencies=krw",proxies=proxies).json().get("dogecoin", {}).get("krw")    

    ltc_amount = round(money / ltc_price, 8) if ltc_price else '다시 시도 해주세요'
    trx_amount = round(money / trx_price, 8) if trx_price else '다시 시도 해주세요'
    btc_amount = round(money / btc_price, 8) if btc_price else '다시 시도 해주세요'
    eth_amount = round(money / eth_price, 8) if eth_price else '다시 시도 해주세요'
    doge_amount = round(money / doge_price, 8) if doge_price else '다시 시도 해주세요'
    
    return jsonify({
        'usd_amount': m,
        'ltc_amount': ltc_amount,
        'trx_amount': trx_amount,
        'btc_amount': btc_amount,
        'eth_amount': eth_amount,
        'doge_amount': doge_amount
    })

@app.route("/bank", methods=["POST"])
def _bank():
    ip = getip()
    if ip not in allowed_ip:
        print(f"사용불가능아이피에서의 요청 :" + ip)
        return {"result": False, "reason": "해당아이피는 사용가능한아이피가아닙니다.", "code": 7}
    
    obj = request.get_json()
    key = obj.get("api_key")
    bankpin = obj.get("bankpin")
    shop = obj.get("shop")
    userinfo = obj.get("userinfo")
    userid = obj.get("userid")
    token = obj.get("token")
    types = obj.get("type")
    amount = obj.get("amount")
    print(f"key : {key}\nbankpin : {bankpin}\nshop : {shop}\nuserinfo : {userinfo}\nuserid : {userid}\ntoken : {token}\ntypes : {types}\namount : {amount}")
    con = sqlite3.connect("databases/key.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM keyinfo WHERE key == ?;", (str(key),))
    key_info = cur.fetchone()
    cur.execute("INSERT INTO log (key, bankpin, shop, userinfo, userid, token, types, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (key, bankpin, shop, userinfo, userid, token, types, amount))
    con.commit()
    con.close()
    if (key_info != None):
        try:
            if (len(bankpin) != 34):
                return {"result": False, "reason": "계좌 비밀번호가 잘못되었습니다.", "code": 0}
        except Exception as e:
            print(e)
            return {"result": False, "reason": "계좌 비밀번호가 잘못되었습니다.", "code": 0}

        try:
            i = ""
            n = ""

            def on_message(ws, message):
                try:
                    try:
                        checktime()
                    except Exception as e:
                        raise Exception("시간제한")

                    obj = json.loads(message)
                    print(obj)
                    if obj["type"] == "push":
                        push = obj["push"]
                        body = push["body"].replace("\n", " ")
                        title = push["title"]
                        NotificationApplicationName = str(push["package_name"])
                        application_name = str(push["application_name"])
                        message = body.replace("원", "").replace(",", "").split(' ')
                        displayname = ""
                        count = 0

                        if NotificationApplicationName == "com.IBK.SmartPush.app":
                            sp = body.split(" ")
                            displayname = sp[2]
                            if sp[1].replace("원", "").replace(",", "").isdigit():
                                count = int(sp[1].replace("원", "").replace(",", ""))
                                
                        elif NotificationApplicationName == "com.kbstar.kbbank":
                            count = title.split(' ')[1].replace(",", "").replace("원", "")
                            if count.isdigit():
                                count = int(count)
                            else:
                                count = None

                            body_parts = body.split(' ')[4]
                            displayname = body_parts

                        elif application_name == "NH올원뱅크":
                            start_index = body.find("입금") + 2
                            end_index = body.find("원", start_index)
                            amount_str = body[start_index:end_index].strip().replace(",", "")
                            count = int(amount_str)

                            # 사용자 이름 추출
                            last_line = body.split("\n")[-1]
                            displayname = last_line.split()[-2]

                        elif NotificationApplicationName == "com.nh.mobilenoti":
                            displayname = message[5]
                            count = message[1].replace("입금", "").replace("원", "").replace(",", "")
                            if count.isdigit():
                                count = int(count)
                                
                        elif NotificationApplicationName == "nh.smart.banking":
                            displayname = message[5]
                            count = message[1].replace("입금", "").replace("원", "").replace(",", "")
                            if count.isdigit():
                                count = int(count)
                                
                        elif NotificationApplicationName == "nh.smart.nhcok":
                            displayname = message[5]
                            count = message[1].replace("입금", "").replace("원", "").replace(",", "")
                            if count.isdigit():
                                count = int(count)
                                
                        elif NotificationApplicationName == "com.wooribank.smart.npib":
                            sp = body.split(" ")
                            displayname = sp[1]
                            if sp[5].replace("원", "").replace(",", "").isdigit():
                                count = int(sp[5].replace("원", "").replace(",", ""))
                                
                        elif NotificationApplicationName == "com.kakaobank.channel":
                            name = body.split(" ")
                            if 'mini' in name[3]:
                                name = body.split(" ")
                                displayname = name[0]
                                if title.split(' ')[1].replace(",", "").replace("원", "").isdigit():
                                    count = int(title.split(' ')[1].replace(",", "").replace("원", ""))
                            else:
                                name = body.split(" ")
                                displayname = name[0]
                                if title.split(' ')[1].replace(",", "").replace("원", "").isdigit():
                                    count = int(title.split(' ')[1].replace(",", "").replace("원", ""))

                        elif NotificationApplicationName == "com.kebhana.hanapush":
                            name = body.split(" ")
                            displayname = name[0]

                            if list(reversed(name))[5].replace("원", "").replace(",", "").isdigit():
                                count = int(list(reversed(name))[5].replace("원", "").replace(",", ""))
                                
                        elif NotificationApplicationName == "com.kbstar.starpush":
                            name = body.split(" ")
                            if name[5].replace(',', '').isdigit():
                                displayname = name[3]
                                count = int(name[5].replace(',', ''))

                        elif NotificationApplicationName == "com.kbankwith.smartbank":
                            name = body.split(" ")
                            if name[1].replace(",", "").replace("원", "").isdigit():
                                displayname = name[2]
                                count = int(name[1].replace(",", "").replace("원", ""))

                        elif NotificationApplicationName == "com.shinhan.sbanking":
                            name = body.split(" ")
                            if name[0].replace(',', '').replace('원', '').isdigit():
                                displayname = name[1]
                                count = int(name[0].replace(',', '').replace('원', ''))

                        elif NotificationApplicationName == "viva.republica.toss":
                            name = body.split(" ")

                            if '토스증권' in name[1]:
                                titles = title.replace("원 입금", "").replace(",", "")

                                if titles.isdigit():
                                    displayname = str(name[4])
                                    count = int(titles)
                            
                            elif '인사를' == name[1]:
                                titles = title.replace("원을 받았어요", "").replace(",", "")

                                if titles.isdigit():
                                    displayname = str(name[0])[:-3]
                                    count = int(titles)
                            elif len(name) >= 3:

                                if'토스증권' in name[3]:
                                    titles = title.replace(
                                        "원 입금", "").replace(",", "")

                                    if titles.isdigit():
                                        displayname = str(name[0])
                                        count = int(titles)      
                                elif '토스뱅크' in name[3]:
                                    titles = title.replace(
                                        "원 입금", "").replace(",", "")

                                    if titles.isdigit():
                                        displayname = str(name[0])
                                        count = int(titles)

                            else:
                                titles = title.replace("원을 받았어요", "").replace(",", "")

                                if titles.isdigit():
                                    displayname = str(name[0])[:-3]
                                    count = int(titles)

                        elif NotificationApplicationName == "com.smg.mgnoti":
                            titles = body.split(" ")[1].replace(
                                ',', '').replace('원', '')

                            if titles.isdigit():
                                name = body.split(' ')[-1]
                                displayname = str(name)
                                count = int(titles)

                        elif NotificationApplicationName == 'com.kbstar.reboot':
                            name = body.split(' ')
                            if str(name[1].replace(',', ''))[:-2].isdigit():
                                displayname = str(name[0])[:-2]
                                count = int(str(name[1].replace(',', ''))[:-2])

                        else:
                            print(f"BankAPI[ERROR]: not found NotificationApplicationName")

                        if displayname == userinfo:
                            print(displayname, userinfo, types)
                            try:
                                if types == False:

                                    print(f'{displayname} / {userinfo}')
                                    print(
                                        f"{str(shop)}서버의 {str(displayname)}님이 {str(count)}원을 충전하셨습니다.")
                                    raise Exception(
                                        f"성공|{shop}|{displayname}|{count}|{userid}|{types}|")
                                if types == True:
                                    if int(amount) == int(count):
                                        print(
                                            f'{displayname} / {userinfo}')
                                        print(
                                            f"{str(shop)}서버의 {str(displayname)}님이 {str(count)}원을 충전하셨습니다.")
                                        raise Exception(
                                            f"성공|{shop}|{displayname}|{count}|{userid}|{types}")
                            except Exception as e:
                                print(e)
                                raise Exception(
                                    f"성공|{shop}|{displayname}|{count}|{userid}|{types}")
                except Exception as e:
                    print(f"BankAPI[ERROR]: {e}")
                    if not str(e) == "'body'":
                        raise Exception(e)

            max_time_end = time.time() + 270

            def checktime():
                if time.time() > max_time_end:
                    raise Exception("시간제한")
                    print("timeout")
            try:
                threading.Timer(10, checktime).start()
            except Exception as e:
                raise Exception("시간제한")

            try:
                def go(id, count):
                    i = id
                    n = count

                    @client.event
                    async def on_ready():
                        user = await client.fetch_user(i)
                        await user.send(embed=discord.Embed(color=0x2acaea, title="입금확인이 완료되었습니다!", description=f"입금유저: <@{str(i)}>\n입금 금액: {n}원\n입금시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"))
                    client.run(token)
            except Exception as e:
                print(e)
                raise Exception("에러")

            try:
                def gose(id, msg):
                    i = id
                    n = msg

                    @client.event
                    async def on_ready():
                        user = await client.fetch_user(i)
                        await user.send(embed=discord.Embed(color=0x2acaea, title="제한시간이 다 되었습니다.", description=f"유저 아이디: {i}\n{n}"))
                    client.run(token)
            except Exception as e:
                print(e)
                raise Exception("에러")

            def on_error(ws, error):
                print(error)
                raise Exception(error)
                print("error:", error)

            def on_close(ws):
                print("### closed ###")

            def on_open(ws):
                print("Opened")

            if __name__ == "__main__":
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                ws = websocket.WebSocketApp(
                    "wss://stream.pushbullet.com/websocket/" + bankpin,
                    on_message=on_message,
                    on_error=on_error,
                    on_close=on_close
                )
                
                ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

        except Exception as e:
            print(f"HOO {str(e)}")
            if (str(e)[:2] == "성공"):
                print("성공쓰")
                msg = str(e)
                shop = msg.split("|")[1]
                displayname = msg.split("|")[2]
                count = msg.split("|")[3]
                userid = msg.split("|")[4]
                types = msg.split("|")[5]

                return {"result": True, "id": userid, "guild": shop, "name": displayname, "count": count, "code": 200}
            elif (str(e) == "에러"):
                return jsonify({"result": False, "reason": "에러가 발생했습니다.", "code": 3})
            elif (str(e) == "시간제한"):
                print('제한시간 감지하고 값 반환함')
                return jsonify({"result": False, "reason": "제한시간이 다 되었습니다.", "code": 4})
            else:
                return jsonify({"result": False, "reason": "예외치 않은 경우입니다.", "code": 5})
    else:
        return {"result": False, "reason": "API KEY가 존재하기 않습니다.", "code": 6}

@ app.before_request
def before_request():
    session.permanent = True

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5032)