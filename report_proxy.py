#!/usr/bin/env python3
import os,glob,datetime,argparse
import base64,json
import hashlib,codecs,struct
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import sqlite3
from pypush_gsa_icloud import icloud_login_mobileme, generate_anisette_headers
from flask import Flask, request, jsonify

app = Flask(__name__)

sq3db = sqlite3.connect(os.path.dirname(os.path.realpath(__file__)) + '/reports.db')

@app.route('/getLocationReports', methods=['POST'])
def get_location_reports():
    try:
        # Get the JSON data from the request
        data = request.json

        # Access the 'ids' key from the JSON data
        ids = data.get('ids', [])
        
        #sq3 = sq3db.cursor()



        unixEpoch = int(datetime.datetime.now().strftime('%s'))
        #startdate = unixEpoch - (60 * 60 * args.hours)
        startdate = unixEpoch - (60 * 60 * 48)
        data = { "search": [{"startDate": startdate *1000, "endDate": unixEpoch *1000, "ids": list(ids)}] }

        r = requests.post("https://gateway.icloud.com/acsnservice/fetch",
                auth=getAuth(regenerate=args.regen, second_factor='trusted_device' if args.trusteddevice else 'sms'),
                headers=generate_anisette_headers(),
                json=data)
        res = json.loads(r.content.decode())['results']
        print(f'{r.status_code}: {len(res)} reports received.')



        

        print(f'found:   {list(res)}')
        #print(f'missing: {[key for key in names.values() if key not in found]}')
        #sq3.close()
        #sq3db.commit()

        return r.content.decode()

    except Exception as e:
        # Handle exceptions as needed
        return jsonify({"status": "error", "message": str(e)})
    
def sha256(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()

def decrypt(enc_data, algorithm_dkey, mode):
    decryptor = Cipher(algorithm_dkey, mode, default_backend()).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()

def decode_tag(data):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], 'big')
    status = int.from_bytes(data[9:10], 'big')
    return {'lat': latitude, 'lon': longitude, 'conf': confidence, 'status':status}

def getAuth(regenerate=False, second_factor='sms'):
    CONFIG_PATH = os.path.dirname(os.path.realpath(__file__)) + "/auth.json"
    if os.path.exists(CONFIG_PATH) and not regenerate:
        with open(CONFIG_PATH, "r") as f: j = json.load(f)
    else:
        mobileme = icloud_login_mobileme(second_factor=second_factor)
        j = {'dsid': mobileme['dsid'], 'searchPartyToken': mobileme['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']}
        with open(CONFIG_PATH, "w") as f: json.dump(j, f)
    return (j['dsid'], j['searchPartyToken'])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--hours', help='only show reports not older than these hours', type=int, default=24)
    parser.add_argument('-p', '--prefix', help='only use keyfiles starting with this prefix', default='')
    parser.add_argument('-r', '--regen', help='regenerate search-party-token', action='store_true')
    parser.add_argument('-t', '--trusteddevice', help='use trusted device for 2FA instead of SMS', action='store_true')
    args = parser.parse_args()

    app.run(host="0.0.0.0")
    sq3db.close()