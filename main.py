import base64
import datetime
import os
import re
import json
import time
import datetime
from flask import *
from flask import jsonify
import requests
from subscriber import SubscriberType
import jsonpickle

from flask import request
import fire as fire
import nacl.encoding
import nacl.hash
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from nacl.signing import SigningKey, VerifyKey



f = open(os.getenv("REQUEST_BODY_PATH", "./request_body_raw_text.json"), "r")
request_body_raw_text = f.read()
# reqBody= json.dumps(request_body_raw_text)


AuthHeader = 'Signature keyId="nsdl.co.in|47|ed25519",algorithm="ed25519", created="1672325938", expires="1672925938", headers="(created) (expires) digest", signature="lwuXg/36gtZyOr97fQzW5YrFcKfWCOgzrOA1tmjMZ5EK/nmnJo8YuZcvKUsOsX93XDd5wlhig4iuvfo8bQL8CQ=="'
# AuthHeader = 'Signature keyId="nsdl.co.in|47|ed25519",algorithm="ed25519", created="1672123702", expires="1672723702", headers="(created) (expires) digest", signature="YC42uhj5mtieB++QyEKsskim4fTNPxAS/R4UedotQO1Oz3/3s4z4+OoYE8mDLeEa8VcnBW09wgau5jICmtSQAQ=="'
# AuthHeader = 'Signature keyId="ondcstore.com|344|ed25519",algorithm="ed25519",created="1672129386",expires="1672302186",headers="(created) (expires) digest",signature="0PS39ieDEmGc1DLAgN3Q2yCfLpTzAnNvjIXBDJrxY/iCHdr1O2DRSEGuGnjfabG/g2G48Hn3n7KCxU5d5R1aCg=="'
# publicKey =  'lqegf0O1Ok+FPEWqaAH9OswRldrH6ClQ2b895TwHucc='
# publicKey =  'Fhjwaka1Za+ld+7Nms7S0C675r24mZoyWVn8JbYTjSs='
publicKey = ''


# AuthHeader = ''

app = Flask(__name__)


def verify_response(signature, signing_key, public_key):
    try:
        # print(signature, signing_key, public_key)
        public_key64 = base64.b64decode(public_key)
        VerifyKey(public_key64).verify(bytes(signing_key, 'utf8'), base64.b64decode(signature))
        return True
    except Exception:
        return False


def lookup_call(url, payload):
    # print(url, payload)
    response = requests.post(url, json=payload)
    print("ResponseCode:  ", response.status_code)
    # print(response.text)
    return json.loads(response.text), response.status_code


# def get_filter_dictionary_or_operation(filter_string):
#     filter_string_list = re.split(',', filter_string)
#     filter_string_list = [x.strip(' ') for x in filter_string_list]  # to remove white spaces from list
#     filter_dictionary_or_operation = dict()
#     for fs in filter_string_list:
#         splits = fs.split('=', maxsplit=1)
#         print("Splits:    ", splits)
#         key = splits[0].strip()
#         print("Key:     ", key)
#         value = splits[1].strip()
#         print("Value:   ", value)
#         filter_dictionary_or_operation[key] = value.replace("\"", "")
#     return filter_dictionary_or_operation


def get_bpp_public_key_from_header(auth_header):
    header_parts = get_filter_dictionary_or_operation(auth_header.replace("Signature ", ""))
    subscriber_type = SubscriberType.BG.name
    # print("SubscriberType", subscriber_type)
    payload = {"type": subscriber_type, "domain": "nic2004:52110",
               "subscriber_id": header_parts['keyId'].split("|")[0]}  # "domain": get_config_by_name('DOMAIN')

    # print(payload)

    # response, status_code = lookup_call(f"{get_config_by_name('https://pilot-gateway-1.beckn.nsdl.co.in')}/lookup", payload=payload)
    response, status_code = lookup_call('https://pilot-gateway-1.beckn.nsdl.co.in/lookup', payload=payload)
    if status_code == 200:
        # print("Signing_Public_Key:    ", response[0]['signing_public_key'])
        return response[0]['signing_public_key']
    else:
        return None


def hash_message(msg):
    HASHER = nacl.hash.blake2b
    digest = HASHER(bytes(msg, 'utf-8'), digest_size=64, encoder=nacl.encoding.Base64Encoder)
    # digest = HASHER([str(d, 'UTF-8') for d in msg], digest_size=64, encoder=nacl.encoding.Base64Encoder)
    digest_str = digest.decode("utf-8")
    return digest_str


def create_signing_string(digest_base64, created=None, expires=None):
    if created is None:
        created = int(datetime.datetime.now().timestamp())
    if expires is None:
        expires = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
    signing_string = f"""(created): {created}
(expires): {expires}
digest: BLAKE-512={digest_base64}"""
    print("SigningString by create_signing_string function:   ", signing_string)
    return signing_string


def get_filter_dictionary_or_operation(filter_string):
    filter_string_list = re.split(',', filter_string)
    filter_string_list = [x.strip(' ') for x in filter_string_list]  # to remove white spaces from list
    filter_dictionary_or_operation = dict()
    for fs in filter_string_list:
        splits = fs.split('=', maxsplit=1)
        # print("Splits:  ",splits)
        key = splits[0].strip()
        # print("Key:  ", key)
        value = splits[1].strip()
        # print("Value:  ", value)
        filter_dictionary_or_operation[key] = value.replace("\"", "")
        # print(filter_dictionary_or_operation)
    return filter_dictionary_or_operation


@app.route('/verifyBgSignature', methods=['POST'])
def verify_authorisation_header(auth_header=AuthHeader, request_body_str=request_body_raw_text,
                                public_key=os.getenv("PUBLIC_KEY")):
    # `request_body_str` should request.data i.e. raw data string

    # `public_key` is sender's public key
    # i.e. if Seller is verifying Buyer's request, then seller will first do lookup for buyer-app
    # and will verify the request using buyer-app's public-key
    authHeaderReq = request.headers['Authorization']
    # authHeaderReq = request.headers['X-Gateway-Authorization']
    req_raw_body = request.data.decode('UTF-8')
    # print("Authorization from request header:   ",authHeaderReq)
    # print("Raw Payload in Request:   ", req_raw_body)
    # print("Before AUthHeader:  ", auth_header)
    # print("Before reqBody:   ",request_body_str)
    auth_header = authHeaderReq
    request_body_str = req_raw_body
    # print("Final AuthHeader Passing:  ", authHeaderReq)
    # print('\n')
    # print("Final reqBody Passing:  ", request_body_str)
    # print('\n')

    minifyFormat = "".join(request_body_str.split())
    print("Minify Format Paylad:   ", minifyFormat)
    # print('\n')

    header_parts = get_filter_dictionary_or_operation(auth_header.replace("Signature ", ""))
    created = int(header_parts['created'])
    expires = int(header_parts['expires'])
    # print(header_parts['signature'])
    # print(created, expires)

    current_timestamp = int(datetime.datetime.now().timestamp())
    # print(current_timestamp)
    if created <= current_timestamp <= expires:
        signing_key = create_signing_string(hash_message(minifyFormat), created=created, expires=expires)
        # print("SigningKey:  ", signing_key)

        bap_publickey = get_bpp_public_key_from_header(auth_header)  # changes
        print("Public-Key:   ", bap_publickey)
        print("is Signature Verified:  ", verify_response(header_parts['signature'], signing_key, bap_publickey))
        signVerified = verify_response(header_parts['signature'], signing_key, public_key=bap_publickey)

        return jsonpickle.encode(signVerified)
    #     return verify_response(header_parts['signature'], signing_key, public_key=bap_publickey)

    # else:

    #     response = jsonify({'message':'NACK: Signature Verification Failed'})
    # return response, 401


if __name__ == '__main__':
    # verify_authorisation_header(AuthHeader, request_body_raw_text, publicKey)
    # verify_authorisation_header(request.headers.get['Authorization'], request.data, publicKey)
    app.run(debug=True, port=3420)
# verify_authorisation_header(request.headers['Authorization'], request.get_json, publicKey)





