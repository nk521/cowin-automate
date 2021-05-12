from typing import Dict, List
import requests
import json
import sys
import hashlib
from hashlib import md5
from Cryptodome import Random
from Cryptodome.Cipher import AES
import base64

BLOCK_SIZE = 16
SECRET = b"b5cab167-7977-4df1-8027-a63aa144f04e"
KEY = b"CoWIN@$#&*(!@%^&"

def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + (chr(length)*length).encode()

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

def encrypt(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))

BASEURL = "https://cdn-api.co-vin.in/api/v2"
HEADERS = {
    'authority': 'cdn-api.co-vin.in',
    'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"',
    'accept': 'application/json',
    'sec-ch-ua-mobile': '?0',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
    'content-type': 'application/json',
    'origin': 'https://apisetu.gov.in',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
    'referer': 'https://apisetu.gov.in/public/marketplace/api/cowin',
    'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
}


class CoWin:
    def __init__(self, phonenumber, otp, txnId, debug=False):
        self.phonenumber = phonenumber
        self.otp = otp
        self.txnId = txnId
        self.debug = debug
        self.token = ""
        self.goodToGoCenters = []
        self.confirmOtp()
    
    @staticmethod
    def sendOtp(phonenumber, debug=False):
        # this is the API that the website uses
        # theres also a secret block that goes in with mobile as param
        # its made using cryptojs afaiu and the key is "CoWIN@$#&*(!@%^&" as far as I've reversed the JS source
        # "b5cab167-7977-4df1-8027-a63aa144f04e" is the "default"
        ############################################################
        ############################################################
        # anonymousLogin() {
        #             return this.http.post(i.a.auth_prefix_url + "/guest/login", {
        #                 user_name: "b5cab167-7977-4df1-8027-a63aa144f04e"
        #             }, {
        #                 responseType: "text"
        #             }).pipe(Object(r.a)(t=>t))
        #         }
        ############################################################
        ############################################################
        
        p = {"mobile": str(phonenumber)}
        p["secret"] = encrypt(SECRET, KEY).decode()

        r = requests.post(BASEURL+"/auth/generateMobileOTP", data=json.dumps(p), headers=HEADERS)
        if r.text == "OTP Already Sent":
            print(f"OTP already sent! If not received then try again after 3 minutes.")
        elif r.text.find("txnId"):
            response_text = eval(r.text)
            print(f"OTP sent to +91-{phonenumber}. This OTP is valid for 3 minutes.")
            if debug:
                print(f"DEBUG: txnId -> {response_text['txnId']}")
            return {"txnId": response_text['txnId']}
        else:
            print("Something went wrong while sending OTP. Closing.")
            sys.exit(-1)

    def confirmOtp(self):
        p = {
                "otp": hashlib.sha256(self.otp.encode()).hexdigest(),
                "txnId": self.txnId
            }
        r = requests.post(BASEURL+"/auth/validateMobileOtp", data=json.dumps(p), headers=HEADERS)
        if r.status_code == 200:
            self.token = eval(r.text)["token"]
            print(f"Logged in successfully as +91-{self.phonenumber}")
            if self.debug:
                print(f"DEBUG: token -> {self.token}")
        
        else:
            print("Something went wrong while confirming OTP. Try again. Closing.")
            sys.exit(-1)
    
    def listAllFamilyMembers(self):
        r = requests.get(BASEURL+"/appointment/beneficiaries", headers={**HEADERS, **{"authorization": f"Bearer {self.token}"}})
        familyMembers: List[Dict] = eval(r.text)["beneficiaries"]
        
        for familyMember in familyMembers:
            print("\n" + "="*20 + "\n")
            print(f"Reference ID : {familyMember['beneficiary_reference_id']}")
            print(f"Name : {familyMember['name']}")
            print(f"Birth Year : {familyMember['birth_year']}")
            print(f"Gender : {familyMember['gender']}")
            print(f"Mobile Number : {familyMember['mobile_number']}")
            print(f"Photo ID Type : {familyMember['photo_id_type']}")
            print(f"Photo ID Number : {familyMember['photo_id_number']}")
            print(f"Vaccination Status : {familyMember['vaccination_status']}")
            print(f"Vaccine : {familyMember['vaccine']}")
            print(f"Dose 1 Date : {familyMember['dose1_date']}")
            print(f"Dose 2 Date : {familyMember['dose2_date']}")
            # print(f"Appointments : {familyMember['beneficiary_reference_id']}")
    
    def findByPincode(self, pinCode, dateForVaccineSearch):
        p = {"pincode": pinCode, "date": f"{dateForVaccineSearch[0]}-{dateForVaccineSearch[1]}-2021"}
        r = requests.get(BASEURL + "/appointment/sessions/public/calendarByPin", params=p, headers={**HEADERS, **{"Accept-Language": "hi_IN"}, **{"authorization": f"Bearer {self.token}"}})
        
        if r.status_code == 200:
            vaccineCenters: List[Dict] = eval(r.text)["centers"]

            for vaccineCenter in vaccineCenters:
                for session in vaccineCenter["sessions"]:
                    if session["min_age_limit"] == 18 and session["available_capacity"] > 0:
                        self.goodToGoCenters.append(vaccineCenter)

            if not len(self.goodToGoCenters):
                print("No vaccine centers available!")
            
            else:
                print(self.goodToGoCenters)


debug = True
phonenumber = input("Enter your phone number (without country code) : ")
otp_send_successfull = CoWin.sendOtp(phonenumber=phonenumber, debug = debug)
if otp_send_successfull:
    otp = input("Enter your OTP : ")
    CoWinObj = CoWin(phonenumber=phonenumber, otp=otp, txnId=otp_send_successfull["txnId"], debug=debug)
    CoWinObj.listAllFamilyMembers()
    pinCode = input("Enter your pincode : ")
    dateForVaccineSearch = input("Enter the date (dd/mm | add a forward slash) (Leave it blank if you want to search it for tomorrow) : ").split("/")
    CoWinObj.findByPincode(pinCode=pinCode, dateForVaccineSearch=dateForVaccineSearch)
