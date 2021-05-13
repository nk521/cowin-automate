from typing import Dict, List
import requests
import json
import sys
import hashlib
from hashlib import md5
from Cryptodome import Random
from Cryptodome.Cipher import AES
import base64
import datetime
import time

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
    def __init__(self, phonenumber, debug=False):
        self.phonenumber = phonenumber
        self.otp = ""
        self.txnId = ""
        self.debug = debug
        self.token = ""
        self.goodToGoCenters = []
        self.familyMembers = []
        self.selectedFamilyMembers = []
        self.selectedFamilyMembersNumber = 0
        self.isVaccineBooked = False
    
    def sendOtp(self):
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
        
        p = {"mobile": str(self.phonenumber)}
        p["secret"] = encrypt(SECRET, KEY).decode()

        r = requests.post(BASEURL+"/auth/generateMobileOTP", data=json.dumps(p), headers=HEADERS)
        if r.text == "OTP Already Sent":
            print(f"OTP already sent! If not received then try again after 3 minutes.")
        
        elif r.text.find("txnId"):
            response_text = eval(r.text)
            print(f"OTP sent to +91-{phonenumber}. This OTP is valid for 3 minutes.")
            
            if self.debug:
                print(f"DEBUG: txnId -> {response_text['txnId']}")
            
            self.txnId = response_text['txnId']
        
        else:
            print("Something went wrong while sending OTP. Closing.")
            sys.exit(-1)


    def confirmOtp(self):
        while True:
            self.otp = input("Enter your OTP : ")
            
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
                
                break
            
            elif r.status_code == 400 and (eval(r.text).get("error") == "Invalid OTP"):
                print("Wrong OTP! Try again!")
                continue

            else:
                print("Something went wrong while confirming OTP. Try again. Closing.")
                sys.exit(-1)
    
    def _listAllFamilyMembers(self):
        r = requests.get(BASEURL+"/appointment/beneficiaries", headers={**HEADERS, **{"authorization": f"Bearer {self.token}"}})
        self.familyMembers: List[Dict] = eval(r.text)["beneficiaries"]
        
        # for familyMember in self.familyMembers:
        #     print("\n" + "="*20 + "\n")
        #     print(f"Reference ID : {familyMember['beneficiary_reference_id']}")
        #     print(f"Name : {familyMember['name']}")
        #     print(f"Birth Year : {familyMember['birth_year']}")
        #     print(f"Gender : {familyMember['gender']}")
        #     print(f"Mobile Number : {familyMember['mobile_number']}")
        #     print(f"Photo ID Type : {familyMember['photo_id_type']}")
        #     print(f"Photo ID Number : {familyMember['photo_id_number']}")
        #     print(f"Vaccination Status : {familyMember['vaccination_status']}")
        #     print(f"Vaccine : {familyMember['vaccine']}")
        #     print(f"Dose 1 Date : {familyMember['dose1_date']}")
        #     print(f"Dose 2 Date : {familyMember['dose2_date']}")
        #     # print(f"Appointments : {familyMember['beneficiary_reference_id']}")
    
    def getFamilyMembersSelection(self):
        #init
        self._listAllFamilyMembers()
        for x, familyMember in enumerate(self.familyMembers):
            print(f"[{x+1}] - {familyMember['name']} | {familyMember['gender']}")
        
        self.selectedFamilyMembers = input("Enter comma seperated values : ").split(",")
        self.selectedFamilyMembers = [int(x) - 1 for x in self.selectedFamilyMembers]
        self.selectedFamilyMembersNumber = len(self.selectedFamilyMembers)
        
        # Oh yeah look at this garbage
        print(f"Selected {str([self.familyMembers[x]['name'] for x in self.selectedFamilyMembers])[1:-1]}")
    
    def findByPincodeAndBookVaccine(self, pinCode, dateForVaccineSearch):

        while True:
            # date is in format dd-mm-yyyy
            p = {"pincode": pinCode, "date": f"{dateForVaccineSearch}-2021"}
            r = requests.get(BASEURL + "/appointment/sessions/public/calendarByPin", params=p, headers={**HEADERS, **{"Accept-Language": "hi_IN"}, **{"authorization": f"Bearer {self.token}"}})
            
            if r.status_code == 200:
                vaccineCenters: List[Dict] = eval(r.text)["centers"]

                # print("\n\nDEBUG\n\n" + str(vaccineCenters[0]))
                for vaccineCenter in vaccineCenters:
                    for session in vaccineCenter["sessions"]:
                        # Doing this bc I want my family members to go in the same center
                        if session["min_age_limit"] == 18:
                            self.goodToGoCenters.append(vaccineCenter)
                            break

                if len(self.goodToGoCenters) > 0:
                    print("No vaccine centers available!")
                
                else:
                    print(f"Found {len(self.goodToGoCenters)} centers! Booking vaccines!")
                    self._bookVaccine()
                    if self.isVaccineBooked:
                        break
            
            # need to find a cleaner way to do this. 
            # 100 calls/5 minutes/IP
            time.sleep(5)


    def _bookVaccine(self):
        # try booking for this center
        # if not successfull then next center
        # if not successfull in all centers then clear self.goodToGoCenters
        # if successfull then switch self.isVaccineBooked to True
        
        # {
        #   "center_id": 1289,
        #   "name": "lalalalala",
        #   "address": "lalalallaa",
        #   "state_name": "Delhi",
        #   "district_name": "asfgasg",
        #   "block_name": "Not Applicable",
        #   "pincode": 110001,
        #   "lat": 28,
        #   "long": 77,
        #   "from": "09:00:00",
        #   "to": "17:00:00",
        #   "fee_type": "Free",
        #   "sessions": [
        #     {
        #       "session_id": "7d5380d3-4517-41d3-a644-d07263829064",
        #       "date": "13-05-2021",
        #       "available_capacity": 0,
        #       "min_age_limit": 18,
        #       "vaccine": "COVAXIN",
        #       "slots": [
        #         "09:00AM-11:00AM",
        #         "11:00AM-01:00PM",
        #         "01:00PM-03:00PM",
        #         "03:00PM-05:00PM"
        #       ]
        #     },
        #     {
        #       "session_id": "7d5380d3-4517-41d3-a644-328758390765",
        #       "date": "15-05-2021",
        #       "available_capacity": 0,
        #       "min_age_limit": 45,
        #       "vaccine": "COVAXIN",
        #       "slots": [
        #         "09:00AM-11:00AM",
        #         "11:00AM-01:00PM",
        #         "01:00PM-03:00PM",
        #         "03:00PM-05:00PM"
        #       ]
        #     }
        #   ]
        # }

        for center in self.goodToGoCenters:
            if not center["fee_type"] == "Free":
                continue
            
            for session in center["sessions"]:
                if session["min_age_limit"] == 18:
                    if session["available_capacity"] >= self.selectedFamilyMembersNumber:
                        p = {
                                "dose": 1,
                                "session_id": session["session_id"],
                                "slot": session["slots"][-1],
                                "beneficiaries": [self.familyMembers[x]['beneficiary_reference_id'] for x in self.selectedFamilyMembers]
                            }
                        
                        r = requests.post(BASEURL+"/appointment/schedule", data=json.dumps(p), headers=HEADERS)

                        if r.status_code == 200:
                            self.isVaccineBooked = True
                            self.appointment_id = eval(r.text)["appointment_id"]
                            print(f"Vaccine Booked! Appointment ID -> {eval(r.text)['appointment_id']}")
                            print(f"Vaccine -> {eval(r.text)['appointment_id']}")
                            print(f"slot -> {session['slots'][-1]}")
                            print(f"Center Name -> {center['name']}")
                            print(f"Center Address -> {center['address']}")
                            
                            break
                        
                        else:
                            self.isVaccineBooked = False
                            continue
                
                time.sleep(0.5)


debug = True
phonenumber = input("Enter your phone number (without country code) : ")
CoWinObj = CoWin(phonenumber=phonenumber, debug=debug)
CoWinObj.sendOtp()
CoWinObj.confirmOtp()
CoWinObj.getFamilyMembersSelection()
pinCode = input("Enter your pincode : ")

dateForVaccineSearch = int(input(f"How many days from today? : "))
dateForVaccineSearch = (datetime.date.today() + datetime.timedelta(days=int(dateForVaccineSearch))).strftime("%d-%m")
print(f"Selected date -> {(datetime.date.today() + datetime.timedelta(days=dateForVaccineSearch)).strftime('%d-%m-%Y')}")

CoWinObj.findByPincodeAndBookVaccine(pinCode=pinCode, dateForVaccineSearch=dateForVaccineSearch)
