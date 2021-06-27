import requests
url = "https://www.fast2sms.com/dev/bulk"
payload = "sender_id=FSTSMS&message=Hi noob! Your verification code is : 234678 &language=english&route=p&numbers=7977535465"
headers = {
    'authorization': "xmSHAJhecCogOEzUudp1vMPl7w2a6D53RIWt89X0kVLFnYNZfrFQfLkclToD62CNMOpdGSvj1X98Pa4K",
    'Content-Type': "application/x-www-form-urlencoded",
    'Cache-Control': "no-cache",
}
response = requests.request("POST", url, data=payload, headers=headers)
print(response.text)
