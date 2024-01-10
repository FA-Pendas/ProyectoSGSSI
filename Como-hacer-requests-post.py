#https://www.w3schools.com/python/ref_requests_post.asp

import requests

url = 'http://localhost:5000/'
myobj = {'somekey': 'somevalue'}

x = requests.post(url, json = myobj)

print(x.text)