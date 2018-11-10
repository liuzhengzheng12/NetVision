import httplib

conn = httplib.HTTPConnection("10.0.2.22", 80)

while True:
    conn.request('GET', '/')
    conn.getresponse().read()

conn.close()