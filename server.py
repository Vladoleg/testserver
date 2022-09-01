from flask import Flask, render_template, url_for
from pymongo import MongoClient
from pprint import pprint
import datetime as dt

#Connecting to mongodb
client=MongoClient("mongodb://localhost:27017/")
my_db=client.cvedb
collection =  my_db.cves

#static variables
fields=['id', 'assigner', 'Published', 'Modified', 'last-modified', 'summary', 'impactScore', 'impactScore3', 'exploitabilityScore', 'exploitabilityScore3', 'references', 'vendors', 'cwe', 'vulnerable_configuration_cpe_2_2']
now=dt.datetime.today()
far=dt.datetime(2022, 7, 1)
cve=[]
elem=[]
a = {}

app = Flask(__name__)
vendors = [{'name': 'huawei', 'url': 'huawei'},
           {'name': 'dell', 'url': 'dell'},
           {'name': 'redhat', 'url': 'redhat'},
           {'name': 'vmware', 'url': 'vmware'},
           {'name': 'veeam', 'url': 'veeam'},
           {'name': 'netapp', 'url': 'netapp'},
           {'name': 'lenovo', 'url': 'lenovo'},
           {'name': 'fujitsu', 'url': 'fujitsu'},
           {'name': 'juniper', 'url': 'juniper'},
           {'name': 'mikrotik', 'url': 'mikrotik'},
           {'name': 'intel', 'url': 'intel'}]

#selecting last 15 documents for mainpage and vendors



def last15(vndr):
	elem.clear()
	elem2 = []
	for i in collection.find({'vendors': vndr}, {'_id':0, 'id':1, 'Published':1, 'last-modified':1}).limit(3):
		elem.append({'name': i['id'], 'url': 'cveinfo/'+i['id']})
		elem2


def last():
	li = ['id', 'Published', 'last-modified']
	for i in collection.find({}, {fields[0]: 1, fields[2]:1, fields[4]:1, '_id':0}).limit(3):
#		a = {x: i[x]  for x in li}
		print (i)

last()
'''
def last_v(vendor):
	elem.clear()
	for i in collection.find({'vendors': vendor}, {" last-modified": {"$slice": -15}}).limit(15):
		elem.append({'name': i['id'], 'url': 'cveinfo/'+i['id']})
	return elem

# Main page with last 15 cve
@app.route('/')
def index():
	last()
	return render_template('index.html', vendors=vendors, e=a)

#vendor page with last 15 cve
@app.route('/<vendor>')
def vendor(vendor):
	last_v(vendor)
	return render_template('vendors.html', vendors=vendors, elem=elem, v=vendor)

#table for cve ID
@app.route('/cveinfo/<cveid>')
def cvepage(cveid):
	cve = collection.find_one({'id': cveid})
	return render_template('cveinfo.html', vendors=vendors, cve=cve, fields=fields)


if __name__=="__main__":
	app.run(debug=True, host='192.168.0.9', port=80)

'''
