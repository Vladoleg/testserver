from flask import Flask, render_template, url_for
from pymongo import MongoClient
from pprint import pprint
import datetime as dt

#Connecting to mongodb
client=MongoClient("mongodb://localhost:27017/")
my_db=client.cvedb
collection =  my_db.cves

#static variables
fields=['id', 'assigner', 'Published', 'Modified', 'last-modified', 'summary', 'impactScore', 'impactScore3', 
		'exploitabilityScore', 'exploitabilityScore3', 'references', 'vendors', 'cwe', 'vulnerable_configuration_cpe_2_2']
cve=[]
elem=[]
a = {}
now = dt.datetime.today()
week = now - dt.timedelta(days=7)
month = now - dt.timedelta(days=30)
year = now - dt.timedelta(days=355)
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

#selecting last 15 documents for mainpage or vendor page
def last_15(*vendor):
	elem.clear()
	li = {'id':1, 'Published':1, 'last-modified':1, 'vendors':1,  '_id':0}
	if vendor:
		for i in collection.find({'vendors': vendor}, li).sort('last-modified', -1).limit(15):
			a = i
			a['url'] = 'cveinfo/'+i['id']
			elem.append(a) 
	else:
		for i in collection.find({}, li ).sort('last-modified', -1).limit(15):
			a = i
			a['url'] = 'cveinfo/'+i['id']
			elem.append(a)
	return elem
'''
x=0
def test(vendors, cond):
	elem.clear()
	li = {'id':1, 'Published':1, 'last-modified':1, '_id':0, 'vendors':1}
	for i in collection.find({'$and': [{'last-modified': {'$gt': week}}, {'vendors':'redhat'}]}, li).sort('last-modified, -1'):
		elem.append(i)
	return elem

a = test('redhat', week)
pprint (a)
'''

# Main page with last 15 cve
@app.route('/')
def index():
	last_15()
	return render_template('index.html', vendors=vendors, e=elem)

#vendor page with last 15 cve
@app.route('/<vendor>')
def vndr(vendor):
	last_15(vendor)
	return render_template('vendors.html', vendors=vendors, e=elem, v=vendor)

#table for cve ID
@app.route('/cveinfo/<cveid>')
def cvepage(cveid):
	cve = collection.find_one({'id': cveid})
	return render_template('cveinfo.html', vendors=vendors, cve=cve, fields=fields)


@app.errorhandler(404)
def errorpage(error):
	return render_template('error_page.html', title='Page not found', vendors=vendors)

if __name__=="__main__":
	app.run(debug=True, host='192.168.0.9', port=80)
