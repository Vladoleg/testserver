from flask import Flask, render_template
from pymongo import MongoClient
from pprint import pprint
import datetime as dt

#Connecting to mongodb
client=MongoClient("mongodb://localhost:27017/")
my_db=client.cvedb
collection =  my_db.cves

#static variables
fields=['id', 'assigner', 'Published', 'Modified', 'last-modified', 'summary', 'impactScore3', 'exploitabilityScore3', 'exploitabilityScore', 'impactScore', 'references', 'vendors', 'cwe', 'vulnerable_configuration_cpe_2_2']
now=dt.datetime.today()
far=dt.datetime(2022, 7, 1)
cve=[]
elem=[]

app = Flask(__name__)
vendors = [{'name': 'huawei', 'url': 'huawei'},
           {'name': 'dell', 'url': 'dell'},
           {'name': 'vmware', 'url': 'vmware'},
           {'name': 'veeam', 'url': 'veeam'},
           {'name': 'netapp', 'url': 'netapp'},
           {'name': 'lenovo', 'url': 'lenovo'},
           {'name': 'fujitsu', 'url': 'fujitsu'},
           {'name': 'juniper', 'url': 'juniper'},
           {'name': 'mikrotik', 'url': 'mikrotik'},
           {'name': 'intel', 'url': 'intel'}]

#selecting last 15 documents for mainpage and vendors

def last():
	elem.clear()
	for i in collection.find().limit(-15):
		x = (i['id'])
		elem.append( {'name': x, 'url': 'cveinfo/'+x })
	return elem


def last_v(vendor):
	elem.clear()
	for i in collection.find({'vendors': vendor}).limit(-15):
		x = i['id']
		elem.append({'name': x, 'url': 'cveinfo/'+x})
	return elem

# Main page with last 15 pieces
@app.route('/')
def index():
	last()
	return render_template('index.html', vendors=vendors, elem=elem)

#vendor page with 15 last pieces
@app.route('/<vendor>')
def vendor(vendor):
	last_v(vendor)
	return render_template('vendors.html', vendors=vendors, elem=elem)

@app.route('/cveinfo/<cveid>')
def cvepage(cveid):
	cve = collection.find_one({'id': cveid})
	return render_template('cveinfo.html', vendors=vendors, cve=cve, fields=fields)


if __name__=="__main__":
	app.run(debug=True, host='192.168.0.9', port=80)

