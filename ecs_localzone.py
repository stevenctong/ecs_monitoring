# Use ecs.conf to set login details

import json
import logging
import datetime
import time
import os
import sys

try:
    import ConfigParser as Config
except ImportError:
    import configparser as Config

import requests
import urllib3
from influxdb import InfluxDBClient

STATUS_200 = 200
STATUS_201 = 201
STATUS_202 = 202
STATUS_204 = 204
STATUS_401 = 401
STATUS_404 = 404
STATUS_497 = 497

GET = "GET"
POST = "POST"
PUT = "PUT"
DELETE = "DELETE"

conf_filename = "ecs.conf"
token_filename = "py4ecs.token"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def set_config(file_path=None):
    cfg = None
    conf_file = None
    if file_path is not None:
        if os.path.isfile(file_path):
            conf_file = file_path
    elif os.path.isfile(conf_filename):
        conf_file = conf_filename
    if conf_file is not None:
        cfg = Config.ConfigParser()
        cfg.read(conf_file)
    return(cfg)

def get_auth_token(username, password, base_url):
    global_path = os.path.expanduser(token_filename)

    if os.path.isfile(global_path):
        fread = open(global_path, "r")
        token = fread.read()

        req = requests.get("{}/license".format(base_url), \
            headers={'X-SDS-AUTH-TOKEN': token}, verify=False)

        if req.status_code is STATUS_200:
            return(token)

    req = requests.get("{}/login".format(base_url), \
        auth=(username, password), verify=False)
    try:
        req.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)

    token = req.headers['X-SDS-AUTH-TOKEN']

    with open(global_path, "w") as fwrite:
        fwrite.write("{}".format(token))

    return(token)

def get_metric_data(field, metric_list=[], metric_values={}):
    # Valid 'metric_list' is a list of dictionary items
    # { 't' : '<epoch time>', '<units of measure>' : '<data>' }
    if len(metric_list):
        # Check if this is a valid list of timestamped data points
        # If so, iterate through the list of data points
        if 't' in metric_list[0]:
            for items in metric_list:
                # Gets the timestamp for this data point
                epoch_time = items.pop('t')
                # Get the data point
                for units in items:
                    data = float(items[units])
                # Data key'ed to time then field : data
                if epoch_time in metric_values:
                    metric_values[epoch_time][field] = data
                else:
                    metric_values[epoch_time] = {}
                    metric_values[epoch_time][field] = data

def get_summary_data(field, current_epoch, summary_dict={}, summary_values={}):
    # Valid 'summary_dict' is a dictionary of three keys
    # 'Min' and 'Max' which is a list with a single item containing
    # { 't' : '<epoch time>', '<units of measure>' : '<data>' }
    # Third key is 'Avg' which just has a value
    for keys in summary_dict:
        if type(summary_dict[keys]) is list:
            # Check non-empty list. Since list is only item we can address
            # the value directly using [0]
            if len(summary_dict[keys]):
                epoch_time = summary_dict[keys][0].pop('t')
                for units in summary_dict[keys][0]:
                    data = float(summary_dict[keys][0][units])
                # Data key'ed to time, then field+keys : data
                # E.g. field+keys "chunksEcRateSummaryMin"
                if epoch_time in summary_values:
                    summary_values[epoch_time][field+keys] = data
                else:
                    summary_values[epoch_time] = {}
                    summary_values[epoch_time][field+keys] = data
        # "Avg" value which is just key : value
        else:
            if current_epoch in summary_values:
                summary_values[current_epoch][field+keys] = \
                    float(summary_dict[keys])
            else:
                summary_values[current_epoch] = {}
                summary_values[current_epoch][field+keys] = \
                    float(summary_dict[keys])


def main():
    current_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    current_epoch_time = time.time()

    db_array = []
    ecsdata = {}
    ecsdata_metrics = {}
    ecsdata_summary = {}
    fields = {}
    tags = {}

    CFG = set_config()

    cluster_ip = CFG.get("setup", "cluster_ip")
    port = int(CFG.get("setup", "port"))
    username = CFG.get("setup", "username")
    password = CFG.get("setup", "password")
    cluster_name = CFG.get("setup", "cluster_name")

    dbhost = CFG.get("influxdb", "dbhost")
    dbport = int(CFG.get("influxdb", "dbport"))
    dbuser = CFG.get("influxdb", "dbuser")
    dbpassword = CFG.get("influxdb", "dbpassword")
    dbname = CFG.get("influxdb", "dbname")

    dbclient = InfluxDBClient(dbhost, dbport, dbuser, dbpassword, dbname)

    base_url = "https://{}:{}".format(cluster_ip, port)

    token = get_auth_token(username=username, password=password, \
                           base_url=base_url)

    req_headers = {'X-SDS-AUTH-TOKEN': token, \
                   'Content-Type' : 'application/json'}

    tags['Cluster'] = cluster_name

    target_name = "LocalZone"
    target_url = "/dashboard/zones/localzone"

    req = requests.get("{}{}".format(base_url, target_url), \
        headers=req_headers, verify=False)

    if req.status_code in [STATUS_401, STATUS_497]:
        token = get_auth_token(username=username, password=password, \
                               base_url=base_url)

        req = requests.get("{}{}".format(base_url, target_url), \
            headers={'X-SDS-AUTH-TOKEN': token}, verify=False)

    req = req.json()

    # Not handling a few metrics for now
    req.pop('_links', None)
    req.pop('transactionErrors', None)
    req.pop('transactionErrorsSummary', None)
    req.pop('transactionErrorsCurrent', None)

    for field in req:
        if type(req[field]) is str:
            try:
                ecsdata[field] = float(req[field])
            except:
                pass

        elif type(req[field]) is list:
            get_metric_data(field=field, metric_list=req[field], \
                            metric_values=ecsdata_metrics)

        else:
            get_summary_data(field=field, summary_dict=req[field], \
                             current_epoch=current_epoch_time, \
                             summary_values=ecsdata_summary)

    db_json = {
        "measurement" : target_name,
        "tags" : tags,
        "fields" : ecsdata,
        "time" : current_time
    }

    db_array.append(db_json.copy())

    for times in ecsdata_metrics:

        influxdb_time = datetime.datetime.utcfromtimestamp(int(times))
        influxdb_time = influxdb_time.strftime("%Y-%m-%dT%H:%M:%S")

        db_json = {
            "measurement" : target_name+"Metrics",
            "tags" : tags,
            "fields" : ecsdata_metrics[times],
            "time" : influxdb_time
        }

        db_array.append(db_json.copy())

    for times in ecsdata_summary:
        influxdb_time = datetime.datetime.utcfromtimestamp(int(times))
        influxdb_time = influxdb_time.strftime("%Y-%m-%dT%H:%M:%S")

        db_json = {
            "measurement" : target_name+"Summary",
            "tags" : tags,
            "fields" : ecsdata_summary[times],
            "time" : influxdb_time
        }

        db_array.append(db_json.copy())

    dbclient.write_points(db_array)

    print(db_array)
main()
