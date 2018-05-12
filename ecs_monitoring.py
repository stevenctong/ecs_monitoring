# Use ecs.cfg to set login details

import json
import logging
import datetime
import os

try:
    import ConfigParser as Config
except ImportError:
    import configparser as Config

import requests
import urllib3
from influxdb import InfluxDBClient

target_url = "/dashboard/zones/localzone/"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_auth_token(username, password):
    req = requests.get("https://{}:{}/login".format(clusterIP, port), \
        auth=(username, password), verify=False)
    return(req.headers['X-SDS-AUTH-TOKEN'])

def check_auth_token():
    return

def set_config(file_path=None):
    cfg = None
    conf_file = None
    conf_file_name = "ecs.cfg"

    if file_path is not None:
        if os.path.isfile(file_path):
            conf_file = file_path
    elif os.path.isfile(conf_file_name):
        conf_file = conf_file_name

    if conf_file is not None:
        cfg = Config.ConfigParser()
        cfg.read(conf_file)

    return(cfg)

def main():
    db_array = []
    localzone = {}
    localzone_metrics = {}
    localzone_summary = {}
    fields = {}
    tags = {}

    CFG = set_config()
    token = CFG.get("token", "X-SDS-AUTH-TOKEN")
    clusterIP = CFG.get("setup", "clusterIP")
    port = CFG.get("setup", "port")

    current_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    dbclient = InfluxDBClient(CFG.get("setup", "dbhost"), \
        int(CFG.get("setup", "dbport")), CFG.get("setup", "dbuser"), \
        CFG.get("setup", "dbpassword"), CFG.get("setup", "dbname"))

    req = requests.get("https://{}:{}{}".format(clusterIP, port, target_url), \
        headers={'X-SDS-AUTH-TOKEN': token}, verify=False)

    req = req.json()

    # Not handling a few metrics for now
    req.pop('_links', None)
    req.pop('transactionErrors', None)
    req.pop('transactionErrorsSummary', None)
    req.pop('transactionErrorsCurrent', None)

    tags.update({'Cluster' : req['name']})

    for keys in req:

        if type(req[keys]) is str:
            try:
                localzone.update({keys : float(req[keys])})

            except:
                pass

        elif type(req[keys]) is list:
            # Check is list is empty
            if len(req[keys]):
                # If 't' exists then is a time-series data point
                if 't' in req[keys][0]:
                    for values in req[keys]:

                        epoch_time = values.pop('t')

                        for values_key in values:
                            data = float(values[values_key])

                        if epoch_time in localzone_metrics:
                            localzone_metrics[epoch_time][keys] = data
                        else:
                            localzone_metrics[epoch_time] = {}
                            localzone_metrics[epoch_time][keys] = data

        else:
            for summary_keys in req[keys]:
                if type(req[keys][summary_keys]) is list:
                    if len(req[keys][summary_keys]):

                        epoch_time = req[keys][summary_keys][0].pop('t')

                        for values in req[keys][summary_keys][0]:
                            data = float(req[keys][summary_keys][0][values])

                        if epoch_time in localzone_summary:
                            localzone_summary[epoch_time][keys+summary_keys] = \
                                data
                        else:
                            localzone_summary[epoch_time] = {}
                            localzone_summary[epoch_time][keys+summary_keys] = \
                                data

                else:
                    if epoch_time in localzone_summary:
                        localzone_summary[epoch_time][keys+summary_keys] = \
                            float(req[keys][summary_keys])
                    else:
                        localzone_summary[epoch_time] = {}
                        localzone_summary[epoch_time][keys+summary_keys] = \
                            float(req[keys][summary_keys])

    db_json = {
        "measurement" : "LocalZone",
        "tags" : tags,
        "fields" : localzone,
        "time" : current_time
    }

    db_array.append(db_json.copy())

    for times in localzone_metrics:

        influxdb_time = datetime.datetime.utcfromtimestamp(int(times))
        influxdb_time = influxdb_time.strftime("%Y-%m-%dT%H:%M:%S")

        db_json = {
            "measurement" : "LocalZoneMetrics",
            "tags" : tags,
            "fields" : localzone_metrics[times],
            "time" : influxdb_time
        }

        db_array.append(db_json.copy())

    for times in localzone_summary:

        influxdb_time = datetime.datetime.utcfromtimestamp(int(times))
        influxdb_time = influxdb_time.strftime("%Y-%m-%dT%H:%M:%S")

        db_json = {
            "measurement" : "LocalZoneSummary",
            "tags" : tags,
            "fields" : localzone_summary[times],
            "time" : influxdb_time
        }

        db_array.append(db_json.copy())

    dbclient.write_points(db_array)

    print(db_array)
main()
