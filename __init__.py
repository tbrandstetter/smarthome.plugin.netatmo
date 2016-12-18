#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2016 Thomas Brandstetter           thomas@brandstetter.co.at
#########################################################################
#  Netatmo-Plugin for SmartHome.py.     https://github.com/smarthomeNG/
#  Code taken from Python Netatmo Library.
#  Author: Philippe Larduinat, philippelt@users.sourceforge.net
#  Source-Code Original: https://github.com/philippelt/netatmo-api-python
#
#  This plugin is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This plugin is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this plugin. If not, see <http://www.gnu.org/licenses/>.
#########################################################################

import logging
from lib.model.smartplugin import SmartPlugin
import json
import time
import urllib.parse
import urllib.request

# Common definitions
_BASE_URL       = "https://api.netatmo.net/"
_AUTH_REQ       = _BASE_URL + "oauth2/token"
_GETUSER_REQ    = _BASE_URL + "api/getuser"
_DEVICELIST_REQ = _BASE_URL + "api/devicelist"
_GETMEASURE_REQ = _BASE_URL + "api/getmeasure"


class ClientAuth(SmartPlugin):

    ALLOW_MULTIINSTANCE = False
    PLUGIN_VERSION = "1.2.1"

    # "Request authentication and keep access token available through token method. Renew it automatically if necessary"
    def __init__(self, authData):
        self.logger = logging.getLogger('Netatmo')

        postParams = {
                "grant_type" : "password",
                "client_id" : authData._client_id,
                "client_secret" : authData._client_secret,
                "username" : authData._email,
                "password" : authData._password,
                "scope" : "read_station"
                }
        resp = postRequest(_AUTH_REQ, postParams)

        self._accessToken = resp['access_token']
        self.refreshToken = resp['refresh_token']
        self._scope = resp['scope']
        self.expiration = int(resp['expire_in'] + time.time())

    @property
    def accessToken(self):

        if self.expiration < time.time(): # Token should be renewed

            postParams = {
                    "grant_type" : "refresh_token",
                    "refresh_token" : self.refreshToken,
                    "client_id" : authData._client_id,
                    "client_secret" : authData._client_secret
                    }
            resp = postRequest(_AUTH_REQ, postParams)

            self._accessToken = resp['access_token']
            self.refreshToken = resp['refresh_token']
            self.expiration = int(resp['expire_in'] + time.time())

        return self._accessToken

class DeviceList:

    def __init__(self, authData):

        self.getAuthToken = authData.accessToken
        postParams = {
                "access_token" : self.getAuthToken,
                "app_type" : "app_station"
                }
        resp = postRequest(_DEVICELIST_REQ, postParams)
        self.rawData = resp['body']
        self.stations = { d['_id'] : d for d in self.rawData['devices'] }
        self.modules = { m['_id'] : m for m in self.rawData['modules'] }
        self.default_station = list(self.stations.values())[0]['station_name']

    def modulesNamesList(self, station=None):
        res = [m['module_name'] for m in self.modules.values()]
        res.append(self.stationByName(station)['module_name'])
        return res

    def stationByName(self, station=None):
        if not station : station = self.default_station
        for i,s in self.stations.items():
            if s['station_name'] == station : return self.stations[i]
        return None

    def stationById(self, sid):
        return None if sid not in self.stations else self.stations[sid]

    def moduleByName(self, module, station=None):
        s = None
        if station :
            s = self.stationByName(station)
            if not s : return None
        for m in self.modules:
            mod = self.modules[m]
            if mod['module_name'] == module :
                if not s or mod['main_device'] == s['_id'] : return mod
        return None

    def moduleById(self, mid, sid=None):
        s = self.stationById(sid) if sid else None
        if mid in self.modules :
            return self.modules[mid] if not s or self.modules[mid]['main_device'] == s['_id'] else None

    def lastData(self, station=None, exclude=0):
        s = self.stationByName(station)
        if not s : return None
        lastD = dict()
        # Define oldest acceptable sensor measure event
        limit = (time.time() - exclude) if exclude else 0
        ds = s['dashboard_data']
        if ds['time_utc'] > limit :
            lastD[s['module_name']] = ds.copy()
            lastD[s['module_name']]['When'] = lastD[s['module_name']].pop("time_utc")
            lastD[s['module_name']]['wifi_status'] = s['wifi_status']
        for mId in s["modules"]:
            ds = self.modules[mId]['dashboard_data']
            if ds['time_utc'] > limit :
                mod = self.modules[mId]
                lastD[mod['module_name']] = ds.copy()
                lastD[mod['module_name']]['When'] = lastD[mod['module_name']].pop("time_utc")
                # For potential use, add battery and radio coverage information to module data if present
                for i in ('battery_vp', 'rf_status') :
                    if i in mod : lastD[mod['module_name']][i] = mod[i]
        return lastD

    def checkNotUpdated(self, station=None, delay=3600):
        res = self.lastData(station)
        ret = []
        for mn,v in res.items():
            if time.time()-v['When'] > delay : ret.append(mn)
        return ret if ret else None

    def checkUpdated(self, station=None, delay=3600):
        res = self.lastData(station)
        ret = []
        for mn,v in res.items():
            if time.time()-v['When'] < delay : ret.append(mn)
        return ret if ret else None

    def getMeasure(self, device_id, scale, mtype, module_id=None, date_begin=None, date_end=None, limit=None, optimize=False, real_time=False):
        postParams = { "access_token" : self.getAuthToken }
        postParams['device_id']  = device_id
        if module_id : postParams['module_id'] = module_id
        postParams['scale']      = scale
        postParams['type']       = mtype
        if date_begin : postParams['date_begin'] = date_begin
        if date_end : postParams['date_end'] = date_end
        if limit : postParams['limit'] = limit
        postParams['optimize'] = "true" if optimize else "false"
        postParams['real_time'] = "true" if real_time else "false"
        return postRequest(_GETMEASURE_REQ, postParams)

# Utilities routines

def postRequest(url, params):
    req = urllib.request.Request(url)
    req.add_header("Content-Type","application/x-www-form-urlencoded;charset=utf-8")
    params = urllib.parse.urlencode(params).encode('utf-8')
    resp = urllib.request.urlopen(req, params).readall().decode("utf-8")
    return json.loads(resp)

class Netatmo():

    def __init__(self, smarthome, client_id, client_secret, email, password, cycle=300):
        self._sh = smarthome
        self._items = []
        self._values = {}
        self._cycle = int(cycle)
        self._client_id = client_id
        self._client_secret = client_secret
        self._email = email
        self._password = password
        self._key2json = {
            'Noise' : 0,
            'Temperature' : 0,
            'CO2' : 0,
            'Humidity' : 0
        }

        if not self._client_id or not self._client_secret or not self._email or not self._password:
            self.logger.error("Netatmo: Bad configuration")

    def run(self):
        self.alive = True
        self._sh.scheduler.add('Netatmo', self._update_values, cycle=self._cycle)

    def stop(self):
        self.alive = False

    def parse_item(self, item):
        if 'netatmo' in item.conf:
            item_key = item.conf['netatmo']
            if item_key in self._key2json:
                self._items.append([item, item_key])
                return self.update_item
            else:
                self.logger.warn('invalid key {0} configured', item_key)
        return None

    def parse_logic(self, logic):
        pass

    def update_item(self, item, caller=None, source=None, dest=None):
        if caller != 'Netatmo':
            pass

    def _update_values(self):
        data = self._get_data()

        for item_key in self._key2json:
            value = data[item_key]
            self._values[item_key] = value

        for item_cfg in self._items:
            if item_cfg[1] in self._values:
                item_cfg[0](self._values[item_cfg[1]], 'Netatmo')

    def _get_data(self):
        authorization = ClientAuth(self)
        devList = DeviceList(authorization)
        device = devList.lastData()
        data = (device['Indoor'])
        return data
