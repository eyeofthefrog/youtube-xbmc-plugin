'''
    YouTube plugin for XBMC
    Copyright (C) 2010-2012 Tobias Ussing And Henrik Mosgaard Jensen

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import re
import sys
import xml.sax
import time
import socket
import urllib
import urllib2
import cStringIO

try:
    import simplejson as json
except ImportError:
    import json

# ERRORCODES:
# 200 = OK
# 303 = See other (returned an error message)
# 500 = uncaught error


class url2request(urllib2.Request):
    """Workaround for using DELETE with urllib2"""
    def __init__(self, url, method, data=None, headers={}, origin_req_host=None, unverifiable=False):
        self._method = method
        urllib2.Request.__init__(self, url, data, headers, origin_req_host, unverifiable)

    def get_method(self):
        if self._method:
            return self._method
        else:
            return urllib2.Request.get_method(self)


class YouTubeCore():
    APIKEY = "AI39si6hWF7uOkKh4B9OEAX-gK337xbwR9Vax-cdeF9CF9iNAcQftT8NVhEXaORRLHAmHxj6GjM-Prw04odK4FxACFfKkiH9lg"

    #===============================================================================
    # The time parameter restricts the search to videos uploaded within the specified time.
    # Valid values for this parameter are today (1 day), this_week (7 days), this_month (1 month) and all_time.
    # The default value for this parameter is all_time.
    #
    # This parameter is supported for search feeds as well as for the top_rated, top_favorites, most_viewed,
    # most_popular, most_discussed and most_responded standard feeds.
    #===============================================================================

    urls = {}
    urls['batch'] = "http://gdata.youtube.com/feeds/api/videos/batch"
    urls['thumbnail'] = "http://i.ytimg.com/vi/%s/0.jpg"

    def __init__(self):
        self.settings = sys.modules["__main__"].settings
        self.language = sys.modules["__main__"].language
        self.plugin = sys.modules["__main__"].plugin
        self.dbg = sys.modules["__main__"].dbg
        self.storage = sys.modules["__main__"].storage
        self.cache = sys.modules["__main__"].cache
        self.login = sys.modules["__main__"].login
        self.utils = sys.modules["__main__"].utils
        self.common = sys.modules["__main__"].common
        urllib2.install_opener(sys.modules["__main__"].opener)

        timeout = [5, 10, 15, 20, 25][int(self.settings.getSetting("timeout"))]
        if not timeout:
            timeout = "15"
        socket.setdefaulttimeout(float(timeout))
        return None

    def delete_favorite(self, params={}):
        self.common.log("")
        get = params.get

        delete_url = "http://gdata.youtube.com/feeds/api/users/default/favorites"
        delete_url += "/" + get('editid')
        result = self._fetchPage({"link": delete_url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def remove_contact(self, params={}):
        self.common.log("")
        get = params.get
        delete_url = "http://gdata.youtube.com/feeds/api/users/default/contacts"
        delete_url += "/" + get("contact")
        result = self._fetchPage({"link": delete_url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def remove_subscription(self, params={}):
        self.common.log("")
        get = params.get
        delete_url = "http://gdata.youtube.com/feeds/api/users/default/subscriptions"
        delete_url += "/" + get("editid")
        result = self._fetchPage({"link": delete_url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def add_contact(self, params={}):
        self.common.log("")
        get = params.get
        url = "http://gdata.youtube.com/feeds/api/users/default/contacts"
        add_request = '<?xml version="1.0" encoding="UTF-8"?> <entry xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://gdata.youtube.com/schemas/2007"><yt:username>%s</yt:username></entry>' % get("contact")
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "request": add_request})
        return (result["content"], result["status"])

    def add_favorite(self, params={}):
        get = params.get
        url = "http://gdata.youtube.com/feeds/api/users/default/favorites"
        add_request = '<?xml version="1.0" encoding="UTF-8"?><entry xmlns="http://www.w3.org/2005/Atom"><id>%s</id></entry>' % get("videoid")
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "request": add_request})
        return (result["content"], result["status"])

    def add_subscription(self, params={}):
        self.common.log("")
        get = params.get
        url = "http://gdata.youtube.com/feeds/api/users/default/subscriptions"
        add_request = '<?xml version="1.0" encoding="UTF-8"?><entry xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://gdata.youtube.com/schemas/2007"> <category scheme="http://gdata.youtube.com/schemas/2007/subscriptiontypes.cat" term="user"/><yt:username>%s</yt:username></entry>' % get("channel")
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "request": add_request})
        return (result["content"], result["status"])

    def add_playlist(self, params={}):
        get = params.get
        url = "http://gdata.youtube.com/feeds/api/users/default/playlists"
        add_request = '<?xml version="1.0" encoding="UTF-8"?><entry xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://gdata.youtube.com/schemas/2007"><title type="text">%s</title><summary>%s</summary></entry>' % (get("title"), get("summary"))
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "request": add_request})
        return (result["content"], result["status"])

    def del_playlist(self, params={}):
        self.common.log("")
        get = params.get
        url = "http://gdata.youtube.com/feeds/api/users/default/playlists/%s" % (get("playlist"))
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def add_to_playlist(self, params={}):
        get = params.get
        self.common.log("")
        url = "http://gdata.youtube.com/feeds/api/playlists/%s" % get("playlist")
        add_request = '<?xml version="1.0" encoding="UTF-8"?><entry xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://gdata.youtube.com/schemas/2007"><id>%s</id></entry>' % get("videoid")
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "request": add_request})
        return (result["content"], result["status"])

    def remove_from_playlist(self, params={}):
        self.common.log("")
        get = params.get
        url = "http://gdata.youtube.com/feeds/api/playlists/%s/%s" % (get("playlist"), get("playlist_entry_id"))
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def remove_from_watch_later(self, params={}):
        self.common.log("")
        get = params.get
        url = "https://gdata.youtube.com/feeds/api/users/default/watch_later/%s" % get("playlist_entry_id")
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def set_video_watched(self, params={}):
        self.common.log("")
        get = params.get
        url = "https://gdata.youtube.com/feeds/api/users/default/watch_later/%s" % get("videoid")
        result = self._fetchPage({"link": url, "api": "true", "login": "true", "auth": "true", "method": "DELETE"})
        return (result["content"], result["status"])

    def getCategoriesFolderInfo(self, xml, params={}):
        self.common.log("")
        self.common.log(xml)
        entries = self.common.parseDOM(xml, "atom:category", ret=True)

        folders = []
        for node in entries:
            folder = {}
            print repr(node)
            if 'yt:deprecated' in node:
                continue

            title = self.common.parseDOM(node, "atom:category", ret="label")[0]

            if title:
                folder['Title'] = self.common.replaceHTMLCodes(title)

            folder['category'] = self.common.parseDOM(node, "atom:category", ret="term")[0]
            folder["icon"] = "explore"
            folder["thumbnail"] = "explore"
            folder["feed"] = "feed_category"

            folders.append(folder)

        return folders

    def getFolderInfo(self, xml, params={}):
        get = params.get

        self.common.log(xml)
        entries = self.common.parseDOM(xml, "entry")
        show_next = False

        #find out if there are more pages
        for link in self.common.parseDOM(xml, "link", ret="rel"):
            if link == "next":
                show_next = True
                break

        folders = []
        for node in entries:
            folder = {"published": "2008-07-05T19:56:35.000-07:00"}

            if get("feed") != "feed_categories":
                folder["login"] = "true"
            title = self.common.parseDOM(node, "title")[0]
            if title.find(": ") > 0:
                title = title[title.find(": ") + 2:]
                title = self.common.replaceHTMLCodes(title)
                
            folder['Title'] = title
            for tmp in self.common.parseDOM(node, "published"):
                folder['published'] = tmp

            for entryid in self.common.parseDOM(node, "id"):
                folder["editid"] = entryid[entryid.rfind(":") + 1:]

            thumb = ""
            if get("user_feed") == "contacts":
                folder["thumbnail"] = "user"
                folder["contact"] = self.common.parseDOM(node, 'yt:username')[0]
                folder["store"] = "contact_options"
                folder["folder"] = "true"

            if get("user_feed") == "subscriptions":
                folder["channel"] = self.common.parseDOM(node, 'yt:username')[0]

            if get("user_feed") == "playlists":
                folder['playlist'] = self.common.parseDOM(node, 'yt:playlistId')[0]
                folder["user_feed"] = "playlist"

            params["thumb"] = "true"
            thumb = self.storage.retrieve(params, "thumbnail", folder)
            if thumb:
                folder["thumbnail"] = thumb

            folders.append(folder)

        if show_next:
            self.utils.addNextFolder(folders, params)

        return folders

    def getBatchDetailsOverride(self, items, params={}):
        videoids = []

        for video in items:
            for k, v in video.items():
                if k == "videoid":
                    videoids.append(v)

        (ytobjects, status) = self.getBatchDetails(videoids, params)

        for video in items:
            videoid = video["videoid"]
            for item in ytobjects:
                if item['videoid'] == videoid:
                    for k, v in video.items():
                        item[k] = v

        while len(items) > len(ytobjects):
            ytobjects.append({'videoid': 'false'})

        return (ytobjects, 200)

    def getBatchDetailsThumbnails(self, items, params={}):
        ytobjects = []
        videoids = []

        for (videoid, thumb) in items:
            videoids.append(videoid)

        (tempobjects, status) = self.getBatchDetails(videoids, params)

        for i in range(0, len(items)):
            (videoid, thumbnail) = items[i]
            for item in tempobjects:
                if item['videoid'] == videoid:
                    item['thumbnail'] = thumbnail
                    ytobjects.append(item)
                    break

        while len(items) > len(ytobjects):
            ytobjects.append({'videoid': 'false'})

        return (ytobjects, 200)

    def getBatchDetails(self, items, params={}):
        self.common.log("params: " + repr(params))
        self.common.log("items: " + str(len(items)))
        request_start = "<feed xmlns='http://www.w3.org/2005/Atom'\n xmlns:media='http://search.yahoo.com/mrss/'\n xmlns:batch='http://schemas.google.com/gdata/batch'\n xmlns:yt='http://gdata.youtube.com/schemas/2007'>\n <batch:operation type='query'/> \n"
        request_end = "</feed>"

        video_request = ""

        ytobjects = []
        status = 500
        i = 1

        temp_objs = self.cache.getMulti("videoidcache", items)

        for index, videoid in enumerate(items):
            if index < len(temp_objs):
                if temp_objs[index]:
                    ytobjects.append(eval(temp_objs[index]))
                    continue
            if videoid:
                video_request += "<entry> \n <id>http://gdata.youtube.com/feeds/api/videos/" + videoid + "</id>\n</entry> \n"
                if i == 50:
                    final_request = request_start + video_request + request_end
                    rstat = 403
                    while rstat == 403:
                        result = self._fetchPage({"link": "http://gdata.youtube.com/feeds/api/videos/batch", "api": "true", "request": final_request})
                        rstat = self.common.parseDOM(result["content"], "batch:status", ret="code")
                        if len(rstat) > 0:
                            if int(rstat[len(rstat) - 1]) == 403:
                                self.common.log("quota exceeded. Waiting 5 seconds. " + repr(rstat))
                                rstat = 403
                                time.sleep(5)

                    temp = self.getVideoInfo(result["content"], params)
                    ytobjects += temp
                    video_request = ""
                    i = 1
                i += 1

        if i > 1:
            final_request = request_start + video_request + request_end
            result = self._fetchPage({"link": "http://gdata.youtube.com/feeds/api/videos/batch", "api": "true", "request": final_request})

            temp = self.getVideoInfo(result["content"], params)
            ytobjects += temp

            save_data = {}
            for item in ytobjects:
                save_data[item["videoid"]] = repr(item)
            self.cache.setMulti("videoidcache", save_data)

        if len(ytobjects) > 0:
            status = 200

        self.common.log("ytobjects: " + str(len(ytobjects)))

        return (ytobjects, status)

    #===============================================================================
    #
    # Internal functions to YouTubeCore.py
    #
    # Return should be value(True for bool functions), or False if failed.
    #
    # False MUST be handled properly in External functions
    #
    #===============================================================================

    def _fetchPage(self, params={}):  # This does not handle cookie timeout for _httpLogin
        if self.settings.getSetting("force_proxy") == "true" and self.settings.getSetting("proxy"):
            params["proxy"] = self.settings.getSetting("proxy")

        get = params.get
        link = get("link")
        ret_obj = {"status": 500, "content": "", "error": 0}
        cookie = ""

        if (get("url_data") or get("request") or get("hidden")) and False:
            self.common.log("called for : " + repr(params['link']))
        else:
            self.common.log("called for : " + repr(params))

        if get("auth", "false") == "true":
            self.common.log("got auth")
            if self._getAuth():
                if link.find("?") > -1:
                    link += "&oauth_token=" + self.settings.getSetting("oauth2_access_token")
                else:
                    link += "?oauth_token=" + self.settings.getSetting("oauth2_access_token")

                self.common.log("updated link: " + link)
            else:
                self.common.log("couldn't get login token")

        if not link or get("error", 0) > 2:
            self.common.log("giving up")
            return ret_obj

        if get("url_data"):
            url_data = get("url_data")
            url_data_encoded = {}
            for k, v in url_data.iteritems():
                url_data_encoded[k] = unicode(v).encode('utf-8')

            request = urllib2.Request(link, urllib.urlencode(url_data_encoded))
            request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        elif get("request", "false") == "false":
            if get("proxy"):
                proxy = get("proxy")
                link = proxy + urllib.quote(link)
                self.common.log("got proxy: %s" % link)
            else:
                self.common.log("got default: %s" % link)

            request = url2request(link, get("method", "GET"))
        else:
            self.common.log("got request")
            request = urllib2.Request(link, get("request"))
            request.add_header('X-GData-Client', "")
            request.add_header('Content-Type', 'application/atom+xml')
            request.add_header('Content-Length', str(len(get("request"))))

        if get("proxy") or (self.settings.getSetting("proxy") != "" and link.find(self.settings.getSetting("proxy")) > -1):
            proxy = self.settings.getSetting("proxy")
            referer = proxy[:proxy.rfind("/")]
            self.common.log("Added proxy refer: %s" % referer)

            request.add_header('Referer', referer)

        if get("api", "false") == "true":
            self.common.log("got api")
            request.add_header('GData-Version', '2.1')
            request.add_header('X-GData-Key', 'key=' + self.APIKEY)
        else:
            request.add_header('User-Agent', self.common.USERAGENT)

            if get("no-language-cookie", "false") == "true":
                cookie += "PREF=f1=50000000&hl=en; "

        if get("login", "false") == "true":
            self.common.log("got login")
            if (self.settings.getSetting("username") == "" or self.settings.getSetting("user_password") == ""):
                self.common.log("_fetchPage, login required but no credentials provided")
                ret_obj["status"] = 303
                ret_obj["content"] = self.language(30622)
                return ret_obj

            # This should be a call to self.login._httpLogin()
            if self.settings.getSetting("cookies_saved") != "true":
                if isinstance(self.login, str):
                    self.login = sys.modules["__main__"].login
                self.login._httpLogin()

        if get("referer", "false") != "false":
            self.common.log("Added referer: %s" % get("referer"))
            request.add_header('Referer', get("referer"))

        try:
            self.common.log("connecting to server... %s" % link )

            if cookie:
                self.common.log("Setting cookie: " + cookie)
                request.add_header('Cookie', cookie)
            con = urllib2.urlopen(request)

            inputdata = con.read()
            ret_obj["content"] = inputdata.decode("utf-8")
            ret_obj["location"] = link

            ret_obj["new_url"] = con.geturl()
            ret_obj["header"] = str(con.info())
            con.close()

            self.common.log("Result: %s " % repr(ret_obj), 9)

            self.common.log("done")
            ret_obj["status"] = 200
            return ret_obj

        except urllib2.HTTPError, e:
            cont = False
            err = str(e)
            msg = e.read()

            self.common.log("HTTPError : " + err)
            if e.code == 400 or True:
                self.common.log("Unhandled HTTPError : [%s] %s " % (e.code, msg), 1)

            params["error"] = get("error", 0) + 1
            ret_obj = self._fetchPage(params)

            if cont and ret_obj["content"] == "":
                ret_obj["content"] = cont
                ret_obj["status"] = 303

            return ret_obj

        except urllib2.URLError, e:
            err = str(e)
            self.common.log("URLError : " + err)
            if err.find("SSL") > -1:
                ret_obj["status"] = 303
                ret_obj["content"] = self.language(30629)
                ret_obj["error"] = 3  # Tell _findErrors that we have an error
                return ret_obj

            time.sleep(3)
            params["error"] = get("error", 0) + 1
            ret_obj = self._fetchPage(params)
            return ret_obj

        except socket.timeout:
            self.common.log("Socket timeout")
            return ret_obj

    def _findErrors(self, ret, silent=False):
        self.common.log("")

        ## Couldn't find 2 factor or normal login
        error = self.common.parseDOM(ret['content'], "div", attrs={"class": "errormsg"})
        if len(error) == 0:
            # An error in 2-factor
            self.common.log("1")
            error = self.common.parseDOM(ret['content'], "div", attrs={"class": "error smaller"})
        if len(error) == 0:
            self.common.log("2")
            error = self.common.parseDOM(ret['content'], "div", attrs={"id": "unavailable-message"})
        if len(error) == 0 and ret['content'].find("yt:quota") > -1:
            self.common.log("3")
            # Api quota
            html = self.common.parseDOM(ret['content'], "error")
            error = self.common.parseDOM(html, "code")

        if len(error) == 0:  # Bad password for _httpLogin.
            error = self.common.parseDOM(ret['content'], "span", attrs={"class": "errormsg"})

            # Has a link. Lets remove that.
            if len(error) == 1:
                if error[0].find("<") > -1:
                    error[0] = error[0][0:error[0].find("<")]

        if len(error) == 0:
            self.common.log("4")
            error = self.common.parseDOM(ret['content'], "div", attrs={"id": "watch7-player-age-gate-content"})

        if len(error) == 0:
            self.common.log("5")
            if len(self.common.parseDOM(ret['content'], "input", attrs={"id": "send-code-button"})):
                error = [self.language(30630)]

        if len(error) == 0:
            self.common.log("6")
            if len(self.common.parseDOM(ret['content'], "h1", attrs={"id": "login-challenge-heading"})):
                error = [self.language(30630)]

        if len(error) == 0:
            self.common.log("7")
            if len(self.common.parseDOM(ret['content'], "h2", attrs={"class": "smsauth-interstitial-heading"})):
                error = [self.language(30630)]

        if len(error) == 0:
            self.common.log("8")
            error = self.common.parseDOM(ret['content'], "span", attrs={"class": "error-msg"})

        if len(error) > 0:
            self.common.log("Found error: " + repr(error))
            error = self.common.stripTags(error[0])
            self.common.log("Found error: " + repr(error))
            if error.find("[") > -1:
                error = error[0:error.find("[")]
            error = urllib.unquote(error.replace("\n", " ").replace("  ", " ")).replace("&#39;", "'")
            self.common.log("returning error : " + repr(error.strip()))
            return error.strip()

        # If no error was found. But fetchPage has an error level of 3+, return the fetchPage content.
        if len(error) == 0 and ret["error"] >= 3:
            self.common.log("Returning error from _fetchPage : " + repr(ret))
            return ret["content"]

        if not silent:
            self.common.log("couldn't find any errors: " + repr(ret))

        return False

    def _oRefreshToken(self):
        self.common.log("")
        # Refresh token
        if self.settings.getSetting("oauth2_refresh_token"):
            url = "https://accounts.google.com/o/oauth2/token"
            data = {"client_id": "208795275779.apps.googleusercontent.com",
                "client_secret": "sZn1pllhAfyonULAWfoGKCfp",
                "refresh_token": self.settings.getSetting("oauth2_refresh_token"),
                "grant_type": "refresh_token"}
            self.settings.setSetting("oauth2_access_token", "")
            ret = self._fetchPage({"link": url, "no-language-cookie": "true", "url_data": data})
            if ret["status"] == 200:
                oauth = ""
                try:
                    oauth = json.loads(ret["content"])
                except:
                    self.common.log("Except: " + repr(ret))
                    return False

                self.common.log("- returning, got result a: " + repr(oauth))

                self.settings.setSetting("oauth2_access_token", oauth["access_token"])
                self.settings.setSetting("oauth2_expires_at", str(int(oauth["expires_in"]) + time.time()) )
                self.common.log("Success")
                return True
            else:
                self.common.log("Failure, Trying a clean login")
                if isinstance(self.login, str):
                    self.login = sys.modules["__main__"].login
                self.login.login({"new": "true"})
            return False

        self.common.log("didn't even try")

        return False

    def performNewLogin(self):
        self.common.log("")
        if isinstance(self.login, str):
            self.login = sys.modules["__main__"].login

        (result, status) = self.login.login()

        if status == 200:
            self.common.log("returning new auth")
            return self.settings.getSetting("oauth2_access_token")

        self.common.log("failed because login failed")
        return False

    def refreshTokenIfNessecary(self):
        now = time.time()

        if self.settings.getSetting("oauth2_expires_at"):
            expire_at = float(self.settings.getSetting("oauth2_expires_at"))
        else:
            expire_at = now

        if expire_at <= now:
            self.common.log("Oauth expired refreshing")
            self._oRefreshToken()

    def _getAuth(self):
        self.common.log("")

        self.refreshTokenIfNessecary()

        auth = self.settings.getSetting("oauth2_access_token")
        if (auth):
            return auth

        return self.performNewLogin()

    def updateVideoIdStatusInCache(self, pre_id, ytobjects):
        self.common.log(pre_id)
        save_data = {}
        for item in ytobjects:
            if "videoid" in item:
                save_data[item["videoid"]] = repr(item)

        self.cache.setMulti(pre_id, save_data)

    def getVideoIdStatusFromCache(self, pre_id, ytobjects):
        self.common.log(pre_id)
        load_data = []
        for item in ytobjects:
            if "videoid" in item:
                load_data.append(item["videoid"])

        res = self.cache.getMulti(pre_id, load_data)
        if len(res) != len(load_data):
            self.common.log("Length mismatch:" + repr(res) + " - " + repr(load_data))
        i = 0
        for item in ytobjects:
            if "videoid" in item:
                if i < len(res):
                    item["Overlay"] = res[i]
                i += 1  # This can NOT be enumerated because there might be missing videoids
        return ytobjects

    def getVideoInfo(self, xml, params={}):
        self.common.log("", 3)

        vch = VideoContentHandler()
        ytobjects = vch.parse(xml, thumbnail_url=self.urls["thumbnail"])

        if vch.addNextPage:
            self.utils.addNextFolder(ytobjects, params)

        self.updateVideoIdStatusInCache("videoidcache", ytobjects)
        self.getVideoIdStatusFromCache("vidstatus-", ytobjects)

        self.common.log("Done: " + str(len(ytobjects)), 3)
        return ytobjects


class VideoContentHandler(xml.sax.ContentHandler):
    MEDIA_URI = 'http://search.yahoo.com/mrss/'
    YT_URI = 'http://gdata.youtube.com/schemas/2007'
    GD_URI = 'http://schemas.google.com/g/2005'
    ATOM_URI = 'http://www.w3.org/2005/Atom'

    def __init__(self):
        xml.sax.ContentHandler.__init__(self)
        self.videos = []
        self.video = {}
        self._buffer = []
        self.state_reason = None
        self.description = ''
        self.thumbnail_url = ''
        self.addNextPage = False
        self.common = sys.modules["__main__"].common
        self.in_entry = False
        self.date_uploaded = time.localtime()

    def parse(self, xml_str, thumbnail_url=''):
        self.thumbnail_url = thumbnail_url

        xml_parser = xml.sax.make_parser()
        xml_parser.setContentHandler(self)
        xml_parser.setFeature(xml.sax.handler.feature_namespaces, True)
        xml_parser.parse(cStringIO.StringIO(xml_str))
        return self.videos

    def characters(self, data):
        self._buffer.append(data)

    def flush_buffer(self):
        data = ''.join(self._buffer).strip()
        self._buffer = []
        return data.strip()

    def startElementNS(self, name, qname, attrs):
        if name[0] == self.ATOM_URI and name[1] == "entry":
            #Reset Defaults
            self.video = {'videoid': 'false',
                          'playlist_entry_id': '',
                          'editid': '',
                          'Studio': '',
                          'Title': '',
                          'Duration': 1,
                          'Rating': 0.0,
                          'Genre': '',
                          'Count': 0,
                          'Date': time.localtime(),
                          'Plot': '',
                          'thumbnail': ''}
            self.in_entry = True
            self.state_reason = None
            self.date_uploaded = time.localtime()
            self.description = ''
        elif not self.in_entry:
            return
        elif name[0] == self.ATOM_URI and name[1] == "content":
            if 'src' in attrs.getQNames():
                url = attrs.getValueByQName("src")
                if self.video['videoid'] == 'false':
                    self.video["videoid"] = url[url.rfind("/") + 1:]
        elif name[0] == self.ATOM_URI and name[1] == "link":
            if 'href' in attrs.getQNames():
                url = attrs.getValueByQName("href")
                if self.video['videoid'] == 'false':
                    match = re.match('.*?v=(.*)\&.*', url)
                    if match:
                        self.video["videoid"] = match.group(1)
            elif 'rel' in attrs.getQNames():
                rel = attrs.getValueByQName("rel")
                if rel == "edit":
                    if 'href' in attrs:
                        url = attrs.getValueByQName("href")
                        self.video['editid'] = url[url.rfind('/') + 1:]
                elif rel == "next":
                    self.addNextPage = True
        elif name[0] == self.YT_URI and name[1] == "state":
            if 'reasonCode' in attrs.getQNames():
                self.state_reason = attrs.getValueByQName("reasonCode")
        elif name[0] == self.YT_URI and name[1] == "duration":
            if 'seconds' in attrs.getQNames():
                self.video["Duration"] = str(int(attrs.getValueByQName("seconds")) / 60)
        elif name[0] == self.GD_URI and name[1] == "rating":
            if 'average' in attrs.getQNames():
                self.video["Rating"] = float(attrs.getValueByQName("average"))
        elif name[0] == self.MEDIA_URI and name[1] == "media:category":
            if 'label' in attrs.getQNames():
                self.video["Genre"] = self.common.replaceHTMLCodes(attrs.getValueByQName("label"))
        elif name[0] == self.YT_URI and name[1] == "statistics":
            if 'viewCount' in attrs.getQNames():
                self.video["Count"] = int(attrs.getValueByQName("viewCount"))

    def endElementNS(self, name, qname):
        data = self.flush_buffer()

        if name[0] == self.YT_URI and name[1] == "videoid":
            self.video["videoid"] = data
        elif name[0] == self.ATOM_URI and name[1] == "id":
            self.video["playlist_entry_id"] = data[data.rfind(":") + 1:]
        elif name[0] == self.YT_URI and name[1] == "state":
            # Ignore unplayable items.
            if data == 'deleted' or data == 'rejected':
                self.video["videoid"] = "false"
                return
            if self.state_reason:
                if self.state_reason in ["private", 'requesterRegion']:
                    self.video["videoid"] = "false"
                elif self.state_reason != 'limitedSyndication':
                    self.common.log("removing video, reason: %s value: %s" % (self.state_reason, data))
                    self.video["videoid"] = "false"
        elif name[0] == self.MEDIA_URI and name[1] == "credit":
            self.video["Studio"] = data
        elif name[0] == self.ATOM_URI and name[1] == "name":
            if "Studio" not in self.video:
                self.video["Studio"] = data
        elif name[0] == self.MEDIA_URI and name[1] == "title":
            self.video["Title"] = self.common.replaceHTMLCodes(data)
        elif name[0] == self.ATOM_URI and name[1] == "published":
            self.date_uploaded = time.strptime(data[:data.find(".")], "%Y-%m-%dT%H:%M:%S")
        elif name[0] == self.MEDIA_URI and name[1] == "description":
            self.description = self.common.replaceHTMLCodes(data)
        elif name[0] == self.ATOM_URI and name[1] == "entry":
            self.video['Date'] = time.strftime("%d-%m-%Y", self.date_uploaded)

            info_string = "Date Uploaded: " + time.strftime("%Y-%m-%d %H:%M:%S", self.date_uploaded) + ", "
            info_string += "View count: " + str(self.video['Count'])
            self.video['Plot'] = info_string + '\n' + self.description

            self.video['thumbnail'] = self.thumbnail_url % self.video['videoid']

            self.videos.append(self.video)
            self.in_entry = False
