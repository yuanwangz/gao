var rule = {
    title: '云音乐',
    host: '',
    homeUrl: '/',
    url: 'fyclass_fypage',
    detailUrl: 'fyid',
    searchUrl: 'cloudsearch?keywords=**&type=fyclass&limit=30&offset=0',
    searchable: 2,
    quickSearch: 0,
    class_name: '我的歌单&单曲&专辑&歌手&歌单&全部MV&最新MV&MV排行榜&设置',
    class_url: 'my&1&10&100&1000&mv_all&mv_first&mv_top&setting',
    headers: { 'User-Agent': 'Mozilla/5.0' },
    timeout: 10000,
    play_parse: true,
    lazy: `js:
        var u = (input || '').trim();
        var base = '';
        if (rule.params && rule.params.trim() !== '') {
            try { base = decodeURIComponent(rule.params); } catch (e) { base = rule.params; }
        }
        if (!base) base = (HOST || '').endsWith('/') ? (HOST || '').slice(0, -1) : (HOST || '');
        base = base.endsWith('/') ? base.slice(0, -1) : base;
        var header = JSON.stringify({'User-Agent': 'Mozilla/5.0' });
        var reqHeaders = { 'User-Agent': 'Mozilla/5.0' };
        var netmusicCookie = getStorage('public_netmusic_cookie') || '';
        if (netmusicCookie) reqHeaders['Cookie'] = netmusicCookie;
        if (/^song_\\d+$/.test(u)) {
            var id = u.replace('song_', '');
            var api = JSON.parse(request(base + '/song/url?id=' + id, { headers: reqHeaders, timeout: 10000 }) || '{}');
            var url = (api.data && api.data[0] && api.data[0].url) ? api.data[0].url : (api.data && api.data.url) ? api.data.url : '';
            if (url) input = { jx: 0, url: url, parse: 0, header: header };
        } else if (u === 'netmusic_qrcode') {
            var keyApi = JSON.parse(request(base + '/login/qr/key?timestamp=' + Date.now(), { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }) || '{}');
            var unikey = (keyApi.data && keyApi.data.unikey) || keyApi.unikey || '';
            if (unikey) {
                var createApi = JSON.parse(request(base + '/login/qr/create?key=' + encodeURIComponent(unikey) + '&timestamp=' + Date.now(), { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }) || '{}');
                var qrurl = (createApi.data && createApi.data.qrurl) || createApi.qrurl || '';
                if (qrurl) {
                    setStorage('public_netmusic_qr_key', unikey);
                    var qrShowUrl = 'vidplay://x-callback-url/showQRCode?text=' + encodeURIComponent('请使用云音乐APP扫码登录，完成后请手动返回') + '&url=' + encodeURIComponent(qrurl);
                    input = { jx: 0, url: qrShowUrl, parse: 0, header: header };
                }
            }
        } else if (u === 'netmusic_logout') {
            setStorage('public_netmusic_cookie', '');
            setStorage('public_netmusic_uid', '');
            input = { jx: 0, url: '', parse: 0, header: header };
        } else if (/^mv_\\d+$/.test(u)) {
            var mvid = u.replace('mv_', '');
            var mvApi = JSON.parse(request(base + '/mv/url?id=' + mvid + '&r=1080', { headers: reqHeaders, timeout: 10000 }) || '{}');
            var mvUrl = (mvApi.data && mvApi.data.url) ? mvApi.data.url : (mvApi.data && mvApi.data[0] ? mvApi.data[0].url : '');
            if (mvUrl) input = { jx: 0, url: mvUrl, parse: 0, header: header };
        }
    `,
    limit: 6,
    double: false,

    推荐: `js:
        var d = [];
        var base = '';
        if (rule.params && rule.params.trim() !== '') {
            try { base = decodeURIComponent(rule.params); } catch (e) { base = rule.params; }
        }
        if (!base) base = (HOST || '').endsWith('/') ? (HOST || '').slice(0, -1) : (HOST || '');
        base = base.endsWith('/') ? base.slice(0, -1) : base;
        var reqHeaders = { 'User-Agent': 'Mozilla/5.0' };
        var netmusicCookie = getStorage('public_netmusic_cookie') || '';
        if (netmusicCookie) reqHeaders['Cookie'] = netmusicCookie;
        var api = JSON.parse(request(base + '/toplist', { headers: reqHeaders, timeout: 10000 }) || '{}');
        var list = (api.list || api.data || []);
        list.forEach(function(it) {
            var id = it.id;
            var name = it.name || (it.toplist && it.toplist.name) || '';
            var pic = (it.coverImgUrl || it.picUrl || it.coverUrl || (it.toplist && it.toplist.coverImgUrl) || '').replace('http://', 'https://');
            var desc = (it.updateFrequency || (it.toplist && it.toplist.updateFrequency) || '榜单').substring(0, 40);
            d.push({ url: 'playlist_' + id, title: name, img: pic, desc: desc });
        });
        api = JSON.parse(request(base + '/personalized?limit=20', { headers: reqHeaders, timeout: 10000 }) || '{}');
        list = (api.result || api.recommend || []);
        list.forEach(function(it) {
            var id = it.id;
            var name = it.name || '';
            var pic = (it.picUrl || it.coverImgUrl || '').replace('http://', 'https://');
            var desc = (it.copywriter || it.description || '歌单').substring(0, 80);
            d.push({ url: 'playlist_' + id, title: name, img: pic, desc: desc });
        });
        setResult(d);
    `,

    一级: `js:
        var d = [];
        var parts = (input || '').split('_');
        var type = parts[0];
        var page = parseInt(parts[1], 10) || 1;
        if (parts[0] === 'mv' && (parts[1] === 'all' || parts[1] === 'first' || parts[1] === 'top') && parts.length >= 3) {
            type = 'mv_' + parts[1];
            page = parseInt(parts[2], 10) || 1;
        }
        var limit = 30;
        var offset = (page - 1) * limit;
        var base = '';
        if (rule.params && rule.params.trim() !== '') {
            try { base = decodeURIComponent(rule.params); } catch (e) { base = rule.params; }
        }
        if (!base) base = (HOST || '').endsWith('/') ? (HOST || '').slice(0, -1) : (HOST || '');
        base = base.endsWith('/') ? base.slice(0, -1) : base;
        var api, list, id, name, pic, desc, artist;
        var netmusicCookieKey = 'public_netmusic_cookie';
        var netmusicUidKey = 'public_netmusic_uid';
        var netmusicQrKey = 'public_netmusic_qr_key';
        if (type === 'setting' || type === 'my') {
            var qrKey = getStorage(netmusicQrKey);
            if (qrKey && qrKey.length > 0) {
                var checkUrl = base + '/login/qr/check?key=' + encodeURIComponent(qrKey) + '&timestamp=' + Date.now();
                var checkApi = JSON.parse(request(checkUrl, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }) || '{}');
                if (checkApi.code === 803 && checkApi.cookie) {
                    var rawCookie = checkApi.cookie;
                    var cookieArr = [];
                    var parts = rawCookie.split(';;');
                    for (var pi = 0; pi < parts.length; pi++) {
                        var entry = parts[pi].trim();
                        if (!entry) continue;
                        var firstSemi = entry.indexOf(';');
                        var nameValue = firstSemi >= 0 ? entry.substring(0, firstSemi).trim() : entry.trim();
                        if (nameValue && nameValue.indexOf('=') >= 0) cookieArr.push(nameValue);
                    }
                    var cookieStr = cookieArr.join('; ');
                    setStorage(netmusicCookieKey, cookieStr);
                    var accReq = JSON.parse(request(base + '/user/account', { headers: { 'User-Agent': 'Mozilla/5.0', 'Cookie': cookieStr }, timeout: 10000 }) || '{}');
                    var acc = accReq.account || (accReq.data && accReq.data.account);
                    var prof = accReq.profile || (accReq.data && accReq.data.profile);
                    var uid = (acc && acc.id) ? String(acc.id) : (prof && prof.userId) ? String(prof.userId) : '';
                    if (uid) setStorage(netmusicUidKey, uid);
                    setStorage(netmusicQrKey, '');
                } else if (checkApi.code === 800) {
                    setStorage(netmusicQrKey, '');
                }
            }
        }
        var reqHeaders = { 'User-Agent': 'Mozilla/5.0' };
        var netmusicCookie = getStorage(netmusicCookieKey) || '';
        if (netmusicCookie) reqHeaders['Cookie'] = netmusicCookie;

        if (type === '1') {
            api = JSON.parse(request(base + '/personalized/newsong?limit=' + limit, { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.result || api.data || []);
            list.forEach(function(it) {
                var s = it.song || it;
                id = s.id;
                name = s.name || '';
                pic = (s.album && s.album.picUrl ? s.album.picUrl : (it.picUrl || '')).replace('http://', 'https://');
                artist = (s.artists || []).map(function(a) { return a.name; }).join(' / ');
                d.push({ url: 'song_' + id, title: name, img: pic, desc: artist || '单曲' });
            });
        } else if (type === '10') {
            api = JSON.parse(request(base + '/top/album?type=hot&limit=' + limit + '&offset=' + offset, { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.weekData || api.monthData || api.data || []);
            list.forEach(function(it) {
                id = it.id;
                name = it.name || '';
                pic = (it.picUrl || it.blurPicUrl || '').replace('http://', 'https://');
                artist = (it.artist || {}).name || (it.artists && it.artists[0] ? it.artists[0].name : '');
                d.push({ url: 'album_' + id, title: name, img: pic, desc: artist || '专辑' });
            });
        } else if (type === '100') {
            api = JSON.parse(request(base + '/artist/list?limit=' + limit + '&offset=' + offset + '&type=-1&area=-1&initial=-1', { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.artists || api.data || []);
            list.forEach(function(it) {
                id = it.id;
                name = it.name || '';
                pic = (it.picUrl || it.img1v1Url || '').replace('http://', 'https://');
                d.push({ url: 'artist_' + id, title: name, img: pic, desc: '歌手' });
            });
        } else if (type === '1000') {
            api = JSON.parse(request(base + '/top/playlist?limit=' + limit + '&offset=' + offset + '&order=hot', { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.playlists || api.data || []);
            list.forEach(function(it) {
                id = it.id;
                name = it.name || '';
                pic = (it.coverImgUrl || it.picUrl || '').replace('http://', 'https://');
                desc = (it.description || it.copywriter || '').substring(0, 60) || '歌单';
                d.push({ url: 'playlist_' + id, title: name, img: pic, desc: desc });
            });
        } else if (type === 'mv_all') {
            api = JSON.parse(request(base + '/mv/all?limit=' + limit + '&offset=' + offset, { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.data || []);
            list.forEach(function(it) {
                id = it.id || it.mvid;
                name = it.name || it.title || '';
                pic = (it.picUrl || it.cover || it.coverUrl || '').replace('http://', 'https://');
                artist = (it.artists || []).map(function(a) { return a.name; }).join(' / ');
                d.push({ url: 'mv_' + id, title: name, img: pic, desc: artist || 'MV' });
            });
        } else if (type === 'mv_first') {
            api = JSON.parse(request(base + '/mv/first?limit=' + limit, { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.data || []);
            list.forEach(function(it) {
                id = it.id || it.mvid;
                name = it.name || it.title || '';
                pic = (it.picUrl || it.cover || it.coverUrl || '').replace('http://', 'https://');
                artist = (it.artists || []).map(function(a) { return a.name; }).join(' / ');
                d.push({ url: 'mv_' + id, title: name, img: pic, desc: artist || 'MV' });
            });
        } else if (type === 'mv_top') {
            api = JSON.parse(request(base + '/top/mv?limit=' + limit + '&offset=' + offset, { headers: reqHeaders, timeout: 10000 }) || '{}');
            list = (api.data || []);
            list.forEach(function(it) {
                id = it.id || it.mvid;
                name = it.name || it.title || '';
                pic = (it.picUrl || it.cover || it.coverUrl || '').replace('http://', 'https://');
                artist = (it.artists || []).map(function(a) { return a.name; }).join(' / ');
                d.push({ url: 'mv_' + id, title: name, img: pic, desc: artist || 'MV' });
            });
        } else if (type === 'my') {
            var uid = '';
            var accApi = JSON.parse(request(base + '/user/account', { headers: reqHeaders, timeout: 10000 }) || '{}');
            var acc = accApi.account || accApi.data && accApi.data.account;
            var prof = accApi.profile || accApi.data && accApi.data.profile;
            if (acc && acc.id) uid = String(acc.id);
            else if (prof && prof.userId) uid = String(prof.userId);
            if (!uid) uid = getStorage(netmusicUidKey) || '';
            if (!uid) {
                var paramStr = (rule.params && rule.params.trim() !== '') ? (function(){ try { return decodeURIComponent(rule.params); } catch (e) { return rule.params; } })() : '';
                uid = (paramStr.indexOf(',') >= 0 ? (paramStr.split(',')[1] || '').trim() : '');
            }
            if (uid) {
                api = JSON.parse(request(base + '/user/playlist?uid=' + encodeURIComponent(uid) + '&limit=' + limit + '&offset=' + offset, { headers: reqHeaders, timeout: 10000 }) || '{}');
                list = (api.playlist || api.data || []);
                list.forEach(function(it) {
                    id = it.id;
                    name = it.name || '';
                    pic = (it.coverImgUrl || it.picUrl || '').replace('http://', 'https://');
                    desc = (it.description || (it.trackCount != null ? it.trackCount + ' 首' : '歌单')).substring(0, 60);
                    d.push({ url: 'playlist_' + id, title: name, img: pic, desc: desc });
                });
            }
        } else if (type === 'setting') {
            var settingTitle = '未登录';
            if (netmusicCookie) {
                var accApi = JSON.parse(request(base + '/user/account', { headers: reqHeaders, timeout: 10000 }) || '{}');
                var acc = accApi.account || (accApi.data && accApi.data.account);
                var prof = accApi.profile || (accApi.data && accApi.data.profile);
                if (prof && prof.nickname) settingTitle = '当前账号: ' + prof.nickname;
                else if (acc && acc.userName) settingTitle = '当前账号: ' + acc.userName;
            }
            d.push({ url: 'setting_menu', title: settingTitle, img: '', desc: '扫码登录 / 注销登录' });
        }
        setResult(d);
    `,

    二级: `js:
        var t = (input || '').split('_');
        var type = t[0];
        var id = t[1];
        if (!id) {
            VOD = { vod_name: '未知', vod_content: 'id 为空' };
        } else {
        var base = '';
        if (rule.params && rule.params.trim() !== '') {
            try { base = decodeURIComponent(rule.params); } catch (e) { base = rule.params; }
        }
        if (!base) base = (HOST || '').endsWith('/') ? (HOST || '').slice(0, -1) : (HOST || '');
        base = base.endsWith('/') ? base.slice(0, -1) : base;
        var netmusicCookieKey = 'public_netmusic_cookie';
        var netmusicUidKey = 'public_netmusic_uid';
        var netmusicQrKey = 'public_netmusic_qr_key';
        if (type === 'setting' && id === 'menu') {
            var qrKey = getStorage(netmusicQrKey);
            if (qrKey && qrKey.length > 0) {
                var checkUrl = base + '/login/qr/check?key=' + encodeURIComponent(qrKey) + '&timestamp=' + Date.now();
                var checkApi = JSON.parse(request(checkUrl, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }) || '{}');
                if (checkApi.code === 803 && checkApi.cookie) {
                    var rawCookie = checkApi.cookie;
                    var cookieArr = [];
                    var parts = rawCookie.split(';;');
                    for (var pi = 0; pi < parts.length; pi++) {
                        var entry = parts[pi].trim();
                        if (!entry) continue;
                        var firstSemi = entry.indexOf(';');
                        var nameValue = firstSemi >= 0 ? entry.substring(0, firstSemi).trim() : entry.trim();
                        if (nameValue && nameValue.indexOf('=') >= 0) cookieArr.push(nameValue);
                    }
                    var cookieStr = cookieArr.join('; ');
                    setStorage(netmusicCookieKey, cookieStr);
                    var accReq = JSON.parse(request(base + '/user/account', { headers: { 'User-Agent': 'Mozilla/5.0', 'Cookie': cookieStr }, timeout: 10000 }) || '{}');
                    var acc = accReq.account || (accReq.data && accReq.data.account);
                    var prof = accReq.profile || (accReq.data && accReq.data.profile);
                    var uid = (acc && acc.id) ? String(acc.id) : (prof && prof.userId) ? String(prof.userId) : '';
                    if (uid) setStorage(netmusicUidKey, uid);
                    setStorage(netmusicQrKey, '');
                } else if (checkApi.code === 800) {
                    setStorage(netmusicQrKey, '');
                }
            }
        }
        var reqHeaders = { 'User-Agent': 'Mozilla/5.0' };
        var netmusicCookie = getStorage(netmusicCookieKey) || '';
        if (netmusicCookie) reqHeaders['Cookie'] = netmusicCookie;
        var api, name, pic, desc, artist, tracks, list, playUrl, playFrom;

        if (type === 'song') {
            api = JSON.parse(request(base + '/song/detail?ids=' + id, { headers: reqHeaders, timeout: 10000 }) || '{}');
            var s = (api.songs && api.songs[0]) || {};
            name = s.name || '';
            pic = (s.al && s.al.picUrl ? s.al.picUrl : '').replace('http://', 'https://');
            artist = (s.ar || []).map(function(a) { return a.name; }).join(' / ');
            VOD = {
                vod_id: 'song_' + id,
                vod_name: name,
                vod_pic: pic,
                vod_content: artist || '单曲',
                vod_actor: artist,
                vod_director: '云音乐',
                vod_remarks: '',
                vod_play_from: '云音乐',
                vod_play_url: (name || '').replace(/#/g, ' ') + '$song_' + id
            };
        } else if (type === 'album') {
            api = JSON.parse(request(base + '/album?id=' + id, { headers: reqHeaders, timeout: 10000 }) || '{}');
            var alb = (api.album || api);
            var songs = (api.songs || alb.songs || []);
            name = alb.name || '';
            pic = (alb.picUrl || '').replace('http://', 'https://');
            artist = (alb.artist && alb.artist.name) || (alb.artists && alb.artists[0] ? alb.artists[0].name : '');
            playFrom = '云音乐';
            playUrl = songs.map(function(s) { return (s.name || '').replace(/#/g, ' ') + '$song_' + (s.id || ''); }).join('#');
            VOD = {
                vod_id: 'album_' + id,
                vod_name: name,
                vod_pic: pic,
                vod_content: artist || '专辑',
                vod_actor: artist,
                vod_director: '云音乐',
                vod_remarks: '',
                vod_play_from: playFrom,
                vod_play_url: playUrl || (name || '').replace(/#/g, ' ') + '$song_0'
            };
        } else if (type === 'artist') {
            api = JSON.parse(request(base + '/artists?id=' + id, { headers: reqHeaders, timeout: 10000 }) || '{}');
            var art = (api.artist || api);
            var hotSongs = (api.hotSongs || art.hotSongs || []);
            name = art.name || '';
            pic = (art.picUrl || art.img1v1Url || '').replace('http://', 'https://');
            playFrom = '云音乐';
            playUrl = hotSongs.map(function(s) { return (s.name || '').replace(/#/g, ' ') + '$song_' + (s.id || ''); }).join('#');
            VOD = {
                vod_id: 'artist_' + id,
                vod_name: name,
                vod_pic: pic,
                vod_content: '歌手',
                vod_actor: name,
                vod_director: '云音乐',
                vod_remarks: '',
                vod_play_from: playFrom,
                vod_play_url: playUrl || (name || '').replace(/#/g, ' ') + '$song_0'
            };
        } else if (type === 'playlist') {
            api = JSON.parse(request(base + '/playlist/detail?id=' + id, { headers: reqHeaders, timeout: 10000 }) || '{}');
            var pl = (api.playlist || api);
            var tr = (pl.tracks || []);
            name = pl.name || '';
            pic = (pl.coverImgUrl || pl.picUrl || '').replace('http://', 'https://');
            desc = pl.description || '';
            playFrom = '云音乐';
            playUrl = tr.map(function(s) { return (s.name || '').replace(/#/g, ' ') + '$song_' + (s.id || ''); }).join('#');
            if (!playUrl && pl.trackIds && pl.trackIds.length) {
                var ids = pl.trackIds.slice(0, 100).map(function(x) { return x.id; }).join(',');
                var det = JSON.parse(request(base + '/song/detail?ids=' + ids, { headers: reqHeaders, timeout: 10000 }) || '{}');
                var sl = (det.songs || []);
                playUrl = sl.map(function(s) { return (s.name || '').replace(/#/g, ' ') + '$song_' + (s.id || ''); }).join('#');
            }
            VOD = {
                vod_id: 'playlist_' + id,
                vod_name: name,
                vod_pic: pic,
                vod_content: desc || '歌单',
                vod_actor: (pl.creator && pl.creator.nickname) || '',
                vod_director: '云音乐',
                vod_remarks: '',
                vod_play_from: playFrom,
                vod_play_url: playUrl || (name || '').replace(/#/g, ' ') + '$song_0'
            };
        } else if (type === 'mv') {
            api = JSON.parse(request(base + '/mv/detail?mvid=' + id, { headers: reqHeaders, timeout: 10000 }) || '{}');
            var m = (api.data || {});
            name = m.name || '';
            pic = (m.cover || m.coverUrl || '').replace('http://', 'https://');
            desc = m.desc || '';
            artist = (m.artists || []).map(function(a) { return a.name; }).join(' / ');
            VOD = {
                vod_id: 'mv_' + id,
                vod_name: name,
                vod_pic: pic,
                vod_content: desc,
                vod_actor: artist,
                vod_director: '云音乐',
                vod_remarks: '',
                vod_play_from: '云音乐',
                vod_play_url: (name || '').replace(/#/g, ' ') + '$mv_' + id
            };
        } else if (type === 'setting' && id === 'menu') {
            VOD = {
                vod_id: 'setting_menu',
                vod_name: '设置',
                vod_pic: '',
                vod_content: '扫码登录 / 注销登录',
                vod_actor: '',
                vod_director: '云音乐',
                vod_remarks: '',
                vod_play_from: '设置',
                vod_play_url: '扫码登录$netmusic_qrcode#注销登录$netmusic_logout'
            };
        } else {
            VOD = { vod_name: '未知类型', vod_content: input };
        }
        }
    `,

    搜索: `js:
        var d = [];
        var raw = (input || '').replace(/\\.html.*$/, '');
        var qs = raw.indexOf('?') >= 0 ? raw.split('?')[1] : '';
        var kw = '';
        if (qs) {
            var m = qs.match(/keywords=([^&]+)/);
            if (m) kw = decodeURIComponent(m[1].replace(/\\+/g, ' '));
        }
        if (!kw) { setResult(d); } else {
        var limit = 30, offset = 0;
        var base = '';
        if (rule.params && rule.params.trim() !== '') {
            try { base = decodeURIComponent(rule.params); } catch (e) { base = rule.params; }
        }
        if (!base) base = (HOST || '').endsWith('/') ? (HOST || '').slice(0, -1) : (HOST || '');
        base = base.endsWith('/') ? base.slice(0, -1) : base;
        var reqHeaders = { 'User-Agent': 'Mozilla/5.0' };
        var netmusicCookie = getStorage('public_netmusic_cookie') || '';
        if (netmusicCookie) reqHeaders['Cookie'] = netmusicCookie;
        var apiBase = base + '/cloudsearch?keywords=' + encodeURIComponent(kw) + '&limit=' + limit + '&offset=' + offset;
        var list, id, name, pic, desc;

        var api1 = JSON.parse(request(apiBase + '&type=1', { headers: reqHeaders, timeout: 10000 }) || '{}');
        list = (api1.result && api1.result.songs) ? api1.result.songs : [];
        list.forEach(function(it) {
            id = it.id;
            name = it.name || '';
            pic = (it.album && it.album.picUrl ? it.album.picUrl : '').replace('http://', 'https://');
            desc = (it.artists || []).map(function(a) { return a.name; }).join(' / ');
            d.push({ url: 'song_' + id, title: name, img: pic, desc: desc || '单曲' });
        });

        var api10 = JSON.parse(request(apiBase + '&type=10', { headers: reqHeaders, timeout: 10000 }) || '{}');
        list = (api10.result && api10.result.albums) ? api10.result.albums : [];
        list.forEach(function(it) {
            id = it.id;
            name = it.name || '';
            pic = (it.picUrl || it.blurPicUrl || '').replace('http://', 'https://');
            desc = (it.artist && it.artist.name) || (it.artists && it.artists[0] ? it.artists[0].name : '');
            d.push({ url: 'album_' + id, title: name, img: pic, desc: desc || '专辑' });
        });

        var api100 = JSON.parse(request(apiBase + '&type=100', { headers: reqHeaders, timeout: 10000 }) || '{}');
        list = (api100.result && api100.result.artists) ? api100.result.artists : [];
        list.forEach(function(it) {
            id = it.id;
            name = it.name || '';
            pic = (it.picUrl || it.img1v1Url || '').replace('http://', 'https://');
            d.push({ url: 'artist_' + id, title: name, img: pic, desc: '歌手' });
        });

        var api1000 = JSON.parse(request(apiBase + '&type=1000', { headers: reqHeaders, timeout: 10000 }) || '{}');
        list = (api1000.result && api1000.result.playlists) ? api1000.result.playlists : [];
        list.forEach(function(it) {
            id = it.id;
            name = it.name || '';
            pic = (it.coverImgUrl || it.picUrl || '').replace('http://', 'https://');
            desc = (it.description || it.copywriter || '').substring(0, 60) || '歌单';
            d.push({ url: 'playlist_' + id, title: name, img: pic, desc: desc });
        });

        setResult(d);
        }
    `,
};
