// 星芽短剧 DRPY 客户端规则
// 海量高品质短剧，单剧近百集，带官方直链 MP4

var rule = {
    title: '星芽短剧',
    host: 'https://app.whjzjx.cn',
    url: '/cloud/v2/theater/home_page?theater_class_id=fyclass&type=1&class2_ids=0&page_num=fypage&page_size=24',
    class_name: '剧场&热播剧&会员专享&星选好剧&新剧&阳光剧场',
    class_url: '1&2&8&7&3&5',
    searchUrl: '/v3/search',
    searchable: 1,
    quickSearch: 0,
    filterable: 0,
    headers: {
        'User-Agent': 'okhttp/4.10.0',
        'x-app-id': '7',
        'platform': '1',
        'version_name': '3.3.1',
        'app_version': '3.3.1',
        'device_platform': 'android',
        'device_id': '24250683a3bdb3f118dff25ba4b1cba1a',
        'device_type': 'RMX1931',
        'device_brand': 'realme',
        'os_version': '9',
        'channel': 'default',
        'uuid': 'randomUUID_914e7a9b-deac-4f80-9247-db56669187df'
    },
    play_parse: true,
    一级: `js:
        var d = [];
        try {
            var device = '24250683a3bdb3f118dff25ba4b1cba1a';
            var devToken = 'Bnf9uRPIcKTIOZasAUgUJAUDXhIOlB4lpDKsyLD4yvKm708G4J8PN1Z-gMaFgPwkRvqJrEje81VRxh41IaSj0lNWuoRLUg1r08Z1f0IqSv2q1lvfxrYckKavmnAPYLdkT9P1fPFNRt0RuN3DLLFZqApRDdPD3mM2jB6d79CF2LtM*';
            var appUa = 'Mozilla/5.0 (Linux; Android 9; RMX1931 Build/PQ3A.190605.05081124; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36';

            function getToken() {
                var t = '';
                try { t = getItem('xy_token'); } catch (e) {}
                if (t && t.length > 10) return t;
                var body = 'device=' + device + '&install_first_open=false&first_install_time=1723214205125&last_update_time=1723214205125&report_link_url=';
                var res = request('https://u.shytkjgs.com/user/v1/account/login', {
                    method: 'POST',
                    headers: {
                        'User-Agent': 'okhttp/4.10.0',
                        'x-app-id': '7',
                        'platform': '1',
                        'version_name': '3.3.1',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: body
                });
                var j = JSON.parse(res);
                t = (j.data && j.data.token) || '';
                if (t) {
                    try { setItem('xy_token', t); } catch (e) {}
                }
                return t;
            }

            var token = getToken();
            var reqHeaders = {
                'User-Agent': 'okhttp/4.10.0',
                'x-app-id': '7',
                'platform': '1',
                'version_name': '3.3.1',
                'device_id': device,
                'authorization': token,
                'dev_token': devToken,
                'user_agent': appUa,
                'support_h265': '1'
            };

            var html = request(input, { headers: reqHeaders });
            var jo = JSON.parse(html);
            if (!jo.data && jo.code !== 'ok') {
                // Token可能过期，重试一次
                token = '';
                try { setItem('xy_token', ''); } catch (e) {}
                token = getToken();
                reqHeaders['authorization'] = token;
                html = request(input, { headers: reqHeaders });
                jo = JSON.parse(html);
            }

            var list = (jo.data && jo.data.list) || [];
            list.forEach(function(row) {
                var it = row.theater || row;
                if (it && it.id && it.title) {
                    d.push({
                        vod_id: String(it.id),
                        vod_name: String(it.title),
                        vod_pic: String(it.cover_url || ''),
                        vod_remarks: it.total ? ('共' + it.total + '集') : (it.son_video_total ? ('共' + it.son_video_total + '集') : '')
                    });
                }
            });
        } catch (e) {
            log('星芽一级解析异常: ' + e.message);
        }
        setResult(d);
    `,
    二级: `js:
        VOD = {};
        try {
            var device = '24250683a3bdb3f118dff25ba4b1cba1a';
            var devToken = 'Bnf9uRPIcKTIOZasAUgUJAUDXhIOlB4lpDKsyLD4yvKm708G4J8PN1Z-gMaFgPwkRvqJrEje81VRxh41IaSj0lNWuoRLUg1r08Z1f0IqSv2q1lvfxrYckKavmnAPYLdkT9P1fPFNRt0RuN3DLLFZqApRDdPD3mM2jB6d79CF2LtM*';
            var appUa = 'Mozilla/5.0 (Linux; Android 9; RMX1931 Build/PQ3A.190605.05081124; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36';

            var token = '';
            try { token = getItem('xy_token'); } catch (e) {}
            if (!token) {
                var body = 'device=' + device + '&install_first_open=false&first_install_time=1723214205125&last_update_time=1723214205125&report_link_url=';
                var res = request('https://u.shytkjgs.com/user/v1/account/login', {
                    method: 'POST',
                    headers: { 'User-Agent': 'okhttp/4.10.0', 'x-app-id': '7', 'platform': '1', 'version_name': '3.3.1', 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body
                });
                token = (JSON.parse(res).data && JSON.parse(res).data.token) || '';
                try { setItem('xy_token', token); } catch (e) {}
            }

            var detailUrl = 'https://app.whjzjx.cn/v2/theater_parent/detail?theater_parent_id=' + encodeURIComponent(input);
            var reqHeaders = {
                'User-Agent': 'okhttp/4.10.0',
                'x-app-id': '7',
                'platform': '1',
                'version_name': '3.3.1',
                'device_id': device,
                'authorization': token,
                'dev_token': devToken,
                'user_agent': appUa,
                'support_h265': '1'
            };

            var html = request(detailUrl, { headers: reqHeaders });
            var data = (JSON.parse(html).data) || {};
            var episodes = [];
            var seen = {};
            (data.theaters || []).forEach(function(entry, idx) {
                var n = Number(entry.num) || (idx + 1);
                if (!seen[n]) {
                    seen[n] = true;
                    var epTitle = entry.son_title && entry.son_title !== data.title ? ('第' + n + '集 ' + entry.son_title) : ('第' + n + '集');
                    epTitle = String(epTitle).replace(/[$#]/g, '_');
                    var playUrl = entry.son_video_url || '';
                    if (playUrl) {
                        episodes.push({ n: n, text: epTitle + '$' + playUrl });
                    }
                }
            });

            episodes.sort(function(a, b) { return a.n - b.n; });

            VOD = {
                vod_id: String(input),
                vod_name: data.title || ('星芽短剧 ' + input),
                vod_pic: data.cover_url || '',
                vod_remarks: '共' + episodes.length + '集',
                vod_content: data.introduction || data.title || '',
                vod_play_from: '星芽短剧',
                vod_play_url: episodes.map(function(x) { return x.text; }).join('#')
            };
        } catch (e) {
            log('星芽二级异常: ' + e.message);
        }
    `,
    lazy: `js:
        if (input && /^https?:\\/\\//.test(input)) {
            input = {
                parse: 0,
                url: input,
                header: {
                    'User-Agent': 'Mozilla/5.0 (Linux; Android 9; RMX1931 Build/PQ3A.190605.05081124; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36',
                    'Referer': 'https://app.whjzjx.cn/'
                }
            };
        } else {
            input = { parse: 0, url: input };
        }
    `,
    搜索: `js:
        var d = [];
        try {
            var device = '24250683a3bdb3f118dff25ba4b1cba1a';
            var devToken = 'Bnf9uRPIcKTIOZasAUgUJAUDXhIOlB4lpDKsyLD4yvKm708G4J8PN1Z-gMaFgPwkRvqJrEje81VRxh41IaSj0lNWuoRLUg1r08Z1f0IqSv2q1lvfxrYckKavmnAPYLdkT9P1fPFNRt0RuN3DLLFZqApRDdPD3mM2jB6d79CF2LtM*';
            var appUa = 'Mozilla/5.0 (Linux; Android 9; RMX1931 Build/PQ3A.190605.05081124; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36';

            var token = '';
            try { token = getItem('xy_token'); } catch (e) {}
            var keyword = (typeof KEY !== 'undefined' && KEY) ? KEY : '';
            if (keyword) {
                var searchUrl = 'https://app.whjzjx.cn/v3/search';
                var res = request(searchUrl, {
                    method: 'POST',
                    headers: {
                        'User-Agent': 'okhttp/4.10.0',
                        'x-app-id': '7',
                        'platform': '1',
                        'version_name': '3.3.1',
                        'device_id': device,
                        'authorization': token,
                        'dev_token': devToken,
                        'user_agent': appUa,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: keyword })
                });
                var jo = JSON.parse(res);
                var list = (jo.data && jo.data.theater && jo.data.theater.search_data) || [];
                list.forEach(function(it) {
                    if (it && it.id && it.title) {
                        d.push({
                            vod_id: String(it.id),
                            vod_name: String(it.title),
                            vod_pic: String(it.cover_url || ''),
                            vod_remarks: it.total ? ('共' + it.total + '集') : ''
                        });
                    }
                });
            }
        } catch (e) {
            log('星芽搜索异常: ' + e.message);
        }
        setResult(d);
    `
};
