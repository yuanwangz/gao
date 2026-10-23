// 围观短剧 DRPY 客户端规则
// 官方高质量短剧 CDN 直链，秒开播放

var rule = {
    title: '围观短剧',
    host: 'https://api.drama.9ddm.com',
    url: '/drama/home/search?version_code=1500&os_type=1',
    class_name: '全部短剧&都市短剧&古装短剧&逆袭短剧&女频短剧',
    class_url: '全部受众&都市&古装&逆袭&女频',
    searchUrl: '/drama/home/search?version_code=1500&os_type=1',
    searchable: 1,
    quickSearch: 0,
    filterable: 0,
    headers: {
        'User-Agent': 'okhttp/4.10.0',
        'Accept': 'application/json, text/plain, */*',
        'Origin': 'https://api.drama.9ddm.com',
        'Referer': 'https://api.drama.9ddm.com/'
    },
    play_parse: true,
    一级: `js:
        var d = [];
        try {
            var cate = typeof MY_CATE !== 'undefined' ? MY_CATE : '全部受众';
            var page = typeof MY_PAGE !== 'undefined' ? MY_PAGE : 1;
            var host = 'https://api.drama.9ddm.com';
            var searchUrl = host + '/drama/home/search?version_code=1500&os_type=1';
            var payload = {
                audience: cate === '全部受众' ? '全部受众' : cate,
                page: Number(page) || 1,
                pageSize: 24,
                searchWord: '',
                subject: cate !== '全部受众' ? cate : '全部主题'
            };
            var res = request(searchUrl, {
                method: 'POST',
                headers: {
                    'User-Agent': 'okhttp/4.10.0',
                    'Content-Type': 'application/json; charset=utf-8',
                    'Origin': host,
                    'Referer': host + '/'
                },
                body: JSON.stringify(payload)
            });
            var jo = JSON.parse(res);
            var list = jo.data || [];
            list.forEach(function(it) {
                var id = it.oneId || it.id;
                var name = it.dramaName || it.title || it.name;
                if (id && name) {
                    d.push({
                        vod_id: String(id),
                        vod_name: String(name),
                        vod_pic: String(it.coverImg || it.posterImg || it.vertPoster || ''),
                        vod_remarks: it.totalEpisode ? ('全' + it.totalEpisode + '集') : (it.episodeCount ? ('全' + it.episodeCount + '集') : '')
                    });
                }
            });
        } catch (e) {
            log('围观短剧一级异常: ' + e.message);
        }
        setResult(d);
    `,
    二级: `js:
        VOD = {};
        try {
            var host = 'https://api.drama.9ddm.com';
            var detailUrl = host + '/drama/home/shortVideoDetail?version_code=1000&os_type=1&oneId=' + encodeURIComponent(input) + '&page=1&pageSize=1000';
            var res = request(detailUrl, {
                headers: {
                    'User-Agent': 'okhttp/4.10.0',
                    'Origin': host,
                    'Referer': host + '/'
                }
            });
            var jo = JSON.parse(res);
            var items = jo.data || [];
            var episodes = [];
            var firstName = '';
            var firstPic = '';

            items.forEach(function(entry, idx) {
                var n = Number(entry.playOrder) || Number(entry.episode) || (idx + 1);
                var epTitle = entry.title || ('第' + n + '集');
                epTitle = String(epTitle).replace(/[$#]/g, '_');
                if (!firstName && entry.dramaName) firstName = entry.dramaName;
                if (!firstPic && entry.vertPoster) firstPic = entry.vertPoster;

                var playSetting = entry.playSetting || entry.videoClarityList;
                if (typeof playSetting === 'string') {
                    try { playSetting = JSON.parse(playSetting); } catch (e) {}
                }
                var mediaUrl = '';
                if (playSetting) {
                    mediaUrl = playSetting.super || playSetting.high || playSetting.normal || '';
                }
                if (!mediaUrl && entry.playUrl) {
                    mediaUrl = entry.playUrl;
                }
                if (mediaUrl) {
                    episodes.push(epTitle + '$' + mediaUrl);
                }
            });

            VOD = {
                vod_id: String(input),
                vod_name: firstName || ('围观短剧 ' + input),
                vod_pic: firstPic || '',
                vod_remarks: '共' + episodes.length + '集',
                vod_content: firstName || '',
                vod_play_from: '围观短剧',
                vod_play_url: episodes.join('#')
            };
        } catch (e) {
            log('围观短剧二级异常: ' + e.message);
        }
    `,
    lazy: `js:
        if (input && /^https?:\\/\\//.test(input)) {
            input = {
                parse: 0,
                url: input,
                header: {
                    'User-Agent': 'okhttp/4.10.0',
                    'Referer': 'https://api.drama.9ddm.com/'
                }
            };
        } else {
            input = { parse: 0, url: input };
        }
    `,
    搜索: `js:
        var d = [];
        try {
            var keyword = (typeof KEY !== 'undefined' && KEY) ? KEY : '';
            if (keyword) {
                var host = 'https://api.drama.9ddm.com';
                var searchUrl = host + '/drama/home/search?version_code=1500&os_type=1';
                var payload = {
                    audience: '全部受众',
                    page: 1,
                    pageSize: 30,
                    searchWord: keyword,
                    subject: '全部主题'
                };
                var res = request(searchUrl, {
                    method: 'POST',
                    headers: {
                        'User-Agent': 'okhttp/4.10.0',
                        'Content-Type': 'application/json; charset=utf-8',
                        'Origin': host,
                        'Referer': host + '/'
                    },
                    body: JSON.stringify(payload)
                });
                var jo = JSON.parse(res);
                var list = jo.data || [];
                list.forEach(function(it) {
                    var id = it.oneId || it.id;
                    var name = it.dramaName || it.title || it.name;
                    if (id && name) {
                        d.push({
                            vod_id: String(id),
                            vod_name: String(name),
                            vod_pic: String(it.coverImg || it.posterImg || it.vertPoster || ''),
                            vod_remarks: it.totalEpisode ? ('全' + it.totalEpisode + '集') : ''
                        });
                    }
                });
            }
        } catch (e) {
            log('围观短剧搜索异常: ' + e.message);
        }
        setResult(d);
    `
};
