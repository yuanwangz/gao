// 酷我短剧 DRPY 客户端规则
// 基于官方 OpenAPI 极速秒播，无防盗链与鉴权

var rule = {
    title: '酷我短剧',
    host: 'http://wapi.kuwo.cn',
    url: '/openapi/v1/shortplay/moduleMore?currentPage=fypage&moduleId=fyclass&rn=24',
    class_name: '猜你想看&土味爱情&更多精彩&霸道总裁&赘婿当道&漫漫追妻路&家庭情感',
    class_url: '10&11&12&13&14&15&16',
    searchUrl: '/openapi/v1/shortplay/moduleMore?currentPage=1&moduleId=10&rn=30',
    searchable: 1,
    quickSearch: 0,
    filterable: 0,
    headers: {
        'User-Agent': 'okhttp/5.1.0',
        'Accept': 'application/json'
    },
    play_parse: true,
    一级: `js:
        var d = [];
        try {
            var html = request(input);
            var jo = JSON.parse(html);
            var list = (jo.data && jo.data.list) || [];
            list.forEach(function(it) {
                var id = it.url || it.id;
                var name = it.title || it.subTitle;
                if (id && name) {
                    d.push({
                        vod_id: String(id),
                        vod_name: String(name),
                        vod_pic: String(it.img || ''),
                        vod_remarks: it.currrentDesc || (it.songNum ? (it.songNum + '集全') : '')
                    });
                }
            });
        } catch (e) {
            log('酷我一级异常: ' + e.message);
        }
        setResult(d);
    `,
    二级: `js:
        VOD = {};
        try {
            var detailUrl = 'http://wapi.kuwo.cn/openapi/v1/shortplay/videoList?albumId=' + encodeURIComponent(input);
            var html = request(detailUrl);
            var jo = JSON.parse(html);
            var data = jo.data || {};
            var sinfo = data.shortinfo || {};
            var list = data.list || [];
            var episodes = [];
            list.forEach(function(it, idx) {
                var vid = (it.mvpayinfo && it.mvpayinfo.vid) || '';
                if (vid) {
                    var epTitle = it.name || ('第' + (idx + 1) + '集');
                    epTitle = String(epTitle).replace(/[$#]/g, '_');
                    episodes.push(epTitle + '$' + vid);
                }
            });
            VOD = {
                vod_id: String(input),
                vod_name: sinfo.title || ('短剧 ' + input),
                vod_pic: sinfo.cover || '',
                vod_remarks: '共' + episodes.length + '集',
                vod_content: sinfo.subTitle || sinfo.title || '',
                vod_play_from: '酷我短剧',
                vod_play_url: episodes.join('#')
            };
        } catch (e) {
            log('酷我二级异常: ' + e.message);
        }
    `,
    lazy: `js:
        try {
            var pUrl = 'http://nmobi.kuwo.cn/mobi.s?f=web&type=get_url_by_vid&vid=' + encodeURIComponent(input);
            var res = request(pUrl);
            var match = res.match(/url=(\\S+)/);
            var media = match ? match[1] : '';
            if (media && /^https?:\\/\\//.test(media)) {
                input = {
                    parse: 0,
                    url: media,
                    header: { 'User-Agent': 'okhttp/5.1.0' }
                };
            } else {
                input = { parse: 0, url: '' };
            }
        } catch (e) {
            log('酷我lazy异常: ' + e.message);
            input = { parse: 0, url: '' };
        }
    `,
    搜索: `js:
        var d = [];
        try {
            var cats = ['10', '11', '12', '13', '14', '15', '16'];
            var seen = {};
            var keyword = (typeof KEY !== 'undefined' && KEY) ? KEY : '';
            cats.forEach(function(cid) {
                var url = 'http://wapi.kuwo.cn/openapi/v1/shortplay/moduleMore?currentPage=1&moduleId=' + cid + '&rn=24';
                var html = request(url);
                var jo = JSON.parse(html);
                var list = (jo.data && jo.data.list) || [];
                list.forEach(function(it) {
                    var id = it.url || it.id;
                    var name = it.title || it.subTitle;
                    if (id && name && !seen[id]) {
                        if (!keyword || name.indexOf(keyword) >= 0) {
                            seen[id] = true;
                            d.push({
                                vod_id: String(id),
                                vod_name: String(name),
                                vod_pic: String(it.img || ''),
                                vod_remarks: it.currrentDesc || (it.songNum ? (it.songNum + '集全') : '')
                            });
                        }
                    }
                });
            });
        } catch (e) {
            log('酷我搜索异常: ' + e.message);
        }
        setResult(d);
    `
};
