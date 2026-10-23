// 短剧巴士 DRPY 客户端规则
// 聚合全网热门爆款短剧（含红果/星芽等爆款），全集80~100集，高清M3U8直链秒播

var rule = {
    title: '短剧巴士',
    host: 'https://www.duanju84.com',
    url: '/show/27---fyclass--------fypage---.html',
    class_name: '现代言情&古装仙侠&脑洞悬疑&穿越重生&反转爽剧&全部短剧',
    class_url: '现代言情&古装仙侠&脑洞悬疑&穿越重生&反转爽剧&',
    searchUrl: '/search/-------------.html?wd=**',
    searchable: 1,
    quickSearch: 0,
    filterable: 0,
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    },
    play_parse: true,
    一级: `js:
        var d = [];
        try {
            var html = request(input);
            var matches = [...html.matchAll(/<a[^>]+href="(\\/duanju\\/\\d+\\.html)"[^>]*title="([^"]+)"[^>]*>[\\s\\S]*?<img[^>]+(?:data-original|src)="([^"]+)"[\\s\\S]*?(?:<span[^>]+class="pic-text[^"]*"[^>]*>([^<]*)<\\/span>)?/gi)];
            matches.forEach(function(m) {
                var pic = m[3] || '';
                if (pic && !pic.startsWith('http')) pic = 'https://www.duanju84.com' + pic;
                d.push({
                    vod_id: m[1],
                    vod_name: m[2],
                    vod_pic: pic,
                    vod_remarks: m[4] ? m[4].trim() : ''
                });
            });
        } catch (e) {
            log('短剧巴士一级异常: ' + e.message);
        }
        setResult(d);
    `,
    二级: `js:
        VOD = {};
        try {
            var dUrl = input.startsWith('http') ? input : ('https://www.duanju84.com' + input);
            var html = request(dUrl);
            var title = (html.match(/<h1[^>]*>([^<]+)<\\/h1>/) || [])[1] || '短剧';
            var pic = (html.match(/<div[^>]+class="lazyload"[^>]+data-original="([^"]+)"/) || [])[1] || '';
            if (pic && !pic.startsWith('http')) pic = 'https://www.duanju84.com' + pic;
            var desc = (html.match(/<div[^>]+class="sketch[^"]*"[^>]*>([\\s\\S]*?)<\\/div>/) || [])[1] || '';
            desc = desc.replace(/<[^>]+>/g, '').trim();

            var epMatches = [...html.matchAll(/href="(\\/djplay\\/[^"]+)"[^>]*>([^<]+)<\\/a>/gi)];
            var episodes = [];
            epMatches.forEach(function(m, idx) {
                var name = m[2].trim();
                if (name === '立即播放') name = '第' + (idx + 1) + '集';
                episodes.push(name + '$' + m[1]);
            });

            VOD = {
                vod_id: input,
                vod_name: title,
                vod_pic: pic,
                vod_remarks: '共' + episodes.length + '集',
                vod_content: desc,
                vod_play_from: '短剧巴士',
                vod_play_url: episodes.join('#')
            };
        } catch (e) {
            log('短剧巴士二级异常: ' + e.message);
        }
    `,
    lazy: `js:
        try {
            var pUrl = input.startsWith('http') ? input : ('https://www.duanju84.com' + input);
            var html = request(pUrl);
            var m = html.match(/"url"\\s*:\\s*"([^"]+)"/);
            var playUrl = m ? m[1].replace(/\\\\/g, '') : '';
            if (playUrl) {
                input = {
                    parse: 0,
                    url: playUrl,
                    header: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                        'Referer': 'https://www.duanju84.com/'
                    }
                };
            } else {
                input = { parse: 0, url: '' };
            }
        } catch (e) {
            log('短剧巴士lazy异常: ' + e.message);
            input = { parse: 0, url: '' };
        }
    `,
    搜索: `js:
        var d = [];
        try {
            var word = (typeof KEY !== 'undefined' && KEY) ? encodeURIComponent(KEY) : '';
            if (word) {
                var sUrl = 'https://www.duanju84.com/search/-------------.html?wd=' + word;
                var html = request(sUrl);
                var matches = [...html.matchAll(/<a[^>]+href="(\\/duanju\\/\\d+\\.html)"[^>]*title="([^"]+)"[^>]*>[\\s\\S]*?<img[^>]+(?:data-original|src)="([^"]+)"[\\s\\S]*?(?:<span[^>]+class="pic-text[^"]*"[^>]*>([^<]*)<\\/span>)?/gi)];
                matches.forEach(function(m) {
                    var pic = m[3] || '';
                    if (pic && !pic.startsWith('http')) pic = 'https://www.duanju84.com' + pic;
                    d.push({
                        vod_id: m[1],
                        vod_name: m[2],
                        vod_pic: pic,
                        vod_remarks: m[4] ? m[4].trim() : ''
                    });
                });
            }
        } catch (e) {
            log('短剧巴士搜索异常: ' + e.message);
        }
        setResult(d);
    `
};
