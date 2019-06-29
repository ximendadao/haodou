// var window = window ||{};
// var navigator = navigator ||{};
// var window = {};
// var navigator = {};

var jsdom =require('jsdom');
var {JSDOM} = jsdom;
var dom  = new JSDOM();
var window = dom.window;
var navigator = dom.window.navigator;
var document = window.document;
var XMLHttpRequest = window.XMLHttpRequest;

        function pidCrypt() {
            function getRandomBytes(len) {
                if (!len)
                    len = 8;
                var bytes = new Array(len);
                var field = [];
                for (var i = 0; i < 256; i++)
                    field[i] = i;
                for (i = 0; i < bytes.length; i++)
                    bytes[i] = field[Math.floor(Math.random() * field.length)];
                return bytes
            }
            this.setDefaults = function() {
                this.params.nBits = 256;
                this.params.salt = getRandomBytes(8);
                this.params.salt = pidCryptUtil.byteArray2String(this.params.salt);
                this.params.salt = pidCryptUtil.convertToHex(this.params.salt);
                this.params.blockSize = 16;
                this.params.UTF8 = true;
                this.params.A0_PAD = true
            }
            ;
            this.debug = true;
            this.params = {};
            this.params.dataIn = '';
            this.params.dataOut = '';
            this.params.decryptIn = '';
            this.params.decryptOut = '';
            this.params.encryptIn = '';
            this.params.encryptOut = '';
            this.params.key = '';
            this.params.iv = '';
            this.params.clear = true;
            this.setDefaults();
            this.errors = '';
            this.warnings = '';
            this.infos = '';
            this.debugMsg = '';
            this.setParams = function(pObj) {
                if (!pObj)
                    pObj = {};
                for (var p in pObj)
                    this.params[p] = pObj[p]
            }
            ;
            this.getParams = function() {
                return this.params
            }
            ;
            this.getParam = function(p) {
                return this.params[p] || ''
            }
            ;
            this.clearParams = function() {
                this.params = {}
            }
            ;
            this.getNBits = function() {
                return this.params.nBits
            }
            ;
            this.getOutput = function() {
                return this.params.dataOut
            }
            ;
            this.setError = function(str) {
                this.error = str
            }
            ;
            this.appendError = function(str) {
                this.errors += str;
                return ''
            }
            ;
            this.getErrors = function() {
                return this.errors
            }
            ;
            this.isError = function() {
                if (this.errors.length > 0)
                    return true;
                return false
            }
            ;
            this.appendInfo = function(str) {
                this.infos += str;
                return ''
            }
            ;
            this.getInfos = function() {
                return this.infos
            }
            ;
            this.setDebug = function(flag) {
                this.debug = flag
            }
            ;
            this.appendDebug = function(str) {
                this.debugMsg += str;
                return ''
            }
            ;
            this.isDebug = function() {
                return this.debug
            }
            ;
            this.getAllMessages = function(options) {
                var defaults = {
                    lf: '\n',
                    clr_mes: false,
                    verbose: 15
                };
                if (!options)
                    options = defaults;
                for (var d in defaults)
                    if (typeof (options[d]) == 'undefined')
                        options[d] = defaults[d];
                var mes = '';
                var tmp = '';
                for (var p in this.params) {
                    switch (p) {
                        case 'encryptOut':
                            tmp = pidCryptUtil.toByteArray(this.params[p].toString());
                            tmp = pidCryptUtil.fragment(tmp.join(), 64, options.lf);
                            break;
                        case 'key':
                        case 'iv':
                            tmp = pidCryptUtil.formatHex(this.params[p], 48);
                            break;
                        default:
                            tmp = pidCryptUtil.fragment(this.params[p].toString(), 64, options.lf)
                    }
                    mes += '<p><b>' + p + '</b>:<pre>' + tmp + '</pre></p>'
                }
                if (this.debug)
                    mes += 'debug: ' + this.debug + options.lf;
                if (this.errors.length > 0 && ((options.verbose & 1) == 1))
                    mes += 'Errors:' + options.lf + this.errors + options.lf;
                if (this.warnings.length > 0 && ((options.verbose & 2) == 2))
                    mes += 'Warnings:' + options.lf + this.warnings + options.lf;
                if (this.infos.length > 0 && ((options.verbose & 4) == 4))
                    mes += 'Infos:' + options.lf + this.infos + options.lf;
                if (this.debug && ((options.verbose & 8) == 8))
                    mes += 'Debug messages:' + options.lf + this.debugMsg + options.lf;
                if (options.clr_mes)
                    this.errors = this.infos = this.warnings = this.debug = '';
                return mes
            }
            ;
            this.getRandomBytes = function(len) {
                return getRandomBytes(len)
            }
        }
        pidCryptUtil = {};
        pidCryptUtil.encodeBase64 = function(str, utf8encode) {
            if (!str)
                str = "";
            var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            utf8encode = (typeof utf8encode == 'undefined') ? false : utf8encode;
            var o1, o2, o3, bits, h1, h2, h3, h4, e = [], pad = '', c, plain, coded;
            plain = utf8encode ? pidCryptUtil.encodeUTF8(str) : str;
            c = plain.length % 3;
            if (c > 0) {
                while (c++ < 3) {
                    pad += '=';
                    plain += '\0'
                }
            }
            for (c = 0; c < plain.length; c += 3) {
                o1 = plain.charCodeAt(c);
                o2 = plain.charCodeAt(c + 1);
                o3 = plain.charCodeAt(c + 2);
                bits = o1 << 16 | o2 << 8 | o3;
                h1 = bits >> 18 & 0x3f;
                h2 = bits >> 12 & 0x3f;
                h3 = bits >> 6 & 0x3f;
                h4 = bits & 0x3f;
                e[c / 3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4)
            }
            coded = e.join('');
            coded = coded.slice(0, coded.length - pad.length) + pad;
            return coded
        }
        ;
        pidCryptUtil.decodeBase64 = function(str, utf8decode) {
            if (!str)
                str = "";
            var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            utf8decode = (typeof utf8decode == 'undefined') ? false : utf8decode;
            var o1, o2, o3, h1, h2, h3, h4, bits, d = [], plain, coded;
            coded = utf8decode ? pidCryptUtil.decodeUTF8(str) : str;
            for (var c = 0; c < coded.length; c += 4) {
                h1 = b64.indexOf(coded.charAt(c));
                h2 = b64.indexOf(coded.charAt(c + 1));
                h3 = b64.indexOf(coded.charAt(c + 2));
                h4 = b64.indexOf(coded.charAt(c + 3));
                bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;
                o1 = bits >>> 16 & 0xff;
                o2 = bits >>> 8 & 0xff;
                o3 = bits & 0xff;
                d[c / 4] = String.fromCharCode(o1, o2, o3);
                if (h4 == 0x40)
                    d[c / 4] = String.fromCharCode(o1, o2);
                if (h3 == 0x40)
                    d[c / 4] = String.fromCharCode(o1)
            }
            plain = d.join('');
            plain = utf8decode ? pidCryptUtil.decodeUTF8(plain) : plain;
            return plain
        }
        ;
        pidCryptUtil.encodeUTF8 = function(str) {
            if (!str)
                str = "";
            str = str.replace(/[\u0080-\u07ff]/g, function(c) {
                var cc = c.charCodeAt(0);
                return String.fromCharCode(0xc0 | cc >> 6, 0x80 | cc & 0x3f)
            });
            str = str.replace(/[\u0800-\uffff]/g, function(c) {
                var cc = c.charCodeAt(0);
                return String.fromCharCode(0xe0 | cc >> 12, 0x80 | cc >> 6 & 0x3F, 0x80 | cc & 0x3f)
            });
            return str
        }
        ;
        pidCryptUtil.decodeUTF8 = function(str) {
            if (!str)
                str = "";
            str = str.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g, function(c) {
                var cc = (c.charCodeAt(0) & 0x1f) << 6 | c.charCodeAt(1) & 0x3f;
                return String.fromCharCode(cc)
            });
            str = str.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g, function(c) {
                var cc = ((c.charCodeAt(0) & 0x0f) << 12) | ((c.charCodeAt(1) & 0x3f) << 6) | (c.charCodeAt(2) & 0x3f);
                return String.fromCharCode(cc)
            });
            return str
        }
        ;
        pidCryptUtil.convertToHex = function(str) {
            if (!str)
                str = "";
            var hs = '';
            var hv = '';
            for (var i = 0; i < str.length; i++) {
                hv = str.charCodeAt(i).toString(16);
                hs += (hv.length == 1) ? '0' + hv : hv
            }
            return hs
        }
        ;
        pidCryptUtil.convertFromHex = function(str) {
            if (!str)
                str = "";
            var s = "";
            for (var i = 0; i < str.length; i += 2) {
                s += String.fromCharCode(parseInt(str.substring(i, i + 2), 16))
            }
            return s
        }
        ;
        pidCryptUtil.stripLineFeeds = function(str) {
            if (!str)
                str = "";
            var s = '';
            s = str.replace(/\n/g, '');
            s = s.replace(/\r/g, '');
            return s
        }
        ;
        pidCryptUtil.toByteArray = function(str) {
            if (!str)
                str = "";
            var ba = [];
            for (var i = 0; i < str.length; i++)
                ba[i] = str.charCodeAt(i);
            return ba
        }
        ;
        pidCryptUtil.fragment = function(str, length, lf) {
            if (!str)
                str = "";
            if (!length || length >= str.length)
                return str;
            if (!lf)
                lf = '\n';
            var tmp = '';
            for (var i = 0; i < str.length; i += length)
                tmp += str.substr(i, length) + lf;
            return tmp
        }
        ;
        pidCryptUtil.formatHex = function(str, length) {
            if (!str)
                str = "";
            if (!length)
                length = 45;
            var str_new = '';
            var j = 0;
            var hex = str.toLowerCase();
            for (var i = 0; i < hex.length; i += 2)
                str_new += hex.substr(i, 2) + ':';
            hex = this.fragment(str_new, length);
            return hex
        }
        ;
        pidCryptUtil.byteArray2String = function(b) {
            var s = '';
            for (var i = 0; i < b.length; i++) {
                s += String.fromCharCode(b[i])
            }
            return s
        }
        ;
        var dbits;
        var canary = 0xdeadbeefcafe;
        var j_lm = ((canary & 0xffffff) == 0xefcafe);
        function BigInteger(a, b, c) {
            if (a != null)
                if ("number" == typeof a)
                    this.fromNumber(a, b, c);
                else if (b == null && "string" != typeof a)
                    this.fromString(a, 256);
                else
                    this.fromString(a, b)
        }
        function nbi() {
            return new BigInteger(null)
        }
        function am1(i, x, w, j, c, n) {
            while (--n >= 0) {
                var v = x * this[i++] + w[j] + c;
                c = Math.floor(v / 0x4000000);
                w[j++] = v & 0x3ffffff
            }
            return c
        }
        function am2(i, x, w, j, c, n) {
            var xl = x & 0x7fff
                , xh = x >> 15;
            while (--n >= 0) {
                var l = this[i] & 0x7fff;
                var h = this[i++] >> 15;
                var m = xh * l + h * xl;
                l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
                c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
                w[j++] = l & 0x3fffffff
            }
            return c
        }
        function am3(i, x, w, j, c, n) {
            var xl = x & 0x3fff
                , xh = x >> 14;
            while (--n >= 0) {
                var l = this[i] & 0x3fff;
                var h = this[i++] >> 14;
                var m = xh * l + h * xl;
                l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
                c = (l >> 28) + (m >> 14) + xh * h;
                w[j++] = l & 0xfffffff
            }
            return c
        }
        if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
            BigInteger.prototype.am = am2;
            dbits = 30
        } else if (j_lm && (navigator.appName != "Netscape")) {
            BigInteger.prototype.am = am1;
            dbits = 26
        } else {
            BigInteger.prototype.am = am3;
            dbits = 28
        }
        BigInteger.prototype.DB = dbits;
        BigInteger.prototype.DM = ((1 << dbits) - 1);
        BigInteger.prototype.DV = (1 << dbits);
        var BI_FP = 52;
        BigInteger.prototype.FV = Math.pow(2, BI_FP);
        BigInteger.prototype.F1 = BI_FP - dbits;
        BigInteger.prototype.F2 = 2 * dbits - BI_FP;
        var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
        var BI_RC = new Array();
        var rr, vv;
        rr = "0".charCodeAt(0);
        for (vv = 0; vv <= 9; ++vv)
            BI_RC[rr++] = vv;
        rr = "a".charCodeAt(0);
        for (vv = 10; vv < 36; ++vv)
            BI_RC[rr++] = vv;
        rr = "A".charCodeAt(0);
        for (vv = 10; vv < 36; ++vv)
            BI_RC[rr++] = vv;
        function int2char(n) {
            return BI_RM.charAt(n)
        }
        function intAt(s, i) {
            var c = BI_RC[s.charCodeAt(i)];
            return (c == null) ? -1 : c
        }
        function bnpCopyTo(r) {
            for (var i = this.t - 1; i >= 0; --i)
                r[i] = this[i];
            r.t = this.t;
            r.s = this.s
        }
        function bnpFromInt(x) {
            this.t = 1;
            this.s = (x < 0) ? -1 : 0;
            if (x > 0)
                this[0] = x;
            else if (x < -1)
                this[0] = x + DV;
            else
                this.t = 0
        }
        function nbv(i) {
            var r = nbi();
            r.fromInt(i);
            return r
        }
        function bnpFromString(s, b) {
            var k;
            if (b == 16)
                k = 4;
            else if (b == 8)
                k = 3;
            else if (b == 256)
                k = 8;
            else if (b == 2)
                k = 1;
            else if (b == 32)
                k = 5;
            else if (b == 4)
                k = 2;
            else {
                this.fromRadix(s, b);
                return
            }
            this.t = 0;
            this.s = 0;
            var i = s.length
                , mi = false
                , sh = 0;
            while (--i >= 0) {
                var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
                if (x < 0) {
                    if (s.charAt(i) == "-")
                        mi = true;
                    continue
                }
                mi = false;
                if (sh == 0)
                    this[this.t++] = x;
                else if (sh + k > this.DB) {
                    this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                    this[this.t++] = (x >> (this.DB - sh))
                } else
                    this[this.t - 1] |= x << sh;
                sh += k;
                if (sh >= this.DB)
                    sh -= this.DB
            }
            if (k == 8 && (s[0] & 0x80) != 0) {
                this.s = -1;
                if (sh > 0)
                    this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh
            }
            this.clamp();
            if (mi)
                BigInteger.ZERO.subTo(this, this)
        }
        function bnpClamp() {
            var c = this.s & this.DM;
            while (this.t > 0 && this[this.t - 1] == c)
                --this.t
        }
        function bnToString(b) {
            if (this.s < 0)
                return "-" + this.negate().toString(b);
            var k;
            if (b == 16)
                k = 4;
            else if (b == 8)
                k = 3;
            else if (b == 2)
                k = 1;
            else if (b == 32)
                k = 5;
            else if (b == 4)
                k = 2;
            else
                return this.toRadix(b);
            var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
            var p = this.DB - (i * this.DB) % k;
            if (i-- > 0) {
                if (p < this.DB && (d = this[i] >> p) > 0) {
                    m = true;
                    r = int2char(d)
                }
                while (i >= 0) {
                    if (p < k) {
                        d = (this[i] & ((1 << p) - 1)) << (k - p);
                        d |= this[--i] >> (p += this.DB - k)
                    } else {
                        d = (this[i] >> (p -= k)) & km;
                        if (p <= 0) {
                            p += this.DB;
                            --i
                        }
                    }
                    if (d > 0)
                        m = true;
                    if (m)
                        r += int2char(d)
                }
            }
            return m ? r : "0"
        }
        function bnNegate() {
            var r = nbi();
            BigInteger.ZERO.subTo(this, r);
            return r
        }
        function bnAbs() {
            return (this.s < 0) ? this.negate() : this
        }
        function bnCompareTo(a) {
            var r = this.s - a.s;
            if (r != 0)
                return r;
            var i = this.t;
            r = i - a.t;
            if (r != 0)
                return r;
            while (--i >= 0)
                if ((r = this[i] - a[i]) != 0)
                    return r;
            return 0
        }
        function nbits(x) {
            var r = 1, t;
            if ((t = x >>> 16) != 0) {
                x = t;
                r += 16
            }
            if ((t = x >> 8) != 0) {
                x = t;
                r += 8
            }
            if ((t = x >> 4) != 0) {
                x = t;
                r += 4
            }
            if ((t = x >> 2) != 0) {
                x = t;
                r += 2
            }
            if ((t = x >> 1) != 0) {
                x = t;
                r += 1
            }
            return r
        }
        function bnBitLength() {
            if (this.t <= 0)
                return 0;
            return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM))
        }
        function bnpDLShiftTo(n, r) {
            var i;
            for (i = this.t - 1; i >= 0; --i)
                r[i + n] = this[i];
            for (i = n - 1; i >= 0; --i)
                r[i] = 0;
            r.t = this.t + n;
            r.s = this.s
        }
        function bnpDRShiftTo(n, r) {
            for (var i = n; i < this.t; ++i)
                r[i - n] = this[i];
            r.t = Math.max(this.t - n, 0);
            r.s = this.s
        }
        function bnpLShiftTo(n, r) {
            var bs = n % this.DB;
            var cbs = this.DB - bs;
            var bm = (1 << cbs) - 1;
            var ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
            for (i = this.t - 1; i >= 0; --i) {
                r[i + ds + 1] = (this[i] >> cbs) | c;
                c = (this[i] & bm) << bs
            }
            for (i = ds - 1; i >= 0; --i)
                r[i] = 0;
            r[ds] = c;
            r.t = this.t + ds + 1;
            r.s = this.s;
            r.clamp()
        }
        function bnpRShiftTo(n, r) {
            r.s = this.s;
            var ds = Math.floor(n / this.DB);
            if (ds >= this.t) {
                r.t = 0;
                return
            }
            var bs = n % this.DB;
            var cbs = this.DB - bs;
            var bm = (1 << bs) - 1;
            r[0] = this[ds] >> bs;
            for (var i = ds + 1; i < this.t; ++i) {
                r[i - ds - 1] |= (this[i] & bm) << cbs;
                r[i - ds] = this[i] >> bs
            }
            if (bs > 0)
                r[this.t - ds - 1] |= (this.s & bm) << cbs;
            r.t = this.t - ds;
            r.clamp()
        }
        function bnpSubTo(a, r) {
            var i = 0
                , c = 0
                , m = Math.min(a.t, this.t);
            while (i < m) {
                c += this[i] - a[i];
                r[i++] = c & this.DM;
                c >>= this.DB
            }
            if (a.t < this.t) {
                c -= a.s;
                while (i < this.t) {
                    c += this[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB
                }
                c += this.s
            } else {
                c += this.s;
                while (i < a.t) {
                    c -= a[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB
                }
                c -= a.s
            }
            r.s = (c < 0) ? -1 : 0;
            if (c < -1)
                r[i++] = this.DV + c;
            else if (c > 0)
                r[i++] = c;
            r.t = i;
            r.clamp()
        }
        function bnpMultiplyTo(a, r) {
            var x = this.abs()
                , y = a.abs();
            var i = x.t;
            r.t = i + y.t;
            while (--i >= 0)
                r[i] = 0;
            for (i = 0; i < y.t; ++i)
                r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
            r.s = 0;
            r.clamp();
            if (this.s != a.s)
                BigInteger.ZERO.subTo(r, r)
        }
        function bnpSquareTo(r) {
            var x = this.abs();
            var i = r.t = 2 * x.t;
            while (--i >= 0)
                r[i] = 0;
            for (i = 0; i < x.t - 1; ++i) {
                var c = x.am(i, x[i], r, 2 * i, 0, 1);
                if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                    r[i + x.t] -= x.DV;
                    r[i + x.t + 1] = 1
                }
            }
            if (r.t > 0)
                r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
            r.s = 0;
            r.clamp()
        }
        function bnpDivRemTo(m, q, r) {
            var pm = m.abs();
            if (pm.t <= 0)
                return;
            var pt = this.abs();
            if (pt.t < pm.t) {
                if (q != null)
                    q.fromInt(0);
                if (r != null)
                    this.copyTo(r);
                return
            }
            if (r == null)
                r = nbi();
            var y = nbi()
                , ts = this.s
                , ms = m.s;
            var nsh = this.DB - nbits(pm[pm.t - 1]);
            if (nsh > 0) {
                pm.lShiftTo(nsh, y);
                pt.lShiftTo(nsh, r)
            } else {
                pm.copyTo(y);
                pt.copyTo(r)
            }
            var ys = y.t;
            var y0 = y[ys - 1];
            if (y0 == 0)
                return;
            var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
            var d1 = this.FV / yt
                , d2 = (1 << this.F1) / yt
                , e = 1 << this.F2;
            var i = r.t
                , j = i - ys
                , t = (q == null) ? nbi() : q;
            y.dlShiftTo(j, t);
            if (r.compareTo(t) >= 0) {
                r[r.t++] = 1;
                r.subTo(t, r)
            }
            BigInteger.ONE.dlShiftTo(ys, t);
            t.subTo(y, y);
            while (y.t < ys)
                y[y.t++] = 0;
            while (--j >= 0) {
                var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
                if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
                    y.dlShiftTo(j, t);
                    r.subTo(t, r);
                    while (r[i] < --qd)
                        r.subTo(t, r)
                }
            }
            if (q != null) {
                r.drShiftTo(ys, q);
                if (ts != ms)
                    BigInteger.ZERO.subTo(q, q)
            }
            r.t = ys;
            r.clamp();
            if (nsh > 0)
                r.rShiftTo(nsh, r);
            if (ts < 0)
                BigInteger.ZERO.subTo(r, r)
        }
        function bnMod(a) {
            var r = nbi();
            this.abs().divRemTo(a, null, r);
            if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
                a.subTo(r, r);
            return r
        }
        function Classic(m) {
            this.m = m
        }
        function cConvert(x) {
            if (x.s < 0 || x.compareTo(this.m) >= 0)
                return x.mod(this.m);
            else
                return x
        }
        function cRevert(x) {
            return x
        }
        function cReduce(x) {
            x.divRemTo(this.m, null, x)
        }
        function cMulTo(x, y, r) {
            x.multiplyTo(y, r);
            this.reduce(r)
        }
        function cSqrTo(x, r) {
            x.squareTo(r);
            this.reduce(r)
        }
        Classic.prototype.convert = cConvert;
        Classic.prototype.revert = cRevert;
        Classic.prototype.reduce = cReduce;
        Classic.prototype.mulTo = cMulTo;
        Classic.prototype.sqrTo = cSqrTo;
        function bnpInvDigit() {
            if (this.t < 1)
                return 0;
            var x = this[0];
            if ((x & 1) == 0)
                return 0;
            var y = x & 3;
            y = (y * (2 - (x & 0xf) * y)) & 0xf;
            y = (y * (2 - (x & 0xff) * y)) & 0xff;
            y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;
            y = (y * (2 - x * y % this.DV)) % this.DV;
            return (y > 0) ? this.DV - y : -y
        }
        function Montgomery(m) {
            this.m = m;
            this.mp = m.invDigit();
            this.mpl = this.mp & 0x7fff;
            this.mph = this.mp >> 15;
            this.um = (1 << (m.DB - 15)) - 1;
            this.mt2 = 2 * m.t
        }
        function montConvert(x) {
            var r = nbi();
            x.abs().dlShiftTo(this.m.t, r);
            r.divRemTo(this.m, null, r);
            if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
                this.m.subTo(r, r);
            return r
        }
        function montRevert(x) {
            var r = nbi();
            x.copyTo(r);
            this.reduce(r);
            return r
        }
        function montReduce(x) {
            while (x.t <= this.mt2)
                x[x.t++] = 0;
            for (var i = 0; i < this.m.t; ++i) {
                var j = x[i] & 0x7fff;
                var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
                j = i + this.m.t;
                x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
                while (x[j] >= x.DV) {
                    x[j] -= x.DV;
                    x[++j]++
                }
            }
            x.clamp();
            x.drShiftTo(this.m.t, x);
            if (x.compareTo(this.m) >= 0)
                x.subTo(this.m, x)
        }
        function montSqrTo(x, r) {
            x.squareTo(r);
            this.reduce(r)
        }
        function montMulTo(x, y, r) {
            x.multiplyTo(y, r);
            this.reduce(r)
        }
        Montgomery.prototype.convert = montConvert;
        Montgomery.prototype.revert = montRevert;
        Montgomery.prototype.reduce = montReduce;
        Montgomery.prototype.mulTo = montMulTo;
        Montgomery.prototype.sqrTo = montSqrTo;
        function bnpIsEven() {
            return ((this.t > 0) ? (this[0] & 1) : this.s) == 0
        }
        function bnpExp(e, z) {
            if (e > 0xffffffff || e < 1)
                return BigInteger.ONE;
            var r = nbi()
                , r2 = nbi()
                , g = z.convert(this)
                , i = nbits(e) - 1;
            g.copyTo(r);
            while (--i >= 0) {
                z.sqrTo(r, r2);
                if ((e & (1 << i)) > 0)
                    z.mulTo(r2, g, r);
                else {
                    var t = r;
                    r = r2;
                    r2 = t
                }
            }
            return z.revert(r)
        }
        function bnModPowInt(e, m) {
            var z;
            if (e < 256 || m.isEven())
                z = new Classic(m);
            else
                z = new Montgomery(m);
            return this.exp(e, z)
        }
        BigInteger.prototype.copyTo = bnpCopyTo;
        BigInteger.prototype.fromInt = bnpFromInt;
        BigInteger.prototype.fromString = bnpFromString;
        BigInteger.prototype.clamp = bnpClamp;
        BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
        BigInteger.prototype.drShiftTo = bnpDRShiftTo;
        BigInteger.prototype.lShiftTo = bnpLShiftTo;
        BigInteger.prototype.rShiftTo = bnpRShiftTo;
        BigInteger.prototype.subTo = bnpSubTo;
        BigInteger.prototype.multiplyTo = bnpMultiplyTo;
        BigInteger.prototype.squareTo = bnpSquareTo;
        BigInteger.prototype.divRemTo = bnpDivRemTo;
        BigInteger.prototype.invDigit = bnpInvDigit;
        BigInteger.prototype.isEven = bnpIsEven;
        BigInteger.prototype.exp = bnpExp;
        BigInteger.prototype.toString = bnToString;
        BigInteger.prototype.negate = bnNegate;
        BigInteger.prototype.abs = bnAbs;
        BigInteger.prototype.compareTo = bnCompareTo;
        BigInteger.prototype.bitLength = bnBitLength;
        BigInteger.prototype.mod = bnMod;
        BigInteger.prototype.modPowInt = bnModPowInt;
        BigInteger.ZERO = nbv(0);
        BigInteger.ONE = nbv(1);
        function bnClone() {
            var r = nbi();
            this.copyTo(r);
            return r
        }
        function bnIntValue() {
            if (this.s < 0) {
                if (this.t == 1)
                    return this[0] - this.DV;
                else if (this.t == 0)
                    return -1
            } else if (this.t == 1)
                return this[0];
            else if (this.t == 0)
                return 0;
            return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0]
        }
        function bnByteValue() {
            return (this.t == 0) ? this.s : (this[0] << 24) >> 24
        }
        function bnShortValue() {
            return (this.t == 0) ? this.s : (this[0] << 16) >> 16
        }
        function bnpChunkSize(r) {
            return Math.floor(Math.LN2 * this.DB / Math.log(r))
        }
        function bnSigNum() {
            if (this.s < 0)
                return -1;
            else if (this.t <= 0 || (this.t == 1 && this[0] <= 0))
                return 0;
            else
                return 1
        }
        function bnpToRadix(b) {
            if (b == null)
                b = 10;
            if (this.signum() == 0 || b < 2 || b > 36)
                return "0";
            var cs = this.chunkSize(b);
            var a = Math.pow(b, cs);
            var d = nbv(a)
                , y = nbi()
                , z = nbi()
                , r = "";
            this.divRemTo(d, y, z);
            while (y.signum() > 0) {
                r = (a + z.intValue()).toString(b).substr(1) + r;
                y.divRemTo(d, y, z)
            }
            return z.intValue().toString(b) + r
        }
        function bnpFromRadix(s, b) {
            this.fromInt(0);
            if (b == null)
                b = 10;
            var cs = this.chunkSize(b);
            var d = Math.pow(b, cs)
                , mi = false
                , j = 0
                , w = 0;
            for (var i = 0; i < s.length; ++i) {
                var x = intAt(s, i);
                if (x < 0) {
                    if (s.charAt(i) == "-" && this.signum() == 0)
                        mi = true;
                    continue
                }
                w = b * w + x;
                if (++j >= cs) {
                    this.dMultiply(d);
                    this.dAddOffset(w, 0);
                    j = 0;
                    w = 0
                }
            }
            if (j > 0) {
                this.dMultiply(Math.pow(b, j));
                this.dAddOffset(w, 0)
            }
            if (mi)
                BigInteger.ZERO.subTo(this, this)
        }
        function bnpFromNumber(a, b, c) {
            if ("number" == typeof b) {
                if (a < 2)
                    this.fromInt(1);
                else {
                    this.fromNumber(a, c);
                    if (!this.testBit(a - 1))
                        this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
                    if (this.isEven())
                        this.dAddOffset(1, 0);
                    while (!this.isProbablePrime(b)) {
                        this.dAddOffset(2, 0);
                        if (this.bitLength() > a)
                            this.subTo(BigInteger.ONE.shiftLeft(a - 1), this)
                    }
                }
            } else {
                var x = new Array()
                    , t = a & 7;
                x.length = (a >> 3) + 1;
                b.nextBytes(x);
                if (t > 0)
                    x[0] &= ((1 << t) - 1);
                else
                    x[0] = 0;
                this.fromString(x, 256)
            }
        }
        function bnToByteArray() {
            var i = this.t
                , r = new Array();
            r[0] = this.s;
            var p = this.DB - (i * this.DB) % 8, d, k = 0;
            if (i-- > 0) {
                if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
                    r[k++] = d | (this.s << (this.DB - p));
                while (i >= 0) {
                    if (p < 8) {
                        d = (this[i] & ((1 << p) - 1)) << (8 - p);
                        d |= this[--i] >> (p += this.DB - 8)
                    } else {
                        d = (this[i] >> (p -= 8)) & 0xff;
                        if (p <= 0) {
                            p += this.DB;
                            --i
                        }
                    }
                    if ((d & 0x80) != 0)
                        d |= -256;
                    if (k == 0 && (this.s & 0x80) != (d & 0x80))
                        ++k;
                    if (k > 0 || d != this.s)
                        r[k++] = d
                }
            }
            return r
        }
        function bnEquals(a) {
            return (this.compareTo(a) == 0)
        }
        function bnMin(a) {
            return (this.compareTo(a) < 0) ? this : a
        }
        function bnMax(a) {
            return (this.compareTo(a) > 0) ? this : a
        }
        function bnpBitwiseTo(a, op, r) {
            var i, f, m = Math.min(a.t, this.t);
            for (i = 0; i < m; ++i)
                r[i] = op(this[i], a[i]);
            if (a.t < this.t) {
                f = a.s & this.DM;
                for (i = m; i < this.t; ++i)
                    r[i] = op(this[i], f);
                r.t = this.t
            } else {
                f = this.s & this.DM;
                for (i = m; i < a.t; ++i)
                    r[i] = op(f, a[i]);
                r.t = a.t
            }
            r.s = op(this.s, a.s);
            r.clamp()
        }
        function op_and(x, y) {
            return x & y
        }
        function bnAnd(a) {
            var r = nbi();
            this.bitwiseTo(a, op_and, r);
            return r
        }
        function op_or(x, y) {
            return x | y
        }
        function bnOr(a) {
            var r = nbi();
            this.bitwiseTo(a, op_or, r);
            return r
        }
        function op_xor(x, y) {
            return x ^ y
        }
        function bnXor(a) {
            var r = nbi();
            this.bitwiseTo(a, op_xor, r);
            return r
        }
        function op_andnot(x, y) {
            return x & ~y
        }
        function bnAndNot(a) {
            var r = nbi();
            this.bitwiseTo(a, op_andnot, r);
            return r
        }
        function bnNot() {
            var r = nbi();
            for (var i = 0; i < this.t; ++i)
                r[i] = this.DM & ~this[i];
            r.t = this.t;
            r.s = ~this.s;
            return r
        }
        function bnShiftLeft(n) {
            var r = nbi();
            if (n < 0)
                this.rShiftTo(-n, r);
            else
                this.lShiftTo(n, r);
            return r
        }
        function bnShiftRight(n) {
            var r = nbi();
            if (n < 0)
                this.lShiftTo(-n, r);
            else
                this.rShiftTo(n, r);
            return r
        }
        function lbit(x) {
            if (x == 0)
                return -1;
            var r = 0;
            if ((x & 0xffff) == 0) {
                x >>= 16;
                r += 16
            }
            if ((x & 0xff) == 0) {
                x >>= 8;
                r += 8
            }
            if ((x & 0xf) == 0) {
                x >>= 4;
                r += 4
            }
            if ((x & 3) == 0) {
                x >>= 2;
                r += 2
            }
            if ((x & 1) == 0)
                ++r;
            return r
        }
        function bnGetLowestSetBit() {
            for (var i = 0; i < this.t; ++i)
                if (this[i] != 0)
                    return i * this.DB + lbit(this[i]);
            if (this.s < 0)
                return this.t * this.DB;
            return -1
        }
        function cbit(x) {
            var r = 0;
            while (x != 0) {
                x &= x - 1;
                ++r
            }
            return r
        }
        function bnBitCount() {
            var r = 0
                , x = this.s & this.DM;
            for (var i = 0; i < this.t; ++i)
                r += cbit(this[i] ^ x);
            return r
        }
        function bnTestBit(n) {
            var j = Math.floor(n / this.DB);
            if (j >= this.t)
                return (this.s != 0);
            return ((this[j] & (1 << (n % this.DB))) != 0)
        }
        function bnpChangeBit(n, op) {
            var r = BigInteger.ONE.shiftLeft(n);
            this.bitwiseTo(r, op, r);
            return r
        }
        function bnSetBit(n) {
            return this.changeBit(n, op_or)
        }
        function bnClearBit(n) {
            return this.changeBit(n, op_andnot)
        }
        function bnFlipBit(n) {
            return this.changeBit(n, op_xor)
        }
        function bnpAddTo(a, r) {
            var i = 0
                , c = 0
                , m = Math.min(a.t, this.t);
            while (i < m) {
                c += this[i] + a[i];
                r[i++] = c & this.DM;
                c >>= this.DB
            }
            if (a.t < this.t) {
                c += a.s;
                while (i < this.t) {
                    c += this[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB
                }
                c += this.s
            } else {
                c += this.s;
                while (i < a.t) {
                    c += a[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB
                }
                c += a.s
            }
            r.s = (c < 0) ? -1 : 0;
            if (c > 0)
                r[i++] = c;
            else if (c < -1)
                r[i++] = this.DV + c;
            r.t = i;
            r.clamp()
        }
        function bnAdd(a) {
            var r = nbi();
            this.addTo(a, r);
            return r
        }
        function bnSubtract(a) {
            var r = nbi();
            this.subTo(a, r);
            return r
        }
        function bnMultiply(a) {
            var r = nbi();
            this.multiplyTo(a, r);
            return r
        }
        function bnDivide(a) {
            var r = nbi();
            this.divRemTo(a, r, null);
            return r
        }
        function bnRemainder(a) {
            var r = nbi();
            this.divRemTo(a, null, r);
            return r
        }
        function bnDivideAndRemainder(a) {
            var q = nbi()
                , r = nbi();
            this.divRemTo(a, q, r);
            return new Array(q,r)
        }
        function bnpDMultiply(n) {
            this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
            ++this.t;
            this.clamp()
        }
        function bnpDAddOffset(n, w) {
            while (this.t <= w)
                this[this.t++] = 0;
            this[w] += n;
            while (this[w] >= this.DV) {
                this[w] -= this.DV;
                if (++w >= this.t)
                    this[this.t++] = 0;
                ++this[w]
            }
        }
        function NullExp() {}
        function nNop(x) {
            return x
        }
        function nMulTo(x, y, r) {
            x.multiplyTo(y, r)
        }
        function nSqrTo(x, r) {
            x.squareTo(r)
        }
        NullExp.prototype.convert = nNop;
        NullExp.prototype.revert = nNop;
        NullExp.prototype.mulTo = nMulTo;
        NullExp.prototype.sqrTo = nSqrTo;
        function bnPow(e) {
            return this.exp(e, new NullExp())
        }
        function bnpMultiplyLowerTo(a, n, r) {
            var i = Math.min(this.t + a.t, n);
            r.s = 0;
            r.t = i;
            while (i > 0)
                r[--i] = 0;
            var j;
            for (j = r.t - this.t; i < j; ++i)
                r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
            for (j = Math.min(a.t, n); i < j; ++i)
                this.am(0, a[i], r, i, 0, n - i);
            r.clamp()
        }
        function bnpMultiplyUpperTo(a, n, r) {
            --n;
            var i = r.t = this.t + a.t - n;
            r.s = 0;
            while (--i >= 0)
                r[i] = 0;
            for (i = Math.max(n - this.t, 0); i < a.t; ++i)
                r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
            r.clamp();
            r.drShiftTo(1, r)
        }
        function Barrett(m) {
            this.r2 = nbi();
            this.q3 = nbi();
            BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
            this.mu = this.r2.divide(m);
            this.m = m
        }
        function barrettConvert(x) {
            if (x.s < 0 || x.t > 2 * this.m.t)
                return x.mod(this.m);
            else if (x.compareTo(this.m) < 0)
                return x;
            else {
                var r = nbi();
                x.copyTo(r);
                this.reduce(r);
                return r
            }
        }
        function barrettRevert(x) {
            return x
        }
        function barrettReduce(x) {
            x.drShiftTo(this.m.t - 1, this.r2);
            if (x.t > this.m.t + 1) {
                x.t = this.m.t + 1;
                x.clamp()
            }
            this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
            this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
            while (x.compareTo(this.r2) < 0)
                x.dAddOffset(1, this.m.t + 1);
            x.subTo(this.r2, x);
            while (x.compareTo(this.m) >= 0)
                x.subTo(this.m, x)
        }
        function barrettSqrTo(x, r) {
            x.squareTo(r);
            this.reduce(r)
        }
        function barrettMulTo(x, y, r) {
            x.multiplyTo(y, r);
            this.reduce(r)
        }
        Barrett.prototype.convert = barrettConvert;
        Barrett.prototype.revert = barrettRevert;
        Barrett.prototype.reduce = barrettReduce;
        Barrett.prototype.mulTo = barrettMulTo;
        Barrett.prototype.sqrTo = barrettSqrTo;
        function bnModPow(e, m) {
            var i = e.bitLength(), k, r = nbv(1), z;
            if (i <= 0)
                return r;
            else if (i < 18)
                k = 1;
            else if (i < 48)
                k = 3;
            else if (i < 144)
                k = 4;
            else if (i < 768)
                k = 5;
            else
                k = 6;
            if (i < 8)
                z = new Classic(m);
            else if (m.isEven())
                z = new Barrett(m);
            else
                z = new Montgomery(m);
            var g = new Array()
                , n = 3
                , k1 = k - 1
                , km = (1 << k) - 1;
            g[1] = z.convert(this);
            if (k > 1) {
                var g2 = nbi();
                z.sqrTo(g[1], g2);
                while (n <= km) {
                    g[n] = nbi();
                    z.mulTo(g2, g[n - 2], g[n]);
                    n += 2
                }
            }
            var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
            i = nbits(e[j]) - 1;
            while (j >= 0) {
                if (i >= k1)
                    w = (e[j] >> (i - k1)) & km;
                else {
                    w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                    if (j > 0)
                        w |= e[j - 1] >> (this.DB + i - k1)
                }
                n = k;
                while ((w & 1) == 0) {
                    w >>= 1;
                    --n
                }
                if ((i -= n) < 0) {
                    i += this.DB;
                    --j
                }
                if (is1) {
                    g[w].copyTo(r);
                    is1 = false
                } else {
                    while (n > 1) {
                        z.sqrTo(r, r2);
                        z.sqrTo(r2, r);
                        n -= 2
                    }
                    if (n > 0)
                        z.sqrTo(r, r2);
                    else {
                        t = r;
                        r = r2;
                        r2 = t
                    }
                    z.mulTo(r2, g[w], r)
                }
                while (j >= 0 && (e[j] & (1 << i)) == 0) {
                    z.sqrTo(r, r2);
                    t = r;
                    r = r2;
                    r2 = t;
                    if (--i < 0) {
                        i = this.DB - 1;
                        --j
                    }
                }
            }
            return z.revert(r)
        }
        function bnGCD(a) {
            var x = (this.s < 0) ? this.negate() : this.clone();
            var y = (a.s < 0) ? a.negate() : a.clone();
            if (x.compareTo(y) < 0) {
                var t = x;
                x = y;
                y = t
            }
            var i = x.getLowestSetBit()
                , g = y.getLowestSetBit();
            if (g < 0)
                return x;
            if (i < g)
                g = i;
            if (g > 0) {
                x.rShiftTo(g, x);
                y.rShiftTo(g, y)
            }
            while (x.signum() > 0) {
                if ((i = x.getLowestSetBit()) > 0)
                    x.rShiftTo(i, x);
                if ((i = y.getLowestSetBit()) > 0)
                    y.rShiftTo(i, y);
                if (x.compareTo(y) >= 0) {
                    x.subTo(y, x);
                    x.rShiftTo(1, x)
                } else {
                    y.subTo(x, y);
                    y.rShiftTo(1, y)
                }
            }
            if (g > 0)
                y.lShiftTo(g, y);
            return y
        }
        function bnpModInt(n) {
            if (n <= 0)
                return 0;
            var d = this.DV % n
                , r = (this.s < 0) ? n - 1 : 0;
            if (this.t > 0)
                if (d == 0)
                    r = this[0] % n;
                else
                    for (var i = this.t - 1; i >= 0; --i)
                        r = (d * r + this[i]) % n;
            return r
        }
        function bnModInverse(m) {
            var ac = m.isEven();
            if ((this.isEven() && ac) || m.signum() == 0)
                return BigInteger.ZERO;
            var u = m.clone()
                , v = this.clone();
            var a = nbv(1)
                , b = nbv(0)
                , c = nbv(0)
                , d = nbv(1);
            while (u.signum() != 0) {
                while (u.isEven()) {
                    u.rShiftTo(1, u);
                    if (ac) {
                        if (!a.isEven() || !b.isEven()) {
                            a.addTo(this, a);
                            b.subTo(m, b)
                        }
                        a.rShiftTo(1, a)
                    } else if (!b.isEven())
                        b.subTo(m, b);
                    b.rShiftTo(1, b)
                }
                while (v.isEven()) {
                    v.rShiftTo(1, v);
                    if (ac) {
                        if (!c.isEven() || !d.isEven()) {
                            c.addTo(this, c);
                            d.subTo(m, d)
                        }
                        c.rShiftTo(1, c)
                    } else if (!d.isEven())
                        d.subTo(m, d);
                    d.rShiftTo(1, d)
                }
                if (u.compareTo(v) >= 0) {
                    u.subTo(v, u);
                    if (ac)
                        a.subTo(c, a);
                    b.subTo(d, b)
                } else {
                    v.subTo(u, v);
                    if (ac)
                        c.subTo(a, c);
                    d.subTo(b, d)
                }
            }
            if (v.compareTo(BigInteger.ONE) != 0)
                return BigInteger.ZERO;
            if (d.compareTo(m) >= 0)
                return d.subtract(m);
            if (d.signum() < 0)
                d.addTo(m, d);
            else
                return d;
            if (d.signum() < 0)
                return d.add(m);
            else
                return d
        }
        var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509];
        var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];
        function bnIsProbablePrime(t) {
            var i, x = this.abs();
            if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
                for (i = 0; i < lowprimes.length; ++i)
                    if (x[0] == lowprimes[i])
                        return true;
                return false
            }
            if (x.isEven())
                return false;
            i = 1;
            while (i < lowprimes.length) {
                var m = lowprimes[i]
                    , j = i + 1;
                while (j < lowprimes.length && m < lplim)
                    m *= lowprimes[j++];
                m = x.modInt(m);
                while (i < j)
                    if (m % lowprimes[i++] == 0)
                        return false
            }
            return x.millerRabin(t)
        }
        function bnpMillerRabin(t) {
            var n1 = this.subtract(BigInteger.ONE);
            var k = n1.getLowestSetBit();
            if (k <= 0)
                return false;
            var r = n1.shiftRight(k);
            t = (t + 1) >> 1;
            if (t > lowprimes.length)
                t = lowprimes.length;
            var a = nbi();
            for (var i = 0; i < t; ++i) {
                a.fromInt(lowprimes[i]);
                var y = a.modPow(r, this);
                if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
                    var j = 1;
                    while (j++ < k && y.compareTo(n1) != 0) {
                        y = y.modPowInt(2, this);
                        if (y.compareTo(BigInteger.ONE) == 0)
                            return false
                    }
                    if (y.compareTo(n1) != 0)
                        return false
                }
            }
            return true
        }
        BigInteger.prototype.chunkSize = bnpChunkSize;
        BigInteger.prototype.toRadix = bnpToRadix;
        BigInteger.prototype.fromRadix = bnpFromRadix;
        BigInteger.prototype.fromNumber = bnpFromNumber;
        BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
        BigInteger.prototype.changeBit = bnpChangeBit;
        BigInteger.prototype.addTo = bnpAddTo;
        BigInteger.prototype.dMultiply = bnpDMultiply;
        BigInteger.prototype.dAddOffset = bnpDAddOffset;
        BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
        BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
        BigInteger.prototype.modInt = bnpModInt;
        BigInteger.prototype.millerRabin = bnpMillerRabin;
        BigInteger.prototype.clone = bnClone;
        BigInteger.prototype.intValue = bnIntValue;
        BigInteger.prototype.byteValue = bnByteValue;
        BigInteger.prototype.shortValue = bnShortValue;
        BigInteger.prototype.signum = bnSigNum;
        BigInteger.prototype.toByteArray = bnToByteArray;
        BigInteger.prototype.equals = bnEquals;
        BigInteger.prototype.min = bnMin;
        BigInteger.prototype.max = bnMax;
        BigInteger.prototype.and = bnAnd;
        BigInteger.prototype.or = bnOr;
        BigInteger.prototype.xor = bnXor;
        BigInteger.prototype.andNot = bnAndNot;
        BigInteger.prototype.not = bnNot;
        BigInteger.prototype.shiftLeft = bnShiftLeft;
        BigInteger.prototype.shiftRight = bnShiftRight;
        BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
        BigInteger.prototype.bitCount = bnBitCount;
        BigInteger.prototype.testBit = bnTestBit;
        BigInteger.prototype.setBit = bnSetBit;
        BigInteger.prototype.clearBit = bnClearBit;
        BigInteger.prototype.flipBit = bnFlipBit;
        BigInteger.prototype.add = bnAdd;
        BigInteger.prototype.subtract = bnSubtract;
        BigInteger.prototype.multiply = bnMultiply;
        BigInteger.prototype.divide = bnDivide;
        BigInteger.prototype.remainder = bnRemainder;
        BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
        BigInteger.prototype.modPow = bnModPow;
        BigInteger.prototype.modInverse = bnModInverse;
        BigInteger.prototype.pow = bnPow;
        BigInteger.prototype.gcd = bnGCD;
        BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
        function Arcfour() {
            this.i = 0;
            this.j = 0;
            this.S = new Array()
        }
        function ARC4init(key) {
            var i, j, t;
            for (i = 0; i < 256; ++i)
                this.S[i] = i;
            j = 0;
            for (i = 0; i < 256; ++i) {
                j = (j + this.S[i] + key[i % key.length]) & 255;
                t = this.S[i];
                this.S[i] = this.S[j];
                this.S[j] = t
            }
            this.i = 0;
            this.j = 0
        }
        function ARC4next() {
            var t;
            this.i = (this.i + 1) & 255;
            this.j = (this.j + this.S[this.i]) & 255;
            t = this.S[this.i];
            this.S[this.i] = this.S[this.j];
            this.S[this.j] = t;
            return this.S[(t + this.S[this.i]) & 255]
        }
        Arcfour.prototype.init = ARC4init;
        Arcfour.prototype.next = ARC4next;
        function prng_newstate() {
            return new Arcfour()
        }
        var rng_psize = 256;
        function SecureRandom() {
            this.rng_state;
            this.rng_pool;
            this.rng_pptr;
            this.rng_seed_int = function(x) {
                this.rng_pool[this.rng_pptr++] ^= x & 255;
                this.rng_pool[this.rng_pptr++] ^= (x >> 8) & 255;
                this.rng_pool[this.rng_pptr++] ^= (x >> 16) & 255;
                this.rng_pool[this.rng_pptr++] ^= (x >> 24) & 255;
                if (this.rng_pptr >= rng_psize)
                    this.rng_pptr -= rng_psize
            }
            ;
            this.rng_seed_time = function() {
                this.rng_seed_int(new Date().getTime())
            }
            ;
            if (this.rng_pool == null) {
                this.rng_pool = new Array();
                this.rng_pptr = 0;
                var t;
                if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
                    var z = window.crypto.random(32);
                    for (t = 0; t < z.length; ++t)
                        this.rng_pool[this.rng_pptr++] = z.charCodeAt(t) & 255
                }
                while (this.rng_pptr < rng_psize) {
                    t = Math.floor(65536 * Math.random());
                    this.rng_pool[this.rng_pptr++] = t >>> 8;
                    this.rng_pool[this.rng_pptr++] = t & 255
                }
                this.rng_pptr = 0;
                this.rng_seed_time()
            }
            this.rng_get_byte = function() {
                if (this.rng_state == null) {
                    this.rng_seed_time();
                    this.rng_state = prng_newstate();
                    this.rng_state.init(this.rng_pool);
                    for (this.rng_pptr = 0; this.rng_pptr < this.rng_pool.length; ++this.rng_pptr)
                        this.rng_pool[this.rng_pptr] = 0;
                    this.rng_pptr = 0
                }
                return this.rng_state.next()
            }
            ;
            this.nextBytes = function(ba) {
                var i;
                for (i = 0; i < ba.length; ++i)
                    ba[i] = this.rng_get_byte()
            }
        }
        function parseBigInt(str, r) {
            return new BigInteger(str,r)
        }
        function linebrk(s, n) {
            var ret = "";
            var i = 0;
            while (i + n < s.length) {
                ret += s.substring(i, i + n) + "\n";
                i += n
            }
            return ret + s.substring(i, s.length)
        }
        function byte2Hex(b) {
            if (b < 0x10)
                return "0" + b.toString(16);
            else
                return b.toString(16)
        }
        function pkcs1unpad2(d, n) {
            var b = d.toByteArray();
            var i = 0;
            while (i < b.length && b[i] == 0)
                ++i;
            if (b.length - i != n - 1 || b[i] != 2)
                return null;
            ++i;
            while (b[i] != 0)
                if (++i >= b.length)
                    return null;
            var ret = "";
            while (++i < b.length)
                ret += String.fromCharCode(b[i]);
            return ret
        }
        function pkcs1pad2(s, n) {
            if (n < s.length + 11) {
                alert("Message too long for RSA");
                return null
            }
            var ba = new Array();
            var i = s.length - 1;
            while (i >= 0 && n > 0) {
                ba[--n] = s.charCodeAt(i--)
            }
            ;ba[--n] = 0;
            var rng = new SecureRandom();
            var x = new Array();
            while (n > 2) {
                x[0] = 0;
                while (x[0] == 0)
                    rng.nextBytes(x);
                ba[--n] = x[0]
            }
            ba[--n] = 2;
            ba[--n] = 0;
            return new BigInteger(ba)
        }
        pidCrypt.RSA = function() {
            this.n = null;
            this.e = 0;
            this.d = null;
            this.p = null;
            this.q = null;
            this.dmp1 = null;
            this.dmq1 = null;
            this.coeff = null
        }
        ;
        pidCrypt.RSA.prototype.doPrivate = function(x) {
            if (this.p == null || this.q == null)
                return x.modPow(this.d, this.n);
            var xp = x.mod(this.p).modPow(this.dmp1, this.p);
            var xq = x.mod(this.q).modPow(this.dmq1, this.q);
            while (xp.compareTo(xq) < 0)
                xp = xp.add(this.p);
            return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq)
        }
        ;
        pidCrypt.RSA.prototype.setPublic = function(N, E, radix) {
            if (typeof (radix) == 'undefined')
                radix = 16;
            if (N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N, radix);
                this.e = parseInt(E, radix)
            } else
                alert("Invalid RSA public key")
        }
        ;
        pidCrypt.RSA.prototype.doPublic = function(x) {
            return x.modPowInt(this.e, this.n)
        }
        ;
        pidCrypt.RSA.prototype.encryptRaw = function(text) {
            var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
            if (m == null)
                return null;
            var c = this.doPublic(m);
            if (c == null)
                return null;
            var h = c.toString(16);
            if ((h.length & 1) == 0)
                return h;
            else
                return "0" + h
        }
        ;
        pidCrypt.RSA.prototype.encrypt = function(text) {
            return this.encryptRaw(text)
        }
        ;
        pidCrypt.RSA.prototype.decryptRaw = function(ctext) {
            var c = parseBigInt(ctext, 16);
            var m = this.doPrivate(c);
            if (m == null)
                return null;
            return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3)
        }
        ;
        pidCrypt.RSA.prototype.decrypt = function(ctext) {
            var str = this.decryptRaw(ctext);
            str = (str) ? pidCryptUtil.decodeBase64(str) : "";
            return str
        }
        ;
        pidCrypt.RSA.prototype.setPrivate = function(N, E, D, radix) {
            if (typeof (radix) == 'undefined')
                radix = 16;
            if (N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N, radix);
                this.e = parseInt(E, radix);
                this.d = parseBigInt(D, radix)
            } else
                alert("Invalid RSA private key")
        }
        ;
        pidCrypt.RSA.prototype.setPrivateEx = function(N, E, D, P, Q, DP, DQ, C, radix) {
            if (typeof (radix) == 'undefined')
                radix = 16;
            if (N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N, radix);
                this.e = parseInt(E, radix);
                this.d = parseBigInt(D, radix);
                this.p = parseBigInt(P, radix);
                this.q = parseBigInt(Q, radix);
                this.dmp1 = parseBigInt(DP, radix);
                this.dmq1 = parseBigInt(DQ, radix);
                this.coeff = parseBigInt(C, radix)
            } else
                alert("Invalid RSA private key")
        }
        ;
        pidCrypt.RSA.prototype.generate = function(B, E) {
            var rng = new SecureRandom();
            var qs = B >> 1;
            this.e = parseInt(E, 16);
            var ee = new BigInteger(E,16);
            for (; ; ) {
                for (; ; ) {
                    this.p = new BigInteger(B - qs,1,rng);
                    if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10))
                        break
                }
                for (; ; ) {
                    this.q = new BigInteger(qs,1,rng);
                    if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10))
                        break
                }
                if (this.p.compareTo(this.q) <= 0) {
                    var t = this.p;
                    this.p = this.q;
                    this.q = t
                }
                var p1 = this.p.subtract(BigInteger.ONE);
                var q1 = this.q.subtract(BigInteger.ONE);
                var phi = p1.multiply(q1);
                if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
                    this.n = this.p.multiply(this.q);
                    this.d = ee.modInverse(phi);
                    this.dmp1 = this.d.mod(p1);
                    this.dmq1 = this.d.mod(q1);
                    this.coeff = this.q.modInverse(this.p);
                    break
                }
            }
        }
        ;
        pidCrypt.RSA.prototype.getASNData = function(tree) {
            var params = {};
            var data = [];
            var p = 0;
            if (tree.value && tree.type == 'INTEGER')
                data[p++] = tree.value;
            if (tree.sub)
                for (var i = 0; i < tree.sub.length; i++)
                    data = data.concat(this.getASNData(tree.sub[i]));
            return data
        }
        ;
        pidCrypt.RSA.prototype.setKeyFromASN = function(key, asntree) {
            var keys = ['N', 'E', 'D', 'P', 'Q', 'DP', 'DQ', 'C'];
            var params = {};
            var asnData = this.getASNData(asntree);
            switch (key) {
                case 'Public':
                case 'public':
                    for (var i = 0; i < asnData.length; i++)
                        params[keys[i]] = asnData[i].toLowerCase();
                    this.setPublic(params.N, params.E, 16);
                    break;
                case 'Private':
                case 'private':
                    for (var i = 1; i < asnData.length; i++)
                        params[keys[i - 1]] = asnData[i].toLowerCase();
                    this.setPrivateEx(params.N, params.E, params.D, params.P, params.Q, params.DP, params.DQ, params.C, 16);
                    break
            }
        }
        ;
        pidCrypt.RSA.prototype.setPublicKeyFromASN = function(asntree) {
            this.setKeyFromASN('public', asntree)
        }
        ;
        pidCrypt.RSA.prototype.setPrivateKeyFromASN = function(asntree) {
            this.setKeyFromASN('private', asntree)
        }
        ;
        pidCrypt.RSA.prototype.getParameters = function() {
            var params = {};
            if (this.n != null)
                params.n = this.n;
            params.e = this.e;
            if (this.d != null)
                params.d = this.d;
            if (this.p != null)
                params.p = this.p;
            if (this.q != null)
                params.q = this.q;
            if (this.dmp1 != null)
                params.dmp1 = this.dmp1;
            if (this.dmq1 != null)
                params.dmq1 = this.dmq1;
            if (this.coeff != null)
                params.c = this.coeff;
            return params
        }
        ;
        var secure = {
            n: 'yevTQ5C8exDUo/c0y0Lrxp+quYD9vxjkKFAgdqV0PtLefJ4FEB4VeTTGDfqaWVgQXeQeyCp0yjCd8EGVUd/77z+Z/HlBpaavHwsE77Rjf3r9AC+aSN+ZZC4uoZL0bYDiDgYcG32CPLdVPP8zbKxa/BSbUb1PhxEot/fMTo+rLrU=',
            e: 'AQAB',
            encrypt: function(plain) {
                var n = pidCryptUtil.decodeBase64(this.n)
                    , e = pidCryptUtil.decodeBase64(this.e)
                    , rsa = new pidCrypt.RSA();
                rsa.setPublic(pidCryptUtil.convertToHex(n), pidCryptUtil.convertToHex(e));
                return pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(rsa.encrypt(plain)))
            }
        }




function encrypt(plain){
     var    n= 'yevTQ5C8exDUo/c0y0Lrxp+quYD9vxjkKFAgdqV0PtLefJ4FEB4VeTTGDfqaWVgQXeQeyCp0yjCd8EGVUd/77z+Z/HlBpaavHwsE77Rjf3r9AC+aSN+ZZC4uoZL0bYDiDgYcG32CPLdVPP8zbKxa/BSbUb1PhxEot/fMTo+rLrU=';
     var    e='AQAB';
    var n = pidCryptUtil.decodeBase64(n)
        , e = pidCryptUtil.decodeBase64(e)
        , rsa = new pidCrypt.RSA();
    rsa.setPublic(pidCryptUtil.convertToHex(n), pidCryptUtil.convertToHex(e));
    return pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(rsa.encrypt(plain)))
}

function get_pwd(pwd) {
    timestamp = new Date().getTime().toString().substr(0,10)
    new_pwd = encrypt(timestamp + '|' + pwd);
    return new_pwd

}

console.log(get_pwd('123456789'))
//Gk0OSNaKMRF7RBjPycsY3OU7Bf0ZUhpZE4lNjfslZuIulfazKzYY+Ft6ROxsRFjpYTDtWd4XzbZAZoYDjX1i5leoXryjFvUebmlu7s7nYjMDNwfOqaPwItP501z5mdQ17Zzy2nS01szh392Qca+eAkO2+xUlohanC+boXUn5GiA=
//D3/6BGhMa6j3qT3mZNMhoeuA0qXsZxgeBrzGx7UUq8sC8CkPNFj8JFyZYEAuohZz85uhRIMLAbg8opPmbJZq8sc7QiRX7ybrAnPEMBWPwtDpZkGEGj1m0Ehnl9XjN3XRRyPr1HlG+TBM3i+61g6nIWHXSKLRGqHPozYZZeNeC7k=
//ca+cY8uPTcc+0XSjIYMhar/bn64XqwCzifDagQ6SQW8CfSykBAh9SV2N4BiWPme+hy5NpXpYEexxjulgNliVD0scw7FOQZsk3xihGSB/0ztb5Oiyyyua0Y14p8E67L2UfSu14vgQO7vplPGlor2/PfafllAkiSsOoiy6Jvwgxqk=