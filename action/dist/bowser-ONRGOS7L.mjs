import { createRequire } from 'module';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/bowser/src/bowser.js
init_esm_shims();

// node_modules/bowser/src/parser.js
init_esm_shims();

// node_modules/bowser/src/parser-browsers.js
init_esm_shims();

// node_modules/bowser/src/utils.js
init_esm_shims();

// node_modules/bowser/src/constants.js
init_esm_shims();
var BROWSER_ALIASES_MAP = {
  AmazonBot: "amazonbot",
  "Amazon Silk": "amazon_silk",
  "Android Browser": "android",
  BaiduSpider: "baiduspider",
  Bada: "bada",
  BingCrawler: "bingcrawler",
  Brave: "brave",
  BlackBerry: "blackberry",
  "ChatGPT-User": "chatgpt_user",
  Chrome: "chrome",
  ClaudeBot: "claudebot",
  Chromium: "chromium",
  Diffbot: "diffbot",
  DuckDuckBot: "duckduckbot",
  DuckDuckGo: "duckduckgo",
  Electron: "electron",
  Epiphany: "epiphany",
  FacebookExternalHit: "facebookexternalhit",
  Firefox: "firefox",
  Focus: "focus",
  Generic: "generic",
  "Google Search": "google_search",
  Googlebot: "googlebot",
  GPTBot: "gptbot",
  "Internet Explorer": "ie",
  InternetArchiveCrawler: "internetarchivecrawler",
  "K-Meleon": "k_meleon",
  LibreWolf: "librewolf",
  Linespider: "linespider",
  Maxthon: "maxthon",
  "Meta-ExternalAds": "meta_externalads",
  "Meta-ExternalAgent": "meta_externalagent",
  "Meta-ExternalFetcher": "meta_externalfetcher",
  "Meta-WebIndexer": "meta_webindexer",
  "Microsoft Edge": "edge",
  "MZ Browser": "mz",
  "NAVER Whale Browser": "naver",
  "OAI-SearchBot": "oai_searchbot",
  Omgilibot: "omgilibot",
  Opera: "opera",
  "Opera Coast": "opera_coast",
  "Pale Moon": "pale_moon",
  PerplexityBot: "perplexitybot",
  "Perplexity-User": "perplexity_user",
  PhantomJS: "phantomjs",
  PingdomBot: "pingdombot",
  Puffin: "puffin",
  QQ: "qq",
  QQLite: "qqlite",
  QupZilla: "qupzilla",
  Roku: "roku",
  Safari: "safari",
  Sailfish: "sailfish",
  "Samsung Internet for Android": "samsung_internet",
  SlackBot: "slackbot",
  SeaMonkey: "seamonkey",
  Sleipnir: "sleipnir",
  "Sogou Browser": "sogou",
  Swing: "swing",
  Tizen: "tizen",
  "UC Browser": "uc",
  Vivaldi: "vivaldi",
  "WebOS Browser": "webos",
  WeChat: "wechat",
  YahooSlurp: "yahooslurp",
  "Yandex Browser": "yandex",
  YandexBot: "yandexbot",
  YouBot: "youbot"
};
var BROWSER_MAP = {
  amazonbot: "AmazonBot",
  amazon_silk: "Amazon Silk",
  android: "Android Browser",
  baiduspider: "BaiduSpider",
  bada: "Bada",
  bingcrawler: "BingCrawler",
  blackberry: "BlackBerry",
  brave: "Brave",
  chatgpt_user: "ChatGPT-User",
  chrome: "Chrome",
  claudebot: "ClaudeBot",
  chromium: "Chromium",
  diffbot: "Diffbot",
  duckduckbot: "DuckDuckBot",
  duckduckgo: "DuckDuckGo",
  edge: "Microsoft Edge",
  electron: "Electron",
  epiphany: "Epiphany",
  facebookexternalhit: "FacebookExternalHit",
  firefox: "Firefox",
  focus: "Focus",
  generic: "Generic",
  google_search: "Google Search",
  googlebot: "Googlebot",
  gptbot: "GPTBot",
  ie: "Internet Explorer",
  internetarchivecrawler: "InternetArchiveCrawler",
  k_meleon: "K-Meleon",
  librewolf: "LibreWolf",
  linespider: "Linespider",
  maxthon: "Maxthon",
  meta_externalads: "Meta-ExternalAds",
  meta_externalagent: "Meta-ExternalAgent",
  meta_externalfetcher: "Meta-ExternalFetcher",
  meta_webindexer: "Meta-WebIndexer",
  mz: "MZ Browser",
  naver: "NAVER Whale Browser",
  oai_searchbot: "OAI-SearchBot",
  omgilibot: "Omgilibot",
  opera: "Opera",
  opera_coast: "Opera Coast",
  pale_moon: "Pale Moon",
  perplexitybot: "PerplexityBot",
  perplexity_user: "Perplexity-User",
  phantomjs: "PhantomJS",
  pingdombot: "PingdomBot",
  puffin: "Puffin",
  qq: "QQ Browser",
  qqlite: "QQ Browser Lite",
  qupzilla: "QupZilla",
  roku: "Roku",
  safari: "Safari",
  sailfish: "Sailfish",
  samsung_internet: "Samsung Internet for Android",
  seamonkey: "SeaMonkey",
  slackbot: "SlackBot",
  sleipnir: "Sleipnir",
  sogou: "Sogou Browser",
  swing: "Swing",
  tizen: "Tizen",
  uc: "UC Browser",
  vivaldi: "Vivaldi",
  webos: "WebOS Browser",
  wechat: "WeChat",
  yahooslurp: "YahooSlurp",
  yandex: "Yandex Browser",
  yandexbot: "YandexBot",
  youbot: "YouBot"
};
var PLATFORMS_MAP = {
  bot: "bot",
  desktop: "desktop",
  mobile: "mobile",
  tablet: "tablet",
  tv: "tv"
};
var OS_MAP = {
  Android: "Android",
  Bada: "Bada",
  BlackBerry: "BlackBerry",
  ChromeOS: "Chrome OS",
  HarmonyOS: "HarmonyOS",
  iOS: "iOS",
  Linux: "Linux",
  MacOS: "macOS",
  PlayStation4: "PlayStation 4",
  Roku: "Roku",
  Tizen: "Tizen",
  WebOS: "WebOS",
  Windows: "Windows",
  WindowsPhone: "Windows Phone"
};
var ENGINE_MAP = {
  Blink: "Blink",
  EdgeHTML: "EdgeHTML",
  Gecko: "Gecko",
  Presto: "Presto",
  Trident: "Trident",
  WebKit: "WebKit"
};

// node_modules/bowser/src/utils.js
var Utils = class _Utils {
  /**
   * Get first matched item for a string
   * @param {RegExp} regexp
   * @param {String} ua
   * @return {Array|{index: number, input: string}|*|boolean|string}
   */
  static getFirstMatch(regexp, ua) {
    const match = ua.match(regexp);
    return match && match.length > 0 && match[1] || "";
  }
  /**
   * Get second matched item for a string
   * @param regexp
   * @param {String} ua
   * @return {Array|{index: number, input: string}|*|boolean|string}
   */
  static getSecondMatch(regexp, ua) {
    const match = ua.match(regexp);
    return match && match.length > 1 && match[2] || "";
  }
  /**
   * Match a regexp and return a constant or undefined
   * @param {RegExp} regexp
   * @param {String} ua
   * @param {*} _const Any const that will be returned if regexp matches the string
   * @return {*}
   */
  static matchAndReturnConst(regexp, ua, _const) {
    if (regexp.test(ua)) {
      return _const;
    }
    return void 0;
  }
  static getWindowsVersionName(version) {
    switch (version) {
      case "NT":
        return "NT";
      case "XP":
        return "XP";
      case "NT 5.0":
        return "2000";
      case "NT 5.1":
        return "XP";
      case "NT 5.2":
        return "2003";
      case "NT 6.0":
        return "Vista";
      case "NT 6.1":
        return "7";
      case "NT 6.2":
        return "8";
      case "NT 6.3":
        return "8.1";
      case "NT 10.0":
        return "10";
      default:
        return void 0;
    }
  }
  /**
   * Get macOS version name
   *    10.5 - Leopard
   *    10.6 - Snow Leopard
   *    10.7 - Lion
   *    10.8 - Mountain Lion
   *    10.9 - Mavericks
   *    10.10 - Yosemite
   *    10.11 - El Capitan
   *    10.12 - Sierra
   *    10.13 - High Sierra
   *    10.14 - Mojave
   *    10.15 - Catalina
   *    11 - Big Sur
   *    12 - Monterey
   *    13 - Ventura
   *    14 - Sonoma
   *    15 - Sequoia
   *
   * @example
   *   getMacOSVersionName("10.14") // 'Mojave'
   *
   * @param  {string} version
   * @return {string} versionName
   */
  static getMacOSVersionName(version) {
    const v = version.split(".").splice(0, 2).map((s) => parseInt(s, 10) || 0);
    v.push(0);
    const major = v[0];
    const minor = v[1];
    if (major === 10) {
      switch (minor) {
        case 5:
          return "Leopard";
        case 6:
          return "Snow Leopard";
        case 7:
          return "Lion";
        case 8:
          return "Mountain Lion";
        case 9:
          return "Mavericks";
        case 10:
          return "Yosemite";
        case 11:
          return "El Capitan";
        case 12:
          return "Sierra";
        case 13:
          return "High Sierra";
        case 14:
          return "Mojave";
        case 15:
          return "Catalina";
        default:
          return void 0;
      }
    }
    switch (major) {
      case 11:
        return "Big Sur";
      case 12:
        return "Monterey";
      case 13:
        return "Ventura";
      case 14:
        return "Sonoma";
      case 15:
        return "Sequoia";
      default:
        return void 0;
    }
  }
  /**
   * Get Android version name
   *    1.5 - Cupcake
   *    1.6 - Donut
   *    2.0 - Eclair
   *    2.1 - Eclair
   *    2.2 - Froyo
   *    2.x - Gingerbread
   *    3.x - Honeycomb
   *    4.0 - Ice Cream Sandwich
   *    4.1 - Jelly Bean
   *    4.4 - KitKat
   *    5.x - Lollipop
   *    6.x - Marshmallow
   *    7.x - Nougat
   *    8.x - Oreo
   *    9.x - Pie
   *
   * @example
   *   getAndroidVersionName("7.0") // 'Nougat'
   *
   * @param  {string} version
   * @return {string} versionName
   */
  static getAndroidVersionName(version) {
    const v = version.split(".").splice(0, 2).map((s) => parseInt(s, 10) || 0);
    v.push(0);
    if (v[0] === 1 && v[1] < 5) return void 0;
    if (v[0] === 1 && v[1] < 6) return "Cupcake";
    if (v[0] === 1 && v[1] >= 6) return "Donut";
    if (v[0] === 2 && v[1] < 2) return "Eclair";
    if (v[0] === 2 && v[1] === 2) return "Froyo";
    if (v[0] === 2 && v[1] > 2) return "Gingerbread";
    if (v[0] === 3) return "Honeycomb";
    if (v[0] === 4 && v[1] < 1) return "Ice Cream Sandwich";
    if (v[0] === 4 && v[1] < 4) return "Jelly Bean";
    if (v[0] === 4 && v[1] >= 4) return "KitKat";
    if (v[0] === 5) return "Lollipop";
    if (v[0] === 6) return "Marshmallow";
    if (v[0] === 7) return "Nougat";
    if (v[0] === 8) return "Oreo";
    if (v[0] === 9) return "Pie";
    return void 0;
  }
  /**
   * Get version precisions count
   *
   * @example
   *   getVersionPrecision("1.10.3") // 3
   *
   * @param  {string} version
   * @return {number}
   */
  static getVersionPrecision(version) {
    return version.split(".").length;
  }
  /**
   * Calculate browser version weight
   *
   * @example
   *   compareVersions('1.10.2.1',  '1.8.2.1.90')    // 1
   *   compareVersions('1.010.2.1', '1.09.2.1.90');  // 1
   *   compareVersions('1.10.2.1',  '1.10.2.1');     // 0
   *   compareVersions('1.10.2.1',  '1.0800.2');     // -1
   *   compareVersions('1.10.2.1',  '1.10',  true);  // 0
   *
   * @param {String} versionA versions versions to compare
   * @param {String} versionB versions versions to compare
   * @param {boolean} [isLoose] enable loose comparison
   * @return {Number} comparison result: -1 when versionA is lower,
   * 1 when versionA is bigger, 0 when both equal
   */
  /* eslint consistent-return: 1 */
  static compareVersions(versionA, versionB, isLoose = false) {
    const versionAPrecision = _Utils.getVersionPrecision(versionA);
    const versionBPrecision = _Utils.getVersionPrecision(versionB);
    let precision = Math.max(versionAPrecision, versionBPrecision);
    let lastPrecision = 0;
    const chunks = _Utils.map([versionA, versionB], (version) => {
      const delta = precision - _Utils.getVersionPrecision(version);
      const _version = version + new Array(delta + 1).join(".0");
      return _Utils.map(_version.split("."), (chunk) => new Array(20 - chunk.length).join("0") + chunk).reverse();
    });
    if (isLoose) {
      lastPrecision = precision - Math.min(versionAPrecision, versionBPrecision);
    }
    precision -= 1;
    while (precision >= lastPrecision) {
      if (chunks[0][precision] > chunks[1][precision]) {
        return 1;
      }
      if (chunks[0][precision] === chunks[1][precision]) {
        if (precision === lastPrecision) {
          return 0;
        }
        precision -= 1;
      } else if (chunks[0][precision] < chunks[1][precision]) {
        return -1;
      }
    }
    return void 0;
  }
  /**
   * Array::map polyfill
   *
   * @param  {Array} arr
   * @param  {Function} iterator
   * @return {Array}
   */
  static map(arr, iterator) {
    const result = [];
    let i;
    if (Array.prototype.map) {
      return Array.prototype.map.call(arr, iterator);
    }
    for (i = 0; i < arr.length; i += 1) {
      result.push(iterator(arr[i]));
    }
    return result;
  }
  /**
   * Array::find polyfill
   *
   * @param  {Array} arr
   * @param  {Function} predicate
   * @return {Array}
   */
  static find(arr, predicate) {
    let i;
    let l;
    if (Array.prototype.find) {
      return Array.prototype.find.call(arr, predicate);
    }
    for (i = 0, l = arr.length; i < l; i += 1) {
      const value = arr[i];
      if (predicate(value, i)) {
        return value;
      }
    }
    return void 0;
  }
  /**
   * Object::assign polyfill
   *
   * @param  {Object} obj
   * @param  {Object} ...objs
   * @return {Object}
   */
  static assign(obj, ...assigners) {
    const result = obj;
    let i;
    let l;
    if (Object.assign) {
      return Object.assign(obj, ...assigners);
    }
    for (i = 0, l = assigners.length; i < l; i += 1) {
      const assigner = assigners[i];
      if (typeof assigner === "object" && assigner !== null) {
        const keys = Object.keys(assigner);
        keys.forEach((key) => {
          result[key] = assigner[key];
        });
      }
    }
    return obj;
  }
  /**
   * Get short version/alias for a browser name
   *
   * @example
   *   getBrowserAlias('Microsoft Edge') // edge
   *
   * @param  {string} browserName
   * @return {string}
   */
  static getBrowserAlias(browserName) {
    return BROWSER_ALIASES_MAP[browserName];
  }
  /**
   * Get browser name for a short version/alias
   *
   * @example
   *   getBrowserTypeByAlias('edge') // Microsoft Edge
   *
   * @param  {string} browserAlias
   * @return {string}
   */
  static getBrowserTypeByAlias(browserAlias) {
    return BROWSER_MAP[browserAlias] || "";
  }
};

// node_modules/bowser/src/parser-browsers.js
var commonVersionIdentifier = /version\/(\d+(\.?_?\d+)+)/i;
var browsersList = [
  /* GPTBot */
  {
    test: [/gptbot/i],
    describe(ua) {
      const browser = {
        name: "GPTBot"
      };
      const version = Utils.getFirstMatch(/gptbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* ChatGPT-User */
  {
    test: [/chatgpt-user/i],
    describe(ua) {
      const browser = {
        name: "ChatGPT-User"
      };
      const version = Utils.getFirstMatch(/chatgpt-user\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* OAI-SearchBot */
  {
    test: [/oai-searchbot/i],
    describe(ua) {
      const browser = {
        name: "OAI-SearchBot"
      };
      const version = Utils.getFirstMatch(/oai-searchbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* ClaudeBot */
  {
    test: [/claudebot/i, /claude-web/i, /claude-user/i, /claude-searchbot/i],
    describe(ua) {
      const browser = {
        name: "ClaudeBot"
      };
      const version = Utils.getFirstMatch(/(?:claudebot|claude-web|claude-user|claude-searchbot)\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Omgilibot */
  {
    test: [/omgilibot/i, /webzio-extended/i],
    describe(ua) {
      const browser = {
        name: "Omgilibot"
      };
      const version = Utils.getFirstMatch(/(?:omgilibot|webzio-extended)\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Diffbot */
  {
    test: [/diffbot/i],
    describe(ua) {
      const browser = {
        name: "Diffbot"
      };
      const version = Utils.getFirstMatch(/diffbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* PerplexityBot */
  {
    test: [/perplexitybot/i],
    describe(ua) {
      const browser = {
        name: "PerplexityBot"
      };
      const version = Utils.getFirstMatch(/perplexitybot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Perplexity-User */
  {
    test: [/perplexity-user/i],
    describe(ua) {
      const browser = {
        name: "Perplexity-User"
      };
      const version = Utils.getFirstMatch(/perplexity-user\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* YouBot */
  {
    test: [/youbot/i],
    describe(ua) {
      const browser = {
        name: "YouBot"
      };
      const version = Utils.getFirstMatch(/youbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Meta-WebIndexer */
  {
    test: [/meta-webindexer/i],
    describe(ua) {
      const browser = {
        name: "Meta-WebIndexer"
      };
      const version = Utils.getFirstMatch(/meta-webindexer\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Meta-ExternalAds */
  {
    test: [/meta-externalads/i],
    describe(ua) {
      const browser = {
        name: "Meta-ExternalAds"
      };
      const version = Utils.getFirstMatch(/meta-externalads\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Meta-ExternalAgent */
  {
    test: [/meta-externalagent/i],
    describe(ua) {
      const browser = {
        name: "Meta-ExternalAgent"
      };
      const version = Utils.getFirstMatch(/meta-externalagent\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Meta-ExternalFetcher */
  {
    test: [/meta-externalfetcher/i],
    describe(ua) {
      const browser = {
        name: "Meta-ExternalFetcher"
      };
      const version = Utils.getFirstMatch(/meta-externalfetcher\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Googlebot */
  {
    test: [/googlebot/i],
    describe(ua) {
      const browser = {
        name: "Googlebot"
      };
      const version = Utils.getFirstMatch(/googlebot\/(\d+(\.\d+))/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Linespider */
  {
    test: [/linespider/i],
    describe(ua) {
      const browser = {
        name: "Linespider"
      };
      const version = Utils.getFirstMatch(/(?:linespider)(?:-[-\w]+)?[\s/](\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* AmazonBot */
  {
    test: [/amazonbot/i],
    describe(ua) {
      const browser = {
        name: "AmazonBot"
      };
      const version = Utils.getFirstMatch(/amazonbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* BingCrawler */
  {
    test: [/bingbot/i],
    describe(ua) {
      const browser = {
        name: "BingCrawler"
      };
      const version = Utils.getFirstMatch(/bingbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* BaiduSpider */
  {
    test: [/baiduspider/i],
    describe(ua) {
      const browser = {
        name: "BaiduSpider"
      };
      const version = Utils.getFirstMatch(/baiduspider\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* DuckDuckBot */
  {
    test: [/duckduckbot/i],
    describe(ua) {
      const browser = {
        name: "DuckDuckBot"
      };
      const version = Utils.getFirstMatch(/duckduckbot\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* InternetArchiveCrawler */
  {
    test: [/ia_archiver/i],
    describe(ua) {
      const browser = {
        name: "InternetArchiveCrawler"
      };
      const version = Utils.getFirstMatch(/ia_archiver\/(\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* FacebookExternalHit */
  {
    test: [/facebookexternalhit/i, /facebookcatalog/i],
    describe() {
      return {
        name: "FacebookExternalHit"
      };
    }
  },
  /* SlackBot */
  {
    test: [/slackbot/i, /slack-imgProxy/i],
    describe(ua) {
      const browser = {
        name: "SlackBot"
      };
      const version = Utils.getFirstMatch(/(?:slackbot|slack-imgproxy)(?:-[-\w]+)?[\s/](\d+(\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* YahooSlurp */
  {
    test: [/yahoo!?[\s/]*slurp/i],
    describe() {
      return {
        name: "YahooSlurp"
      };
    }
  },
  /* YandexBot */
  {
    test: [/yandexbot/i, /yandexmobilebot/i],
    describe() {
      return {
        name: "YandexBot"
      };
    }
  },
  /* PingdomBot */
  {
    test: [/pingdom/i],
    describe() {
      return {
        name: "PingdomBot"
      };
    }
  },
  /* Opera < 13.0 */
  {
    test: [/opera/i],
    describe(ua) {
      const browser = {
        name: "Opera"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:opera)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Opera > 13.0 */
  {
    test: [/opr\/|opios/i],
    describe(ua) {
      const browser = {
        name: "Opera"
      };
      const version = Utils.getFirstMatch(/(?:opr|opios)[\s/](\S+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/SamsungBrowser/i],
    describe(ua) {
      const browser = {
        name: "Samsung Internet for Android"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:SamsungBrowser)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/Whale/i],
    describe(ua) {
      const browser = {
        name: "NAVER Whale Browser"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:whale)[\s/](\d+(?:\.\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/PaleMoon/i],
    describe(ua) {
      const browser = {
        name: "Pale Moon"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:PaleMoon)[\s/](\d+(?:\.\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/MZBrowser/i],
    describe(ua) {
      const browser = {
        name: "MZ Browser"
      };
      const version = Utils.getFirstMatch(/(?:MZBrowser)[\s/](\d+(?:\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/focus/i],
    describe(ua) {
      const browser = {
        name: "Focus"
      };
      const version = Utils.getFirstMatch(/(?:focus)[\s/](\d+(?:\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/swing/i],
    describe(ua) {
      const browser = {
        name: "Swing"
      };
      const version = Utils.getFirstMatch(/(?:swing)[\s/](\d+(?:\.\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/coast/i],
    describe(ua) {
      const browser = {
        name: "Opera Coast"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:coast)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/opt\/\d+(?:.?_?\d+)+/i],
    describe(ua) {
      const browser = {
        name: "Opera Touch"
      };
      const version = Utils.getFirstMatch(/(?:opt)[\s/](\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/yabrowser/i],
    describe(ua) {
      const browser = {
        name: "Yandex Browser"
      };
      const version = Utils.getFirstMatch(/(?:yabrowser)[\s/](\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/ucbrowser/i],
    describe(ua) {
      const browser = {
        name: "UC Browser"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:ucbrowser)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/Maxthon|mxios/i],
    describe(ua) {
      const browser = {
        name: "Maxthon"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:Maxthon|mxios)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/epiphany/i],
    describe(ua) {
      const browser = {
        name: "Epiphany"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:epiphany)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/puffin/i],
    describe(ua) {
      const browser = {
        name: "Puffin"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:puffin)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/sleipnir/i],
    describe(ua) {
      const browser = {
        name: "Sleipnir"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:sleipnir)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/k-meleon/i],
    describe(ua) {
      const browser = {
        name: "K-Meleon"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/(?:k-meleon)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/micromessenger/i],
    describe(ua) {
      const browser = {
        name: "WeChat"
      };
      const version = Utils.getFirstMatch(/(?:micromessenger)[\s/](\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/qqbrowser/i],
    describe(ua) {
      const browser = {
        name: /qqbrowserlite/i.test(ua) ? "QQ Browser Lite" : "QQ Browser"
      };
      const version = Utils.getFirstMatch(/(?:qqbrowserlite|qqbrowser)[/](\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/msie|trident/i],
    describe(ua) {
      const browser = {
        name: "Internet Explorer"
      };
      const version = Utils.getFirstMatch(/(?:msie |rv:)(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/\sedg\//i],
    describe(ua) {
      const browser = {
        name: "Microsoft Edge"
      };
      const version = Utils.getFirstMatch(/\sedg\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/edg([ea]|ios)/i],
    describe(ua) {
      const browser = {
        name: "Microsoft Edge"
      };
      const version = Utils.getSecondMatch(/edg([ea]|ios)\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/vivaldi/i],
    describe(ua) {
      const browser = {
        name: "Vivaldi"
      };
      const version = Utils.getFirstMatch(/vivaldi\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/seamonkey/i],
    describe(ua) {
      const browser = {
        name: "SeaMonkey"
      };
      const version = Utils.getFirstMatch(/seamonkey\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/sailfish/i],
    describe(ua) {
      const browser = {
        name: "Sailfish"
      };
      const version = Utils.getFirstMatch(/sailfish\s?browser\/(\d+(\.\d+)?)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/silk/i],
    describe(ua) {
      const browser = {
        name: "Amazon Silk"
      };
      const version = Utils.getFirstMatch(/silk\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/phantom/i],
    describe(ua) {
      const browser = {
        name: "PhantomJS"
      };
      const version = Utils.getFirstMatch(/phantomjs\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/slimerjs/i],
    describe(ua) {
      const browser = {
        name: "SlimerJS"
      };
      const version = Utils.getFirstMatch(/slimerjs\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/blackberry|\bbb\d+/i, /rim\stablet/i],
    describe(ua) {
      const browser = {
        name: "BlackBerry"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/blackberry[\d]+\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/(web|hpw)[o0]s/i],
    describe(ua) {
      const browser = {
        name: "WebOS Browser"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua) || Utils.getFirstMatch(/w(?:eb)?[o0]sbrowser\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/bada/i],
    describe(ua) {
      const browser = {
        name: "Bada"
      };
      const version = Utils.getFirstMatch(/dolfin\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/tizen/i],
    describe(ua) {
      const browser = {
        name: "Tizen"
      };
      const version = Utils.getFirstMatch(/(?:tizen\s?)?browser\/(\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/qupzilla/i],
    describe(ua) {
      const browser = {
        name: "QupZilla"
      };
      const version = Utils.getFirstMatch(/(?:qupzilla)[\s/](\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/librewolf/i],
    describe(ua) {
      const browser = {
        name: "LibreWolf"
      };
      const version = Utils.getFirstMatch(/(?:librewolf)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/firefox|iceweasel|fxios/i],
    describe(ua) {
      const browser = {
        name: "Firefox"
      };
      const version = Utils.getFirstMatch(/(?:firefox|iceweasel|fxios)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/electron/i],
    describe(ua) {
      const browser = {
        name: "Electron"
      };
      const version = Utils.getFirstMatch(/(?:electron)\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/sogoumobilebrowser/i, /metasr/i, /se 2\.[x]/i],
    describe(ua) {
      const browser = {
        name: "Sogou Browser"
      };
      const sogouMobileVersion = Utils.getFirstMatch(/(?:sogoumobilebrowser)[\s/](\d+(\.?_?\d+)+)/i, ua);
      const chromiumVersion = Utils.getFirstMatch(/(?:chrome|crios|crmo)\/(\d+(\.?_?\d+)+)/i, ua);
      const seVersion = Utils.getFirstMatch(/se ([\d.]+)x/i, ua);
      const version = sogouMobileVersion || chromiumVersion || seVersion;
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/MiuiBrowser/i],
    describe(ua) {
      const browser = {
        name: "Miui"
      };
      const version = Utils.getFirstMatch(/(?:MiuiBrowser)[\s/](\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* DuckDuckGo Browser */
  {
    test(parser) {
      if (parser.hasBrand("DuckDuckGo")) {
        return true;
      }
      return parser.test(/\sDdg\/[\d.]+$/i);
    },
    describe(ua, parser) {
      const browser = {
        name: "DuckDuckGo"
      };
      if (parser) {
        const hintsVersion = parser.getBrandVersion("DuckDuckGo");
        if (hintsVersion) {
          browser.version = hintsVersion;
          return browser;
        }
      }
      const uaVersion = Utils.getFirstMatch(/\sDdg\/([\d.]+)$/i, ua);
      if (uaVersion) {
        browser.version = uaVersion;
      }
      return browser;
    }
  },
  /* Brave Browser */
  {
    test(parser) {
      return parser.hasBrand("Brave");
    },
    describe(ua, parser) {
      const browser = {
        name: "Brave"
      };
      if (parser) {
        const hintsVersion = parser.getBrandVersion("Brave");
        if (hintsVersion) {
          browser.version = hintsVersion;
          return browser;
        }
      }
      return browser;
    }
  },
  {
    test: [/chromium/i],
    describe(ua) {
      const browser = {
        name: "Chromium"
      };
      const version = Utils.getFirstMatch(/(?:chromium)[\s/](\d+(\.?_?\d+)+)/i, ua) || Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/chrome|crios|crmo/i],
    describe(ua) {
      const browser = {
        name: "Chrome"
      };
      const version = Utils.getFirstMatch(/(?:chrome|crios|crmo)\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  {
    test: [/GSA/i],
    describe(ua) {
      const browser = {
        name: "Google Search"
      };
      const version = Utils.getFirstMatch(/(?:GSA)\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Android Browser */
  {
    test(parser) {
      const notLikeAndroid = !parser.test(/like android/i);
      const butAndroid = parser.test(/android/i);
      return notLikeAndroid && butAndroid;
    },
    describe(ua) {
      const browser = {
        name: "Android Browser"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* PlayStation 4 */
  {
    test: [/playstation 4/i],
    describe(ua) {
      const browser = {
        name: "PlayStation 4"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Safari */
  {
    test: [/safari|applewebkit/i],
    describe(ua) {
      const browser = {
        name: "Safari"
      };
      const version = Utils.getFirstMatch(commonVersionIdentifier, ua);
      if (version) {
        browser.version = version;
      }
      return browser;
    }
  },
  /* Something else */
  {
    test: [/.*/i],
    describe(ua) {
      const regexpWithoutDeviceSpec = /^(.*)\/(.*) /;
      const regexpWithDeviceSpec = /^(.*)\/(.*)[ \t]\((.*)/;
      const hasDeviceSpec = ua.search("\\(") !== -1;
      const regexp = hasDeviceSpec ? regexpWithDeviceSpec : regexpWithoutDeviceSpec;
      return {
        name: Utils.getFirstMatch(regexp, ua),
        version: Utils.getSecondMatch(regexp, ua)
      };
    }
  }
];
var parser_browsers_default = browsersList;

// node_modules/bowser/src/parser-os.js
init_esm_shims();
var parser_os_default = [
  /* Roku */
  {
    test: [/Roku\/DVP/],
    describe(ua) {
      const version = Utils.getFirstMatch(/Roku\/DVP-(\d+\.\d+)/i, ua);
      return {
        name: OS_MAP.Roku,
        version
      };
    }
  },
  /* Windows Phone */
  {
    test: [/windows phone/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/windows phone (?:os)?\s?(\d+(\.\d+)*)/i, ua);
      return {
        name: OS_MAP.WindowsPhone,
        version
      };
    }
  },
  /* Windows */
  {
    test: [/windows /i],
    describe(ua) {
      const version = Utils.getFirstMatch(/Windows ((NT|XP)( \d\d?.\d)?)/i, ua);
      const versionName = Utils.getWindowsVersionName(version);
      return {
        name: OS_MAP.Windows,
        version,
        versionName
      };
    }
  },
  /* Firefox on iPad */
  {
    test: [/Macintosh(.*?) FxiOS(.*?)\//],
    describe(ua) {
      const result = {
        name: OS_MAP.iOS
      };
      const version = Utils.getSecondMatch(/(Version\/)(\d[\d.]+)/, ua);
      if (version) {
        result.version = version;
      }
      return result;
    }
  },
  /* macOS */
  {
    test: [/macintosh/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/mac os x (\d+(\.?_?\d+)+)/i, ua).replace(/[_\s]/g, ".");
      const versionName = Utils.getMacOSVersionName(version);
      const os = {
        name: OS_MAP.MacOS,
        version
      };
      if (versionName) {
        os.versionName = versionName;
      }
      return os;
    }
  },
  /* iOS */
  {
    test: [/(ipod|iphone|ipad)/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/os (\d+([_\s]\d+)*) like mac os x/i, ua).replace(/[_\s]/g, ".");
      return {
        name: OS_MAP.iOS,
        version
      };
    }
  },
  /* HarmonyOS */
  {
    test: [/OpenHarmony/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/OpenHarmony\s+(\d+(\.\d+)*)/i, ua);
      return {
        name: OS_MAP.HarmonyOS,
        version
      };
    }
  },
  /* Android */
  {
    test(parser) {
      const notLikeAndroid = !parser.test(/like android/i);
      const butAndroid = parser.test(/android/i);
      return notLikeAndroid && butAndroid;
    },
    describe(ua) {
      const version = Utils.getFirstMatch(/android[\s/-](\d+(\.\d+)*)/i, ua);
      const versionName = Utils.getAndroidVersionName(version);
      const os = {
        name: OS_MAP.Android,
        version
      };
      if (versionName) {
        os.versionName = versionName;
      }
      return os;
    }
  },
  /* WebOS */
  {
    test: [/(web|hpw)[o0]s/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/(?:web|hpw)[o0]s\/(\d+(\.\d+)*)/i, ua);
      const os = {
        name: OS_MAP.WebOS
      };
      if (version && version.length) {
        os.version = version;
      }
      return os;
    }
  },
  /* BlackBerry */
  {
    test: [/blackberry|\bbb\d+/i, /rim\stablet/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/rim\stablet\sos\s(\d+(\.\d+)*)/i, ua) || Utils.getFirstMatch(/blackberry\d+\/(\d+([_\s]\d+)*)/i, ua) || Utils.getFirstMatch(/\bbb(\d+)/i, ua);
      return {
        name: OS_MAP.BlackBerry,
        version
      };
    }
  },
  /* Bada */
  {
    test: [/bada/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/bada\/(\d+(\.\d+)*)/i, ua);
      return {
        name: OS_MAP.Bada,
        version
      };
    }
  },
  /* Tizen */
  {
    test: [/tizen/i],
    describe(ua) {
      const version = Utils.getFirstMatch(/tizen[/\s](\d+(\.\d+)*)/i, ua);
      return {
        name: OS_MAP.Tizen,
        version
      };
    }
  },
  /* Linux */
  {
    test: [/linux/i],
    describe() {
      return {
        name: OS_MAP.Linux
      };
    }
  },
  /* Chrome OS */
  {
    test: [/CrOS/],
    describe() {
      return {
        name: OS_MAP.ChromeOS
      };
    }
  },
  /* Playstation 4 */
  {
    test: [/PlayStation 4/],
    describe(ua) {
      const version = Utils.getFirstMatch(/PlayStation 4[/\s](\d+(\.\d+)*)/i, ua);
      return {
        name: OS_MAP.PlayStation4,
        version
      };
    }
  }
];

// node_modules/bowser/src/parser-platforms.js
init_esm_shims();
var parser_platforms_default = [
  /* Googlebot */
  {
    test: [/googlebot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Google"
      };
    }
  },
  /* LineSpider */
  {
    test: [/linespider/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Line"
      };
    }
  },
  /* AmazonBot */
  {
    test: [/amazonbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Amazon"
      };
    }
  },
  /* GPTBot */
  {
    test: [/gptbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "OpenAI"
      };
    }
  },
  /* ChatGPT-User */
  {
    test: [/chatgpt-user/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "OpenAI"
      };
    }
  },
  /* OAI-SearchBot */
  {
    test: [/oai-searchbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "OpenAI"
      };
    }
  },
  /* Baidu */
  {
    test: [/baiduspider/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Baidu"
      };
    }
  },
  /* Bingbot */
  {
    test: [/bingbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Bing"
      };
    }
  },
  /* DuckDuckBot */
  {
    test: [/duckduckbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "DuckDuckGo"
      };
    }
  },
  /* ClaudeBot */
  {
    test: [/claudebot/i, /claude-web/i, /claude-user/i, /claude-searchbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Anthropic"
      };
    }
  },
  /* Omgilibot */
  {
    test: [/omgilibot/i, /webzio-extended/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Webz.io"
      };
    }
  },
  /* Diffbot */
  {
    test: [/diffbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Diffbot"
      };
    }
  },
  /* PerplexityBot */
  {
    test: [/perplexitybot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Perplexity AI"
      };
    }
  },
  /* Perplexity-User */
  {
    test: [/perplexity-user/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Perplexity AI"
      };
    }
  },
  /* YouBot */
  {
    test: [/youbot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "You.com"
      };
    }
  },
  /* Internet Archive Crawler */
  {
    test: [/ia_archiver/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Internet Archive"
      };
    }
  },
  /* Meta-WebIndexer */
  {
    test: [/meta-webindexer/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Meta"
      };
    }
  },
  /* Meta-ExternalAds */
  {
    test: [/meta-externalads/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Meta"
      };
    }
  },
  /* Meta-ExternalAgent */
  {
    test: [/meta-externalagent/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Meta"
      };
    }
  },
  /* Meta-ExternalFetcher */
  {
    test: [/meta-externalfetcher/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Meta"
      };
    }
  },
  /* Meta Web Crawler */
  {
    test: [/facebookexternalhit/i, /facebookcatalog/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Meta"
      };
    }
  },
  /* SlackBot */
  {
    test: [/slackbot/i, /slack-imgProxy/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Slack"
      };
    }
  },
  /* Yahoo! Slurp */
  {
    test: [/yahoo/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Yahoo"
      };
    }
  },
  /* Yandex */
  {
    test: [/yandexbot/i, /yandexmobilebot/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Yandex"
      };
    }
  },
  /* Pingdom */
  {
    test: [/pingdom/i],
    describe() {
      return {
        type: PLATFORMS_MAP.bot,
        vendor: "Pingdom"
      };
    }
  },
  /* Huawei */
  {
    test: [/huawei/i],
    describe(ua) {
      const model = Utils.getFirstMatch(/(can-l01)/i, ua) && "Nova";
      const platform = {
        type: PLATFORMS_MAP.mobile,
        vendor: "Huawei"
      };
      if (model) {
        platform.model = model;
      }
      return platform;
    }
  },
  /* Nexus Tablet */
  {
    test: [/nexus\s*(?:7|8|9|10).*/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tablet,
        vendor: "Nexus"
      };
    }
  },
  /* iPad */
  {
    test: [/ipad/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tablet,
        vendor: "Apple",
        model: "iPad"
      };
    }
  },
  /* Firefox on iPad */
  {
    test: [/Macintosh(.*?) FxiOS(.*?)\//],
    describe() {
      return {
        type: PLATFORMS_MAP.tablet,
        vendor: "Apple",
        model: "iPad"
      };
    }
  },
  /* Amazon Kindle Fire */
  {
    test: [/kftt build/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tablet,
        vendor: "Amazon",
        model: "Kindle Fire HD 7"
      };
    }
  },
  /* Another Amazon Tablet with Silk */
  {
    test: [/silk/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tablet,
        vendor: "Amazon"
      };
    }
  },
  /* Tablet */
  {
    test: [/tablet(?! pc)/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tablet
      };
    }
  },
  /* iPod/iPhone */
  {
    test(parser) {
      const iDevice = parser.test(/ipod|iphone/i);
      const likeIDevice = parser.test(/like (ipod|iphone)/i);
      return iDevice && !likeIDevice;
    },
    describe(ua) {
      const model = Utils.getFirstMatch(/(ipod|iphone)/i, ua);
      return {
        type: PLATFORMS_MAP.mobile,
        vendor: "Apple",
        model
      };
    }
  },
  /* Nexus Mobile */
  {
    test: [/nexus\s*[0-6].*/i, /galaxy nexus/i],
    describe() {
      return {
        type: PLATFORMS_MAP.mobile,
        vendor: "Nexus"
      };
    }
  },
  /* Nokia */
  {
    test: [/Nokia/i],
    describe(ua) {
      const model = Utils.getFirstMatch(/Nokia\s+([0-9]+(\.[0-9]+)?)/i, ua);
      const platform = {
        type: PLATFORMS_MAP.mobile,
        vendor: "Nokia"
      };
      if (model) {
        platform.model = model;
      }
      return platform;
    }
  },
  /* Mobile */
  {
    test: [/[^-]mobi/i],
    describe() {
      return {
        type: PLATFORMS_MAP.mobile
      };
    }
  },
  /* BlackBerry */
  {
    test(parser) {
      return parser.getBrowserName(true) === "blackberry";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.mobile,
        vendor: "BlackBerry"
      };
    }
  },
  /* Bada */
  {
    test(parser) {
      return parser.getBrowserName(true) === "bada";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.mobile
      };
    }
  },
  /* Windows Phone */
  {
    test(parser) {
      return parser.getBrowserName() === "windows phone";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.mobile,
        vendor: "Microsoft"
      };
    }
  },
  /* Android Tablet */
  {
    test(parser) {
      const osMajorVersion = Number(String(parser.getOSVersion()).split(".")[0]);
      return parser.getOSName(true) === "android" && osMajorVersion >= 3;
    },
    describe() {
      return {
        type: PLATFORMS_MAP.tablet
      };
    }
  },
  /* Android Mobile */
  {
    test(parser) {
      return parser.getOSName(true) === "android";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.mobile
      };
    }
  },
  /* Smart TV */
  {
    test: [/smart-?tv|smarttv/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tv
      };
    }
  },
  /* NetCast (LG Smart TV) */
  {
    test: [/netcast/i],
    describe() {
      return {
        type: PLATFORMS_MAP.tv
      };
    }
  },
  /* desktop */
  {
    test(parser) {
      return parser.getOSName(true) === "macos";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.desktop,
        vendor: "Apple"
      };
    }
  },
  /* Windows */
  {
    test(parser) {
      return parser.getOSName(true) === "windows";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.desktop
      };
    }
  },
  /* Linux */
  {
    test(parser) {
      return parser.getOSName(true) === "linux";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.desktop
      };
    }
  },
  /* PlayStation 4 */
  {
    test(parser) {
      return parser.getOSName(true) === "playstation 4";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.tv
      };
    }
  },
  /* Roku */
  {
    test(parser) {
      return parser.getOSName(true) === "roku";
    },
    describe() {
      return {
        type: PLATFORMS_MAP.tv
      };
    }
  }
];

// node_modules/bowser/src/parser-engines.js
init_esm_shims();
var parser_engines_default = [
  /* EdgeHTML */
  {
    test(parser) {
      return parser.getBrowserName(true) === "microsoft edge";
    },
    describe(ua) {
      const isBlinkBased = /\sedg\//i.test(ua);
      if (isBlinkBased) {
        return {
          name: ENGINE_MAP.Blink
        };
      }
      const version = Utils.getFirstMatch(/edge\/(\d+(\.?_?\d+)+)/i, ua);
      return {
        name: ENGINE_MAP.EdgeHTML,
        version
      };
    }
  },
  /* Trident */
  {
    test: [/trident/i],
    describe(ua) {
      const engine = {
        name: ENGINE_MAP.Trident
      };
      const version = Utils.getFirstMatch(/trident\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        engine.version = version;
      }
      return engine;
    }
  },
  /* Presto */
  {
    test(parser) {
      return parser.test(/presto/i);
    },
    describe(ua) {
      const engine = {
        name: ENGINE_MAP.Presto
      };
      const version = Utils.getFirstMatch(/presto\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        engine.version = version;
      }
      return engine;
    }
  },
  /* Gecko */
  {
    test(parser) {
      const isGecko = parser.test(/gecko/i);
      const likeGecko = parser.test(/like gecko/i);
      return isGecko && !likeGecko;
    },
    describe(ua) {
      const engine = {
        name: ENGINE_MAP.Gecko
      };
      const version = Utils.getFirstMatch(/gecko\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        engine.version = version;
      }
      return engine;
    }
  },
  /* Blink */
  {
    test: [/(apple)?webkit\/537\.36/i],
    describe() {
      return {
        name: ENGINE_MAP.Blink
      };
    }
  },
  /* WebKit */
  {
    test: [/(apple)?webkit/i],
    describe(ua) {
      const engine = {
        name: ENGINE_MAP.WebKit
      };
      const version = Utils.getFirstMatch(/webkit\/(\d+(\.?_?\d+)+)/i, ua);
      if (version) {
        engine.version = version;
      }
      return engine;
    }
  }
];

// node_modules/bowser/src/parser.js
var Parser = class {
  /**
   * Create instance of Parser
   *
   * @param {String} UA User-Agent string
   * @param {Boolean|ClientHints} [skipParsingOrHints=false] Either a boolean to skip parsing,
   * or a ClientHints object containing User-Agent Client Hints data
   * @param {ClientHints} [clientHints] User-Agent Client Hints data (navigator.userAgentData)
   *
   * @throw {Error} in case of empty UA String
   *
   * @constructor
   */
  constructor(UA, skipParsingOrHints = false, clientHints = null) {
    if (UA === void 0 || UA === null || UA === "") {
      throw new Error("UserAgent parameter can't be empty");
    }
    this._ua = UA;
    let skipParsing = false;
    if (typeof skipParsingOrHints === "boolean") {
      skipParsing = skipParsingOrHints;
      this._hints = clientHints;
    } else if (skipParsingOrHints != null && typeof skipParsingOrHints === "object") {
      this._hints = skipParsingOrHints;
    } else {
      this._hints = null;
    }
    this.parsedResult = {};
    if (skipParsing !== true) {
      this.parse();
    }
  }
  /**
   * Get Client Hints data
   * @return {ClientHints|null}
   *
   * @public
   * @example
   * const parser = Bowser.getParser(UA, clientHints);
   * const hints = parser.getHints();
   * console.log(hints.platform); // 'Windows'
   * console.log(hints.mobile); // false
   */
  getHints() {
    return this._hints;
  }
  /**
   * Check if a brand exists in Client Hints brands array
   * @param {string} brandName The brand name to check for
   * @return {boolean}
   *
   * @public
   * @example
   * const parser = Bowser.getParser(UA, clientHints);
   * if (parser.hasBrand('Google Chrome')) {
   *   console.log('Chrome detected!');
   * }
   */
  hasBrand(brandName) {
    if (!this._hints || !Array.isArray(this._hints.brands)) {
      return false;
    }
    const brandLower = brandName.toLowerCase();
    return this._hints.brands.some(
      (b) => b.brand && b.brand.toLowerCase() === brandLower
    );
  }
  /**
   * Get brand version from Client Hints
   * @param {string} brandName The brand name to get version for
   * @return {string|undefined}
   *
   * @public
   * @example
   * const parser = Bowser.getParser(UA, clientHints);
   * const version = parser.getBrandVersion('Google Chrome');
   * console.log(version); // '131'
   */
  getBrandVersion(brandName) {
    if (!this._hints || !Array.isArray(this._hints.brands)) {
      return void 0;
    }
    const brandLower = brandName.toLowerCase();
    const brand = this._hints.brands.find(
      (b) => b.brand && b.brand.toLowerCase() === brandLower
    );
    return brand ? brand.version : void 0;
  }
  /**
   * Get UserAgent string of current Parser instance
   * @return {String} User-Agent String of the current <Parser> object
   *
   * @public
   */
  getUA() {
    return this._ua;
  }
  /**
   * Test a UA string for a regexp
   * @param {RegExp} regex
   * @return {Boolean}
   */
  test(regex) {
    return regex.test(this._ua);
  }
  /**
   * Get parsed browser object
   * @return {Object}
   */
  parseBrowser() {
    this.parsedResult.browser = {};
    const browserDescriptor = Utils.find(parser_browsers_default, (_browser) => {
      if (typeof _browser.test === "function") {
        return _browser.test(this);
      }
      if (Array.isArray(_browser.test)) {
        return _browser.test.some((condition) => this.test(condition));
      }
      throw new Error("Browser's test function is not valid");
    });
    if (browserDescriptor) {
      this.parsedResult.browser = browserDescriptor.describe(this.getUA(), this);
    }
    return this.parsedResult.browser;
  }
  /**
   * Get parsed browser object
   * @return {Object}
   *
   * @public
   */
  getBrowser() {
    if (this.parsedResult.browser) {
      return this.parsedResult.browser;
    }
    return this.parseBrowser();
  }
  /**
   * Get browser's name
   * @return {String} Browser's name or an empty string
   *
   * @public
   */
  getBrowserName(toLowerCase) {
    if (toLowerCase) {
      return String(this.getBrowser().name).toLowerCase() || "";
    }
    return this.getBrowser().name || "";
  }
  /**
   * Get browser's version
   * @return {String} version of browser
   *
   * @public
   */
  getBrowserVersion() {
    return this.getBrowser().version;
  }
  /**
   * Get OS
   * @return {Object}
   *
   * @example
   * this.getOS();
   * {
   *   name: 'macOS',
   *   version: '10.11.12'
   * }
   */
  getOS() {
    if (this.parsedResult.os) {
      return this.parsedResult.os;
    }
    return this.parseOS();
  }
  /**
   * Parse OS and save it to this.parsedResult.os
   * @return {*|{}}
   */
  parseOS() {
    this.parsedResult.os = {};
    const os = Utils.find(parser_os_default, (_os) => {
      if (typeof _os.test === "function") {
        return _os.test(this);
      }
      if (Array.isArray(_os.test)) {
        return _os.test.some((condition) => this.test(condition));
      }
      throw new Error("Browser's test function is not valid");
    });
    if (os) {
      this.parsedResult.os = os.describe(this.getUA());
    }
    return this.parsedResult.os;
  }
  /**
   * Get OS name
   * @param {Boolean} [toLowerCase] return lower-cased value
   * @return {String} name of the OS — macOS, Windows, Linux, etc.
   */
  getOSName(toLowerCase) {
    const { name } = this.getOS();
    if (toLowerCase) {
      return String(name).toLowerCase() || "";
    }
    return name || "";
  }
  /**
   * Get OS version
   * @return {String} full version with dots ('10.11.12', '5.6', etc)
   */
  getOSVersion() {
    return this.getOS().version;
  }
  /**
   * Get parsed platform
   * @return {{}}
   */
  getPlatform() {
    if (this.parsedResult.platform) {
      return this.parsedResult.platform;
    }
    return this.parsePlatform();
  }
  /**
   * Get platform name
   * @param {Boolean} [toLowerCase=false]
   * @return {*}
   */
  getPlatformType(toLowerCase = false) {
    const { type } = this.getPlatform();
    if (toLowerCase) {
      return String(type).toLowerCase() || "";
    }
    return type || "";
  }
  /**
   * Get parsed platform
   * @return {{}}
   */
  parsePlatform() {
    this.parsedResult.platform = {};
    const platform = Utils.find(parser_platforms_default, (_platform) => {
      if (typeof _platform.test === "function") {
        return _platform.test(this);
      }
      if (Array.isArray(_platform.test)) {
        return _platform.test.some((condition) => this.test(condition));
      }
      throw new Error("Browser's test function is not valid");
    });
    if (platform) {
      this.parsedResult.platform = platform.describe(this.getUA());
    }
    return this.parsedResult.platform;
  }
  /**
   * Get parsed engine
   * @return {{}}
   */
  getEngine() {
    if (this.parsedResult.engine) {
      return this.parsedResult.engine;
    }
    return this.parseEngine();
  }
  /**
   * Get engines's name
   * @return {String} Engines's name or an empty string
   *
   * @public
   */
  getEngineName(toLowerCase) {
    if (toLowerCase) {
      return String(this.getEngine().name).toLowerCase() || "";
    }
    return this.getEngine().name || "";
  }
  /**
   * Get parsed platform
   * @return {{}}
   */
  parseEngine() {
    this.parsedResult.engine = {};
    const engine = Utils.find(parser_engines_default, (_engine) => {
      if (typeof _engine.test === "function") {
        return _engine.test(this);
      }
      if (Array.isArray(_engine.test)) {
        return _engine.test.some((condition) => this.test(condition));
      }
      throw new Error("Browser's test function is not valid");
    });
    if (engine) {
      this.parsedResult.engine = engine.describe(this.getUA());
    }
    return this.parsedResult.engine;
  }
  /**
   * Parse full information about the browser
   * @returns {Parser}
   */
  parse() {
    this.parseBrowser();
    this.parseOS();
    this.parsePlatform();
    this.parseEngine();
    return this;
  }
  /**
   * Get parsed result
   * @return {ParsedResult}
   */
  getResult() {
    return Utils.assign({}, this.parsedResult);
  }
  /**
   * Check if parsed browser matches certain conditions
   *
   * @param {Object} checkTree It's one or two layered object,
   * which can include a platform or an OS on the first layer
   * and should have browsers specs on the bottom-laying layer
   *
   * @returns {Boolean|undefined} Whether the browser satisfies the set conditions or not.
   * Returns `undefined` when the browser is no described in the checkTree object.
   *
   * @example
   * const browser = Bowser.getParser(window.navigator.userAgent);
   * if (browser.satisfies({chrome: '>118.01.1322' }))
   * // or with os
   * if (browser.satisfies({windows: { chrome: '>118.01.1322' } }))
   * // or with platforms
   * if (browser.satisfies({desktop: { chrome: '>118.01.1322' } }))
   */
  satisfies(checkTree) {
    const platformsAndOSes = {};
    let platformsAndOSCounter = 0;
    const browsers = {};
    let browsersCounter = 0;
    const allDefinitions = Object.keys(checkTree);
    allDefinitions.forEach((key) => {
      const currentDefinition = checkTree[key];
      if (typeof currentDefinition === "string") {
        browsers[key] = currentDefinition;
        browsersCounter += 1;
      } else if (typeof currentDefinition === "object") {
        platformsAndOSes[key] = currentDefinition;
        platformsAndOSCounter += 1;
      }
    });
    if (platformsAndOSCounter > 0) {
      const platformsAndOSNames = Object.keys(platformsAndOSes);
      const OSMatchingDefinition = Utils.find(platformsAndOSNames, (name) => this.isOS(name));
      if (OSMatchingDefinition) {
        const osResult = this.satisfies(platformsAndOSes[OSMatchingDefinition]);
        if (osResult !== void 0) {
          return osResult;
        }
      }
      const platformMatchingDefinition = Utils.find(
        platformsAndOSNames,
        (name) => this.isPlatform(name)
      );
      if (platformMatchingDefinition) {
        const platformResult = this.satisfies(platformsAndOSes[platformMatchingDefinition]);
        if (platformResult !== void 0) {
          return platformResult;
        }
      }
    }
    if (browsersCounter > 0) {
      const browserNames = Object.keys(browsers);
      const matchingDefinition = Utils.find(browserNames, (name) => this.isBrowser(name, true));
      if (matchingDefinition !== void 0) {
        return this.compareVersion(browsers[matchingDefinition]);
      }
    }
    return void 0;
  }
  /**
   * Check if the browser name equals the passed string
   * @param {string} browserName The string to compare with the browser name
   * @param [includingAlias=false] The flag showing whether alias will be included into comparison
   * @returns {boolean}
   */
  isBrowser(browserName, includingAlias = false) {
    const defaultBrowserName = this.getBrowserName().toLowerCase();
    let browserNameLower = browserName.toLowerCase();
    const alias = Utils.getBrowserTypeByAlias(browserNameLower);
    if (includingAlias && alias) {
      browserNameLower = alias.toLowerCase();
    }
    return browserNameLower === defaultBrowserName;
  }
  compareVersion(version) {
    let expectedResults = [0];
    let comparableVersion = version;
    let isLoose = false;
    const currentBrowserVersion = this.getBrowserVersion();
    if (typeof currentBrowserVersion !== "string") {
      return void 0;
    }
    if (version[0] === ">" || version[0] === "<") {
      comparableVersion = version.substr(1);
      if (version[1] === "=") {
        isLoose = true;
        comparableVersion = version.substr(2);
      } else {
        expectedResults = [];
      }
      if (version[0] === ">") {
        expectedResults.push(1);
      } else {
        expectedResults.push(-1);
      }
    } else if (version[0] === "=") {
      comparableVersion = version.substr(1);
    } else if (version[0] === "~") {
      isLoose = true;
      comparableVersion = version.substr(1);
    }
    return expectedResults.indexOf(
      Utils.compareVersions(currentBrowserVersion, comparableVersion, isLoose)
    ) > -1;
  }
  /**
   * Check if the OS name equals the passed string
   * @param {string} osName The string to compare with the OS name
   * @returns {boolean}
   */
  isOS(osName) {
    return this.getOSName(true) === String(osName).toLowerCase();
  }
  /**
   * Check if the platform type equals the passed string
   * @param {string} platformType The string to compare with the platform type
   * @returns {boolean}
   */
  isPlatform(platformType) {
    return this.getPlatformType(true) === String(platformType).toLowerCase();
  }
  /**
   * Check if the engine name equals the passed string
   * @param {string} engineName The string to compare with the engine name
   * @returns {boolean}
   */
  isEngine(engineName) {
    return this.getEngineName(true) === String(engineName).toLowerCase();
  }
  /**
   * Is anything? Check if the browser is called "anything",
   * the OS called "anything" or the platform called "anything"
   * @param {String} anything
   * @param [includingAlias=false] The flag showing whether alias will be included into comparison
   * @returns {Boolean}
   */
  is(anything, includingAlias = false) {
    return this.isBrowser(anything, includingAlias) || this.isOS(anything) || this.isPlatform(anything);
  }
  /**
   * Check if any of the given values satisfies this.is(anything)
   * @param {String[]} anythings
   * @returns {Boolean}
   */
  some(anythings = []) {
    return anythings.some((anything) => this.is(anything));
  }
};
var parser_default = Parser;

// node_modules/bowser/src/bowser.js
var Bowser = class {
  /**
   * Creates a {@link Parser} instance
   *
   * @param {String} UA UserAgent string
   * @param {Boolean|Object} [skipParsingOrHints=false] Either a boolean to skip parsing,
   * or a ClientHints object (navigator.userAgentData)
   * @param {Object} [clientHints] User-Agent Client Hints data (navigator.userAgentData)
   * @returns {Parser}
   * @throws {Error} when UA is not a String
   *
   * @example
   * const parser = Bowser.getParser(window.navigator.userAgent);
   * const result = parser.getResult();
   *
   * @example
   * // With User-Agent Client Hints
   * const parser = Bowser.getParser(
   *   window.navigator.userAgent,
   *   window.navigator.userAgentData
   * );
   */
  static getParser(UA, skipParsingOrHints = false, clientHints = null) {
    if (typeof UA !== "string") {
      throw new Error("UserAgent should be a string");
    }
    return new parser_default(UA, skipParsingOrHints, clientHints);
  }
  /**
   * Creates a {@link Parser} instance and runs {@link Parser.getResult} immediately
   *
   * @param {String} UA UserAgent string
   * @param {Object} [clientHints] User-Agent Client Hints data (navigator.userAgentData)
   * @return {ParsedResult}
   *
   * @example
   * const result = Bowser.parse(window.navigator.userAgent);
   *
   * @example
   * // With User-Agent Client Hints
   * const result = Bowser.parse(
   *   window.navigator.userAgent,
   *   window.navigator.userAgentData
   * );
   */
  static parse(UA, clientHints = null) {
    return new parser_default(UA, clientHints).getResult();
  }
  static get BROWSER_MAP() {
    return BROWSER_MAP;
  }
  static get ENGINE_MAP() {
    return ENGINE_MAP;
  }
  static get OS_MAP() {
    return OS_MAP;
  }
  static get PLATFORMS_MAP() {
    return PLATFORMS_MAP;
  }
};
var bowser_default = Bowser;
/*! Bundled license information:

bowser/src/bowser.js:
  (*!
   * Bowser - a browser detector
   * https://github.com/bowser-js/bowser
   * MIT License | (c) Dustin Diaz 2012-2015
   * MIT License | (c) Denis Demchenko 2015-2019
   *)
*/

export { bowser_default as default };
