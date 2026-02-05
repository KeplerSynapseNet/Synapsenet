#include "web/web.h"
#include <regex>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <stack>

namespace synapse {
namespace web {

struct HtmlExtractor::Impl {
    size_t maxTextLength = 50000;
    bool removeAds = true;
    bool removeScripts = true;
    bool removeStyles = true;
    bool removeNavigation = true;
    
    std::string stripTags(const std::string& html);
    std::string decodeEntities(const std::string& text);
    std::string normalizeWhitespace(const std::string& text);
    std::vector<std::string> findAllMatches(const std::string& html, const std::regex& pattern);
    std::string extractBetweenTags(const std::string& html, const std::string& tag);
    bool isAdElement(const std::string& element);
    bool isNavigationElement(const std::string& element);
};

std::string HtmlExtractor::Impl::stripTags(const std::string& html) {
    std::string result;
    bool inTag = false;
    bool inScript = false;
    bool inStyle = false;
    
    for (size_t i = 0; i < html.size(); i++) {
        if (html[i] == '<') {
            std::string tagStart = html.substr(i, 10);
            std::transform(tagStart.begin(), tagStart.end(), tagStart.begin(), ::tolower);
            
            if (tagStart.find("<script") == 0) inScript = true;
            if (tagStart.find("<style") == 0) inStyle = true;
            if (tagStart.find("</script") == 0) inScript = false;
            if (tagStart.find("</style") == 0) inStyle = false;
            
            inTag = true;
        } else if (html[i] == '>') {
            inTag = false;
        } else if (!inTag && !inScript && !inStyle) {
            result += html[i];
        }
    }
    
    return result;
}

std::string HtmlExtractor::Impl::decodeEntities(const std::string& text) {
    std::string result = text;
    
    std::vector<std::pair<std::string, std::string>> entities = {
        {"&nbsp;", " "}, {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"},
        {"&quot;", "\""}, {"&apos;", "'"}, {"&#39;", "'"}, {"&#x27;", "'"},
        {"&mdash;", "-"}, {"&ndash;", "-"}, {"&hellip;", "..."},
        {"&copy;", "(c)"}, {"&reg;", "(R)"}, {"&trade;", "(TM)"},
        {"&laquo;", "<<"}, {"&raquo;", ">>"}, {"&bull;", "*"},
        {"&middot;", "*"}, {"&deg;", " degrees"}, {"&plusmn;", "+/-"}
    };
    
    for (const auto& [entity, replacement] : entities) {
        size_t pos = 0;
        while ((pos = result.find(entity, pos)) != std::string::npos) {
            result.replace(pos, entity.length(), replacement);
            pos += replacement.length();
        }
    }
    
    std::regex numericEntity("&#(\\d+);");
    std::smatch match;
    while (std::regex_search(result, match, numericEntity)) {
        int code = std::stoi(match[1].str());
        std::string replacement(1, static_cast<char>(code));
        result = match.prefix().str() + replacement + match.suffix().str();
    }
    
    return result;
}

std::string HtmlExtractor::Impl::normalizeWhitespace(const std::string& text) {
    std::string result;
    bool lastWasSpace = false;
    
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!lastWasSpace) {
                result += ' ';
                lastWasSpace = true;
            }
        } else {
            result += c;
            lastWasSpace = false;
        }
    }
    
    size_t start = result.find_first_not_of(' ');
    size_t end = result.find_last_not_of(' ');
    
    if (start == std::string::npos) return "";
    return result.substr(start, end - start + 1);
}

std::vector<std::string> HtmlExtractor::Impl::findAllMatches(const std::string& html, const std::regex& pattern) {
    std::vector<std::string> matches;
    std::sregex_iterator it(html.begin(), html.end(), pattern);
    std::sregex_iterator end;
    
    while (it != end) {
        matches.push_back((*it)[1].str());
        ++it;
    }
    
    return matches;
}

std::string HtmlExtractor::Impl::extractBetweenTags(const std::string& html, const std::string& tag) {
    std::string openTag = "<" + tag;
    std::string closeTag = "</" + tag + ">";
    
    size_t start = html.find(openTag);
    if (start == std::string::npos) return "";
    
    start = html.find('>', start);
    if (start == std::string::npos) return "";
    start++;
    
    size_t end = html.find(closeTag, start);
    if (end == std::string::npos) return "";
    
    return html.substr(start, end - start);
}

bool HtmlExtractor::Impl::isAdElement(const std::string& element) {
    std::string lower = element;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    std::vector<std::string> adIndicators = {
        "ad-", "ads-", "advertisement", "sponsor", "promo", "banner",
        "adsense", "advert", "commercial", "marketing"
    };
    
    for (const auto& indicator : adIndicators) {
        if (lower.find(indicator) != std::string::npos) return true;
    }
    
    return false;
}

bool HtmlExtractor::Impl::isNavigationElement(const std::string& element) {
    std::string lower = element;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    std::vector<std::string> navIndicators = {
        "nav", "menu", "sidebar", "footer", "header", "breadcrumb",
        "pagination", "toolbar", "topbar", "bottombar"
    };
    
    for (const auto& indicator : navIndicators) {
        if (lower.find(indicator) != std::string::npos) return true;
    }
    
    return false;
}

HtmlExtractor::HtmlExtractor() : impl_(std::make_unique<Impl>()) {}
HtmlExtractor::~HtmlExtractor() = default;

ExtractedContent HtmlExtractor::extract(const std::string& html, const std::string& url) {
    ExtractedContent content;
    content.originalSize = html.size();
    content.truncated = false;
    
    content.title = extractTitle(html);
    content.mainText = extractMainText(html);
    content.codeBlocks = extractCodeBlocks(html);
    content.onionLinks = extractOnionLinks(html);
    content.clearnetLinks = extractLinks(html);
    content.metadata = extractMetadata(html);
    
    if (!url.empty()) {
        content.metadata["source_url"] = url;
        content.metadata["domain"] = extractDomain(url);
    }
    
    if (content.mainText.size() > impl_->maxTextLength) {
        content.mainText = content.mainText.substr(0, impl_->maxTextLength);
        content.truncated = true;
    }
    
    content.extractedSize = content.title.size() + content.mainText.size();
    for (const auto& code : content.codeBlocks) {
        content.extractedSize += code.size();
    }
    
    return content;
}

std::string HtmlExtractor::extractTitle(const std::string& html) {
    std::regex titleRegex("<title[^>]*>([^<]+)</title>", std::regex::icase);
    std::smatch match;
    
    if (std::regex_search(html, match, titleRegex)) {
        return impl_->normalizeWhitespace(impl_->decodeEntities(match[1].str()));
    }
    
    std::regex h1Regex("<h1[^>]*>([^<]+)</h1>", std::regex::icase);
    if (std::regex_search(html, match, h1Regex)) {
        return impl_->normalizeWhitespace(impl_->decodeEntities(match[1].str()));
    }
    
    std::regex ogTitleRegex("<meta[^>]*property=\"og:title\"[^>]*content=\"([^\"]+)\"", std::regex::icase);
    if (std::regex_search(html, match, ogTitleRegex)) {
        return impl_->normalizeWhitespace(impl_->decodeEntities(match[1].str()));
    }
    
    return "";
}

std::string HtmlExtractor::extractMainText(const std::string& html) {
    std::string processed = html;
    
    if (impl_->removeScripts) {
        std::regex scriptRegex("<script[^>]*>[\\s\\S]*?</script>", std::regex::icase);
        processed = std::regex_replace(processed, scriptRegex, "");
    }
    
    if (impl_->removeStyles) {
        std::regex styleRegex("<style[^>]*>[\\s\\S]*?</style>", std::regex::icase);
        processed = std::regex_replace(processed, styleRegex, "");
    }
    
    if (impl_->removeNavigation) {
        std::regex navRegex("<nav[^>]*>[\\s\\S]*?</nav>", std::regex::icase);
        std::regex headerRegex("<header[^>]*>[\\s\\S]*?</header>", std::regex::icase);
        std::regex footerRegex("<footer[^>]*>[\\s\\S]*?</footer>", std::regex::icase);
        processed = std::regex_replace(processed, navRegex, "");
        processed = std::regex_replace(processed, headerRegex, "");
        processed = std::regex_replace(processed, footerRegex, "");
    }
    
    std::regex commentRegex("<!--[\\s\\S]*?-->");
    processed = std::regex_replace(processed, commentRegex, "");
    
    std::regex brRegex("<br[^>]*>", std::regex::icase);
    processed = std::regex_replace(processed, brRegex, "\n");
    
    std::regex pRegex("</p>", std::regex::icase);
    processed = std::regex_replace(processed, pRegex, "\n\n");
    
    std::regex divRegex("</div>", std::regex::icase);
    processed = std::regex_replace(processed, divRegex, "\n");
    
    std::string text = impl_->stripTags(processed);
    text = impl_->decodeEntities(text);
    text = impl_->normalizeWhitespace(text);
    
    return text;
}

std::vector<std::string> HtmlExtractor::extractCodeBlocks(const std::string& html) {
    std::vector<std::string> codeBlocks;
    
    std::regex preRegex("<pre[^>]*>([\\s\\S]*?)</pre>", std::regex::icase);
    auto preMatches = impl_->findAllMatches(html, preRegex);
    for (const auto& match : preMatches) {
        std::string code = impl_->stripTags(match);
        code = impl_->decodeEntities(code);
        if (!code.empty()) codeBlocks.push_back(code);
    }
    
    std::regex codeRegex("<code[^>]*>([\\s\\S]*?)</code>", std::regex::icase);
    auto codeMatches = impl_->findAllMatches(html, codeRegex);
    for (const auto& match : codeMatches) {
        std::string code = impl_->stripTags(match);
        code = impl_->decodeEntities(code);
        if (!code.empty() && code.size() > 20) codeBlocks.push_back(code);
    }
    
    return codeBlocks;
}

std::vector<std::string> HtmlExtractor::extractLinks(const std::string& html) {
    std::vector<std::string> links;
    std::regex linkRegex("href=\"(https?://[^\"]+)\"", std::regex::icase);
    
    std::sregex_iterator it(html.begin(), html.end(), linkRegex);
    std::sregex_iterator end;
    
    while (it != end) {
        std::string url = (*it)[1].str();
        if (!isOnionUrl(url)) {
            links.push_back(url);
        }
        ++it;
    }
    
    std::sort(links.begin(), links.end());
    links.erase(std::unique(links.begin(), links.end()), links.end());
    
    return links;
}

std::vector<std::string> HtmlExtractor::extractOnionLinks(const std::string& html) {
    std::vector<std::string> onionLinks;
    std::regex onionRegex("(https?://[a-z2-7]{56}\\.onion[^\"\\s<>]*)", std::regex::icase);
    
    std::sregex_iterator it(html.begin(), html.end(), onionRegex);
    std::sregex_iterator end;
    
    while (it != end) {
        onionLinks.push_back((*it)[1].str());
        ++it;
    }
    
    std::sort(onionLinks.begin(), onionLinks.end());
    onionLinks.erase(std::unique(onionLinks.begin(), onionLinks.end()), onionLinks.end());
    
    return onionLinks;
}

std::map<std::string, std::string> HtmlExtractor::extractMetadata(const std::string& html) {
    std::map<std::string, std::string> metadata;
    
    std::regex metaRegex("<meta[^>]*name=\"([^\"]+)\"[^>]*content=\"([^\"]+)\"", std::regex::icase);
    std::sregex_iterator it(html.begin(), html.end(), metaRegex);
    std::sregex_iterator end;
    
    while (it != end) {
        std::string name = (*it)[1].str();
        std::string content = (*it)[2].str();
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        metadata[name] = impl_->decodeEntities(content);
        ++it;
    }
    
    std::regex ogRegex("<meta[^>]*property=\"og:([^\"]+)\"[^>]*content=\"([^\"]+)\"", std::regex::icase);
    it = std::sregex_iterator(html.begin(), html.end(), ogRegex);
    
    while (it != end) {
        std::string name = "og:" + (*it)[1].str();
        std::string content = (*it)[2].str();
        metadata[name] = impl_->decodeEntities(content);
        ++it;
    }
    
    std::regex langRegex("<html[^>]*lang=\"([^\"]+)\"", std::regex::icase);
    std::smatch langMatch;
    if (std::regex_search(html, langMatch, langRegex)) {
        metadata["language"] = langMatch[1].str();
    }
    
    return metadata;
}

void HtmlExtractor::setMaxTextLength(size_t length) {
    impl_->maxTextLength = length;
}

void HtmlExtractor::setRemoveAds(bool remove) {
    impl_->removeAds = remove;
}

void HtmlExtractor::setRemoveScripts(bool remove) {
    impl_->removeScripts = remove;
}

void HtmlExtractor::setRemoveStyles(bool remove) {
    impl_->removeStyles = remove;
}

void HtmlExtractor::setRemoveNavigation(bool remove) {
    impl_->removeNavigation = remove;
}

std::string HtmlExtractor::cleanHtml(const std::string& html) {
    std::string cleaned = html;
    
    std::regex scriptRegex("<script[^>]*>[\\s\\S]*?</script>", std::regex::icase);
    cleaned = std::regex_replace(cleaned, scriptRegex, "");
    
    std::regex styleRegex("<style[^>]*>[\\s\\S]*?</style>", std::regex::icase);
    cleaned = std::regex_replace(cleaned, styleRegex, "");
    
    std::regex commentRegex("<!--[\\s\\S]*?-->");
    cleaned = std::regex_replace(cleaned, commentRegex, "");
    
    std::regex whitespaceRegex("\\s+");
    cleaned = std::regex_replace(cleaned, whitespaceRegex, " ");
    
    return cleaned;
}

std::string HtmlExtractor::htmlToText(const std::string& html) {
    std::string text = impl_->stripTags(html);
    text = impl_->decodeEntities(text);
    text = impl_->normalizeWhitespace(text);
    return text;
}

}
}
