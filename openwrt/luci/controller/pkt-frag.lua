module("luci.controller.pkt-frag", package.seeall)

function index()
    entry({"admin", "network", "pkt-frag"}, cbi("pkt-frag"), _("Packet Fragmentation"), 60)
    entry({"admin", "network", "pkt-frag", "status"}, call("action_status")).leaf = true
    entry({"admin", "network", "pkt-frag", "apply"}, call("action_apply")).leaf = true
end

function action_status()
    local sys = require "luci.sys"
    local uci = require "luci.model.uci".cursor()
    
    local status = {
        running = sys.call("pgrep -f pkt-frag-daemon >/dev/null 2>&1") == 0,
        module_loaded = sys.call("lsmod | grep -q pkt_frag") == 0,
        params = {},
        stats = {}
    }
    
    local params = {"enabled", "frag_size", "enable_tcp", "enable_udp", "enable_tls_frag", 
                    "enable_quic_frag", "enable_padding", "padding_min", "padding_max",
                    "enable_fingerprint", "tls_record_size"}
    
    for _, p in ipairs(params) do
        local val = sys.exec("cat /sys/module/pkt_frag/parameters/" .. p .. " 2>/dev/null")
        status.params[p] = val and val:match("^%s*(.-)%s*$") or "N/A"
    end
    
    local stats = sys.exec("cat /proc/net/pkt_frag_stats 2>/dev/null")
    if stats and #stats > 0 then
        for line in stats:gmatch("[^\n]+") do
            local k, v = line:match("(%S+):%s*(%S+)")
            if k and v then status.stats[k] = v end
        end
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(status)
end

function action_apply()
    local uci = require "luci.model.uci".cursor()
    uci:load("pkt-frag")
    uci:commit("pkt-frag")
    luci.sys.call("/etc/init.d/pkt-frag reload >/dev/null 2>&1")
    luci.http.prepare_content("application/json")
    luci.http.write_json({success = true})
end