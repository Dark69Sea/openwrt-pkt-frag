local m, s, o

m = Map("pkt-frag", translate("Advanced Packet Fragmentation"),
    translate("Configure packet fragmentation, TLS ClientHello splitting, QUIC fragmentation, "..
              "random padding, and TLS fingerprint modification to bypass DPI filtering."))

m.on_after_commit = function(self)
    luci.sys.call("/etc/init.d/pkt-frag reload >/dev/null 2>&1")
end

s = m:section(TypedSection, "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

o = s:option(Value, "frag_size", translate("Fragment Size (bytes)"))
o.datatype = "range(64,1400)"
o.default = 512
o.description = translate("Base fragment size for IP fragmentation. Smaller = more obfuscation, more overhead.")

o = s:option(ListValue, "interface", translate("Interface"))
o.default = "wan"
o:value("wan", "WAN")
o:value("lan", "LAN")
o:value("", "All Interfaces")
function o.cfgvalue(self, section)
    return m.uci:get("pkt-frag", section, "interface") or "wan"
end

s = m:section(TypedSection, "global", translate("Protocol Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable_tcp", translate("Fragment TCP"))
o.default = 1
o.rmempty = false

o = s:option(Flag, "enable_udp", translate("Fragment UDP"))
o.default = 1
o.rmempty = false

o = s:option(Flag, "enable_tls_frag", translate("TLS ClientHello Fragmentation"))
o.default = 1
o.rmempty = false
o.description = translate("Split TLS ClientHello into multiple records. Breaks DPI signature matching.")

o = s:option(Value, "tls_record_size", translate("Max TLS Record Size"))
o.datatype = "range(256,16384)"
o.default = 1400
o:depends("enable_tls_frag", "1")
o.description = translate("Maximum size of TLS records after splitting.")

o = s:option(Flag, "enable_quic_frag", translate("QUIC/HTTP3 Fragmentation"))
o.default = 1
o.rmempty = false
o.description = translate("Fragment QUIC Initial packets (UDP 443).")

s = m:section(TypedSection, "global", translate("Padding & Obfuscation"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable_padding", translate("Random Padding"))
o.default = 1
o.rmempty = false
o.description = translate("Add random bytes to packets to defeat length-based analysis.")

o = s:option(Value, "padding_min", translate("Min Padding (bytes)"))
o.datatype = "range(0,255)"
o.default = 0
o:depends("enable_padding", "1")

o = s:option(Value, "padding_max", translate("Max Padding (bytes)"))
o.datatype = "range(0,255)"
o.default = 64
o:depends("enable_padding", "1")

s = m:section(TypedSection, "global", translate("TLS Fingerprint Modification"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable_fingerprint", translate("Enable Fingerprint Spoofing"))
o.default = 1
o.rmempty = false
o.description = translate("Modify TLS ClientHello cipher suites, extensions to mimic browsers.")

o = s:option(ListValue, "fingerprint_profile", translate("Fingerprint Profile"))
o.default = "chrome"
o:value("chrome", "Chrome")
o:value("firefox", "Firefox")
o:value("safari", "Safari")
o:value("edge", "Edge")
o:value("curl", "cURL")
o:value("random", "Random (Rotate)")
o:depends("enable_fingerprint", "1")

o = s:option(Value, "rotate_interval", translate("Rotation Interval (seconds)"))
o.datatype = "uinteger"
o.default = 3600
o:depends("fingerprint_profile", "random")
o.description = translate("How often to rotate fingerprint profile (0 = disable).")

s = m:section(TypedSection, "global", translate("Advanced"))
s.anonymous = true
s.addremove = false

o = s:option(DummyValue, "_status", translate("Module Status"))
o.template = "pkt-frag/status"

o = s:option(Button, "_apply", translate("Apply & Reload"))
o.inputtitle = translate("Apply Changes")
o.inputstyle = "apply"
function o.write(self, section)
    luci.sys.call("/etc/init.d/pkt-frag reload >/dev/null 2>&1")
end

return m