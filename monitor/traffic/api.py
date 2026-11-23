"""Flask routes of the Traffic Analyzer (/api/traffic/*). All admin-only: they expose IP addresses, host names and process names."""
import csv
import io
import ipaddress
import os
import time

from flask import jsonify, request, send_file, Response

from . import store, notify
from . import manager as _M
from .manager import get_manager, interfaces

PAGE = 30
SORTS = {"bytes_desc": ("bytes", True), "bytes_asc": ("bytes", False), "packets_desc": ("packets", True), "packets_asc": ("packets", False),
         "last_desc": ("last", True), "last_asc": ("last", False), "first_desc": ("first", True), "first_asc": ("first", False)}


def _match(value, q):
    """Sniffnet search: case-insensitive substring; a leading '=' means exact match."""
    if not q: return True
    v = "" if value is None else str(value).lower(); q = q.lower()
    return v == q[1:] if q.startswith("=") else q in v


def _csv_cell(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s       # neutralise spreadsheet formula injection


def _dsum(d):
    return {"in_bytes": d[0], "out_bytes": d[1], "in_packets": d[2], "out_packets": d[3], "bytes": d[0] + d[1], "packets": d[2] + d[3]}


def register(app, require_admin, current_email, audit):
    G = lambda: get_manager()

    def guard():
        return require_admin()

    def eng_or_404():
        e = G().engine
        return e

    def favs():
        f = {"host": set(), "service": set(), "program": set()}
        for r in store.list_favorites(): f.setdefault(r["kind"], set()).add(r["value"])
        return f

    def device_map():
        from .. import config_manager as cm
        m = {}
        for d in cm.get_config().get("devices", []):
            h = str(d.get("host", "")).strip()
            if h: m[h] = d.get("name") or d.get("id")
        return m

    # ---------------------------------------------------------------- control
    @app.route("/api/traffic/status")
    def tr_status():
        e = guard()
        if e: return e
        m = G()
        try:
            s = m.status(); s["settings"] = m.settings(); s["notifications_emitted"] = getattr(getattr(m.engine, "notifier", None), "emitted", 0) if m.engine else 0
            n = store.list_notifications(1); s["latest_notification_id"] = n[0]["id"] if n else 0
        except Exception as ex:      # V12.4: never answer 500 -- the page would silently show 'Idle' with no Stop button
            import logging; logging.getLogger("netmon.traffic").exception("traffic status failed")
            s = {"state": m.state, "error": f"Status could not be read completely: {type(ex).__name__}: {ex}", "source": m.source or {}, "settings": {}, "latest_notification_id": 0, "status_degraded": True}
        return jsonify(s)

    @app.route("/api/traffic/interfaces")
    def tr_interfaces():
        e = guard()
        if e: return e
        return jsonify({"interfaces": interfaces()})

    @app.route("/api/traffic/start", methods=["POST"])
    def tr_start():
        e = guard()
        if e: return e
        b = request.get_json(force=True) or {}
        try:
            st = G().start(b)
        except (ValueError, RuntimeError) as ex:
            return jsonify({"ok": False, "error": str(ex)}), 400
        audit(current_email(), "traffic_start", b.get("type", ""), f"{b.get('iface') or b.get('path') or b.get('port') or ''} {b.get('bpf', '')}".strip())
        return jsonify({"ok": True, "status": st})

    @app.route("/api/traffic/stop", methods=["POST"])
    def tr_stop():
        e = guard()
        if e: return e
        audit(current_email(), "traffic_stop", "", "")
        return jsonify({"ok": True, "status": G().stop()})

    @app.route("/api/traffic/reset", methods=["POST"])
    def tr_reset():
        e = guard()
        if e: return e
        audit(current_email(), "traffic_reset", "", "")
        return jsonify({"ok": True, "status": G().reset()})

    @app.route("/api/traffic/pause", methods=["POST"])
    def tr_pause():
        e = guard()
        if e: return e
        on = bool((request.get_json(silent=True) or {}).get("on", True))
        return jsonify({"ok": True, "status": G().pause(on)})

    @app.route("/api/traffic/pcap-upload", methods=["POST"])
    def tr_pcap_upload():
        e = guard()
        if e: return e
        f = request.files.get("file")
        if not f: return jsonify({"ok": False, "error": "No file received."}), 400
        if (request.content_length or 0) > 500 * 1024 * 1024: return jsonify({"ok": False, "error": "Capture files are limited to 500 MB."}), 413
        os.makedirs(os.path.join(_M.DATA_DIR, "uploads"), exist_ok=True)
        from werkzeug.utils import secure_filename
        safe = secure_filename(f.filename or "") or "capture.pcap"          # keep the user's file name so History is readable
        path = os.path.join(_M.DATA_DIR, "uploads", f"{int(time.time())}-{safe}")
        f.save(path)
        with open(path, "rb") as fh: magic = fh.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
            os.remove(path); return jsonify({"ok": False, "error": "This is not a pcap / pcapng capture file."}), 400
        return jsonify({"ok": True, "path": path, "size": os.path.getsize(path)})

    # ---------------------------------------------------------------- live views
    def build_overview(top, sort, n):
        eng = eng_or_404()
        if not eng: return {"active": False}
        key = (lambda d: d["packets"]) if sort == "packets" else (lambda d: d["bytes"])
        fv = favs(); dm = device_map()
        hosts = []
        for h in eng.hosts():
            d = _dsum(h["d"]); dev = next((dm[a] for a in h["addresses"] if a in dm), None)
            hosts.append(dict(d, name=h["name"], domain=h["domain"], asn=h["asn"], asn_name=h["asn_name"], country=h["country"], country_name=h["country_name"],
                              local=h["local"], bogon=h["bogon"], traffic_type=h["traffic_type"], addresses=h["addresses"][:3], n_addresses=len(h["addresses"]),
                              favorite=h["name"] in fv["host"] or any(a in fv["host"] for a in h["addresses"]), device=dev))
        hosts.sort(key=key, reverse=True)
        with eng.lock:
            services = sorted(({"name": k, **_dsum(v), "favorite": k in fv["service"]} for k, v in eng.services.items()), key=key, reverse=True)
            programs = sorted(({"name": k, **_dsum(v), "favorite": k in fv["program"]} for k, v in eng.progs.items()), key=key, reverse=True)
        countries = sorted(({"code": c["code"], "name": c["name"], "hosts": c["hosts"], **_dsum(c["d"])} for c in eng.countries()), key=key, reverse=True)
        from . import services as S
        for s_ in services: s_["category"] = S.category(s_["name"])
        t = eng.totals()
        return {"active": True, "state": G().state, "totals": _dsum(t["tot"]), "connections": t["connections"], "hosts_count": t["hosts"], "blacklisted": t["blacklisted"],
                "last_second": _dsum(t["last_second"]), "series": [{"t": x[0], "in_bytes": x[1], "out_bytes": x[2], "in_packets": x[3], "out_packets": x[4]} for x in eng.recent_series(n)],
                "hosts": hosts[:top], "services": services[:top], "programs": programs[:top], "countries": countries[:top],
                "n_hosts": len(hosts), "n_services": len(services), "n_programs": len(programs), "n_countries": len(countries), "elapsed": time.time() - eng.started}

    @app.route("/api/traffic/overview")
    def tr_overview():
        e = guard()
        if e: return e
        return jsonify(build_overview(int(request.args.get("top", 10)), request.args.get("sort", "bytes"), int(request.args.get("series", 120))))

    @app.route("/api/traffic/list/<kind>")
    def tr_list(kind):
        """Full sortable lists: hosts | services | programs | countries"""
        e = guard()
        if e: return e
        if kind not in ("hosts", "services", "programs", "countries"): return jsonify({"error": "unknown list"}), 404
        full = build_overview(100000, request.args.get("sort", "bytes"), 1)
        return jsonify({"items": full.get(kind, []), "total": full.get("n_" + kind, 0)})

    @app.route("/api/traffic/connections")
    def tr_connections():
        e = guard()
        if e: return e
        eng = eng_or_404(); a = request.args
        if not eng: return jsonify({"items": [], "total": 0, "page": 1, "pages": 1})
        fv = favs(); dm = device_map(); rows = []
        with eng.lock: conns = list(eng.conns.values())
        q = a.get("q", "").strip(); only_fav = a.get("favorite") == "1"; only_bl = a.get("blacklisted") == "1"
        for c in conns:
            h = eng.host_of(c.addr)
            if a.get("direction") and c.direction != a["direction"]: continue
            if a.get("proto") and not _match(c.key.proto, a["proto"]): continue
            if a.get("service") and not _match(c.service, a["service"]): continue
            if a.get("app") and not _match(c.program, a["app"]): continue
            if a.get("domain") and not (_match(h["name"], a["domain"]) or _match(h["domain"], a["domain"])): continue
            if a.get("country") and not _match(h["country"], a["country"]): continue          # ISO code, exactly like Sniffnet
            if a.get("asn") and not (_match(h["asn_name"], a["asn"]) or _match(h["asn"], a["asn"])): continue
            if a.get("ip") and not (_match(c.key.src_ip, a["ip"]) or _match(c.key.dst_ip, a["ip"])): continue
            if a.get("port") and not (_match(c.key.src_port, a["port"]) or _match(c.key.dst_port, a["port"])): continue
            if only_bl and not c.blacklisted: continue
            fav = c.service in fv["service"] or (c.program in fv["program"] if c.program else False) or h["name"] in fv["host"] or c.addr in fv["host"]
            if only_fav and not fav: continue
            if q and not any(_match(x, q) for x in (c.key.src_ip, c.key.dst_ip, c.key.src_port, c.key.dst_port, c.key.proto, c.service, c.program, h["name"], h["country"], h["country_name"], h["asn_name"], h["asn"])): continue
            d = c.as_dict(); d.update(host=h["name"], domain=h["domain"], country=h["country"], country_name=h["country_name"], asn=h["asn"], asn_name=h["asn_name"],
                                       local=h["local"], bogon=h["bogon"], favorite=fav, device=dm.get(c.key.src_ip) or dm.get(c.key.dst_ip))
            rows.append(d)
        field, rev = SORTS.get(a.get("sort", "bytes_desc"), SORTS["bytes_desc"])
        rows.sort(key=lambda r: r[field], reverse=rev)
        size = max(1, min(200, int(a.get("page_size", PAGE)))); pages = max(1, -(-len(rows) // size)); page = max(1, min(pages, int(a.get("page", 1))))
        return jsonify({"items": rows[(page - 1) * size: page * size], "total": len(rows), "page": page, "pages": pages, "page_size": size})

    @app.route("/api/traffic/connections/<int:cid>")
    def tr_conn(cid):
        e = guard()
        if e: return e
        eng = eng_or_404(); c = eng._by_id.get(cid) if eng else None
        if not c: return jsonify({"error": "Connection not found (the capture may have been restarted)."}), 404
        h = eng.host_of(c.addr); d = c.as_dict(); dm = device_map()
        d.update(host=h["name"], domain=h["domain"], country=h["country"], country_name=h["country_name"], asn=h["asn"], asn_name=h["asn_name"], local=h["local"], bogon=h["bogon"],
                 device=dm.get(c.key.src_ip) or dm.get(c.key.dst_ip), duration=max(0, c.last - c.first))
        from . import services as S
        d["category"] = S.category(c.service)
        return jsonify(d)

    @app.route("/api/traffic/connections/<int:cid>/latency", methods=["POST"])
    def tr_latency(cid):
        e = guard()
        if e: return e
        eng = eng_or_404(); c = eng._by_id.get(cid) if eng else None
        if not c: return jsonify({"error": "Connection not found."}), 404
        try: ipaddress.ip_address(c.addr)
        except ValueError: return jsonify({"error": "Invalid address."}), 400
        r = G().latency(c.addr)
        return jsonify({"ip": c.addr, "reachable": r.get("reachable"), "latency_ms": r.get("latency_ms"), "packet_loss_pct": r.get("packet_loss_pct"), "error": r.get("error")})

    # ---------------------------------------------------------------- favorites / notifications / settings
    @app.route("/api/traffic/favorites", methods=["GET", "POST", "DELETE"])
    def tr_favorites():
        e = guard()
        if e: return e
        if request.method == "GET": return jsonify({"favorites": store.list_favorites()})
        b = request.get_json(force=True) or {}; kind, value = b.get("kind"), str(b.get("value") or "").strip()
        if kind not in ("host", "service", "program") or not value: return jsonify({"ok": False, "error": "kind must be host, service or program, and value is required."}), 400
        if request.method == "POST": store.add_favorite(kind, value, b.get("label", ""))
        else: store.delete_favorite(kind, value)
        return jsonify({"ok": True, "favorites": store.list_favorites()})

    @app.route("/api/traffic/notifications/settings", methods=["GET", "POST"])
    def tr_notif_settings():
        e = guard()
        if e: return e
        if request.method == "POST":
            try: s = notify.save_settings(request.get_json(force=True) or {})
            except ValueError as ex: return jsonify({"ok": False, "error": str(ex)}), 400
            audit(current_email(), "traffic_notification_settings", "", "")
            return jsonify({"ok": True, "settings": s})
        return jsonify({"settings": notify.get_settings(), "sounds": list(notify.SOUNDS)})

    @app.route("/api/traffic/notifications/log", methods=["GET", "DELETE"])
    def tr_notif_log():
        e = guard()
        if e: return e
        if request.method == "DELETE":
            store.clear_notifications(); return jsonify({"ok": True})
        since = int(request.args.get("since", 0)); items = store.list_notifications(int(request.args.get("limit", 100)))
        return jsonify({"items": [i for i in items if i["id"] > since]})

    @app.route("/api/traffic/notifications/test", methods=["POST"])
    def tr_notif_test():
        e = guard()
        if e: return e
        s = notify.get_settings(); n = notify.Notifier(lambda: G().sid, store.list_favorites)
        n.emit("test", "Test notification", "This is a test from Net-monit Traffic.", {}, "pop", s)
        return jsonify({"ok": True})

    @app.route("/api/traffic/settings", methods=["GET", "POST"])
    def tr_settings():
        e = guard()
        if e: return e
        m = G()
        if request.method == "POST":
            b = request.get_json(force=True) or {}
            for k in ("country_db", "asn_db", "blacklist"):
                p = str(b.get(k) or "").strip()
                if p and not os.path.isfile(p): return jsonify({"ok": False, "error": f"File not found: {p}"}), 400
            s = m.save_settings(b); audit(current_email(), "traffic_settings", "", "")
            return jsonify({"ok": True, "settings": s, "geo": m.geo.status(), "blacklist": m.blacklist_status(), "error": m.error})
        m._prepare()
        return jsonify({"settings": m.settings(), "geo": m.geo.status(), "blacklist": m.blacklist_status()})

    @app.route("/api/traffic/blacklist-upload", methods=["POST"])
    def tr_bl_upload():
        e = guard()
        if e: return e
        f = request.files.get("file")
        if not f: return jsonify({"ok": False, "error": "No file received."}), 400
        os.makedirs(_M.DATA_DIR, exist_ok=True); path = os.path.join(_M.DATA_DIR, "ip_blacklist.txt"); f.save(path)
        s = get_manager().save_settings({"blacklist": path}); m = G()
        return jsonify({"ok": True, "entries": m.blacklist_status()["entries"], "path": path})

    # ---------------------------------------------------------------- history & exports
    @app.route("/api/traffic/sessions")
    def tr_sessions():
        e = guard()
        if e: return e
        return jsonify({"sessions": store.list_sessions(int(request.args.get("limit", 50)))})

    @app.route("/api/traffic/sessions/<int:sid>", methods=["GET", "DELETE"])
    def tr_session(sid):
        e = guard()
        if e: return e
        if request.method == "DELETE":
            if G().sid == sid and G().state in ("running", "paused"): return jsonify({"ok": False, "error": "Stop the capture first."}), 400
            store.delete_session(sid); return jsonify({"ok": True})
        s = store.get_session(sid)
        if not s: return jsonify({"error": "Not found"}), 404
        return jsonify({"session": s, "minutes": store.get_minutes(sid), "connections": store.get_conns(sid, int(request.args.get("limit", 200)))})

    def _rows_for(sid):
        eng = G().engine
        if sid in (None, G().sid) and eng:
            out = []
            for c in sorted(list(eng.conns.values()), key=lambda i: -i.bytes):
                h = eng.host_of(c.addr); d = c.as_dict(); d.update(host=h["name"], country=h["country"], asn=h["asn"], asn_name=h["asn_name"]); out.append(d)
            return out
        return store.get_conns(sid, 100000) if sid else []

    @app.route("/api/traffic/export/report.csv")
    def tr_report():
        e = guard()
        if e: return e
        sid = request.args.get("session", type=int)
        rows = _rows_for(sid)
        buf = io.StringIO(); w = csv.writer(buf)
        w.writerow(["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "direction", "service", "bytes", "packets", "first_seen", "last_seen", "remote_host", "country", "asn", "as_name", "program", "blacklisted"])
        iso = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""
        for r in rows:
            w.writerow([_csv_cell(x) for x in (r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"], r["proto"], r["direction"], r["service"], r["bytes"], r["packets"],
                                               iso(r["first"] if "first" in r else r.get("first_ts")), iso(r["last"] if "last" in r else r.get("last_ts")),
                                               r.get("host", ""), r.get("country", ""), r.get("asn", ""), r.get("asn_name", ""), r.get("program") or "", 1 if r.get("blacklisted") else 0)])
        return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=net-monit-traffic-report.csv"})

    @app.route("/api/traffic/export/capture.pcap")
    def tr_pcap():
        e = guard()
        if e: return e
        sid = request.args.get("session", type=int) or G().sid
        s = store.get_session(sid) if sid else None
        p = (s or {}).get("pcap_path")
        if not p or not os.path.isfile(p) or not os.path.abspath(p).startswith(os.path.abspath(_M.DATA_DIR)):
            return jsonify({"error": "No packet capture was saved for this session (enable 'Save packets to a .pcap file' when starting)."}), 404
        return send_file(p, as_attachment=True, download_name=f"net-monit-capture-{sid}.pcap")
