#!/usr/bin/env python3
"""
FacturAR Pro — Backend Cloud v1
Multi-tenant, Render deployment
"""
import os, json, base64, datetime, subprocess, tempfile, ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class LegacySSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)

_session = requests.Session()
_session.mount("https://", LegacySSLAdapter())

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")

SUPABASE_URL         = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
ANTHROPIC_API_KEY    = os.environ.get("ANTHROPIC_API_KEY", "")
ADMIN_EMAIL          = os.environ.get("ADMIN_EMAIL", "contadora@elassad.com")
MODO_PRUEBA          = os.environ.get("MODO_PRUEBA", "false").lower() == "true"
MP_ACCESS_TOKEN      = os.environ.get("MP_ACCESS_TOKEN", "")

WSAA_WSDL = ("https://wsaahomo.afip.gov.ar/ws/services/LoginCms?WSDL" if MODO_PRUEBA
             else "https://wsaa.afip.gov.ar/ws/services/LoginCms?WSDL")
WSFE_WSDL = ("https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL" if MODO_PRUEBA
             else "https://servicios1.afip.gov.ar/wsfev1/service.asmx?WSDL")

_token_cache = {}

# ── SUPABASE ──────────────────────────────────────────────────────────────────
def sb():
    from supabase import create_client
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# ── AUTH ──────────────────────────────────────────────────────────────────────
def verificar_token(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    try:
        user = sb().auth.get_user(auth[7:])
        return user.user.id, user.user.email
    except:
        return None, None

def es_admin(email):
    return email == ADMIN_EMAIL

# ── CERTIFICADOS ──────────────────────────────────────────────────────────────
def get_cert_paths(cuit):
    s = sb()
    try:
        key_data  = s.storage.from_("certificados").download(f"{cuit}/privada.key")
        cert_data = s.storage.from_("certificados").download(f"{cuit}/certificado.crt")
    except Exception as e:
        raise Exception(f"Certificados no encontrados para CUIT {cuit}: {e}")
    kf = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
    cf = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)
    kf.write(key_data); kf.close()
    cf.write(cert_data); cf.close()
    return kf.name, cf.name

def cleanup(*paths):
    for p in paths:
        try: os.unlink(p)
        except: pass

# ── WSAA ──────────────────────────────────────────────────────────────────────
def wsaa_token(cuit, key_path, cert_path):
    cached = _token_cache.get(cuit)
    if cached and cached["expiry"] > datetime.datetime.utcnow():
        return cached["token"], cached["sign"]

    ahora_ar  = datetime.datetime.utcnow() - datetime.timedelta(hours=3)
    expira_ar = ahora_ar + datetime.timedelta(hours=10)
    uid       = str(int(datetime.datetime.utcnow().timestamp()))

    tra_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<loginTicketRequest version="1.0"><header>'
        '<uniqueId>' + uid + '</uniqueId>'
        '<generationTime>' + ahora_ar.strftime("%Y-%m-%dT%H:%M:%S") + '-03:00</generationTime>'
        '<expirationTime>' + expira_ar.strftime("%Y-%m-%dT%H:%M:%S") + '-03:00</expirationTime>'
        '</header><service>wsfe</service></loginTicketRequest>'
    )

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as f:
        f.write(tra_xml); tra_path = f.name

    cms_path = tra_path + ".cms"
    openssl  = next((c for c in ["/usr/bin/openssl", "/usr/local/bin/openssl", "openssl"]
                     if os.path.exists(c) or c == "openssl"), "openssl")

    res = subprocess.run(
        [openssl, "smime", "-sign", "-signer", cert_path, "-inkey", key_path,
         "-in", tra_path, "-out", cms_path, "-outform", "DER", "-nodetach"],
        capture_output=True
    )
    os.unlink(tra_path)
    if res.returncode != 0:
        raise Exception("OpenSSL error: " + res.stderr.decode())

    with open(cms_path, "rb") as f:
        cms_b64 = base64.b64encode(f.read()).decode()
    os.unlink(cms_path)

    from zeep import Client as Z; from zeep.transports import Transport; import lxml.etree as ET
    resp  = Z(WSAA_WSDL, transport=Transport(session=_session)).service.loginCms(in0=cms_b64)
    root  = ET.fromstring(resp.encode())
    token = root.find(".//token").text
    sign  = root.find(".//sign").text

    _token_cache[cuit] = {"token": token, "sign": sign,
                          "expiry": datetime.datetime.utcnow() + datetime.timedelta(hours=10)}
    return token, sign

# ── WSFE ──────────────────────────────────────────────────────────────────────
def wsfe_emitir(cuit, pv, token, sign, datos):
    from zeep import Client as Z; from zeep.transports import Transport
    wsfe = Z(WSFE_WSDL, transport=Transport(session=_session))
    auth = {"Token": token, "Sign": sign, "Cuit": int(cuit)}
    tipo = datos.get("tipo_cbte", 11)
    ult  = wsfe.service.FECompUltimoAutorizado(Auth=auth, PtoVta=int(pv), CbteTipo=tipo)
    nro  = (ult.CbteNro or 0) + 1
    hoy  = datetime.datetime.now().strftime("%Y%m%d")
    imp  = float(datos.get("importe", 0))
    rc   = str(datos.get("receptor_cuit", "0")).replace("-", "").replace(" ", "")
    det  = {
        "Concepto": 2, "DocTipo": 80 if rc and rc != "0" else 99,
        "DocNro": int(rc) if rc and rc != "0" else 0,
        "CbteDesde": nro, "CbteHasta": nro, "CbteFch": hoy,
        "ImpTotal": imp, "ImpTotConc": 0, "ImpNeto": imp,
        "ImpOpEx": 0, "ImpIVA": 0, "ImpTrib": 0,
        "FchServDesde": hoy, "FchServHasta": hoy, "FchVtoPago": hoy,
        "MonId": "PES", "MonCotiz": 1,
    }
    r = wsfe.service.FECAESolicitar(Auth=auth, FeCAEReq={
        "FeCabReq": {"CantReg": 1, "PtoVta": int(pv), "CbteTipo": tipo},
        "FeDetReq": {"FECAEDetRequest": det}
    })
    d = r.FeDetResp.FECAEDetResponse[0]
    if d.Resultado == "A":
        return {"ok": True, "cae": d.CAE, "cae_vencimiento": d.CAEFchVto, "nro_comprobante": nro}
    obs = [o.Msg for o in d.Observaciones.Obs] if d.Observaciones else []
    return {"ok": False, "errores": obs}

def guardar_factura(cliente_id, datos, resultado):
    sb().table("facturas").insert({
        "cliente_id": cliente_id,
        "fecha": datetime.date.today().isoformat(),
        "nro_comprobante": resultado.get("nro_comprobante"),
        "cae": resultado.get("cae"),
        "importe": datos.get("importe"),
        "concepto": datos.get("concepto"),
        "receptor_nombre": datos.get("receptor_nombre"),
        "receptor_cuit": datos.get("receptor_cuit"),
        "estado": "emitida"
    }).execute()

# ── ENDPOINTS CLIENTE ─────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"ok": True, "modo": "PRUEBA" if MODO_PRUEBA else "PRODUCCION"})

@app.route("/api/cliente/info", methods=["GET"])
def cliente_info():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    res = sb().table("clientes").select("*").eq("user_email", email).single().execute()
    if not res.data: return jsonify({"error": "Cliente no encontrado"}), 404
    return jsonify(res.data)

@app.route("/api/cliente/config", methods=["POST"])
def cliente_config():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    datos = request.json or {}
    campos = {k: datos[k] for k in ["concepto_default", "punto_venta", "historial_monto",
              "categoria_monotributo", "tipo_actividad"] if k in datos}
    sb().table("clientes").update(campos).eq("user_email", email).execute()
    if "historial_monto" in datos:
        c = sb().table("clientes").select("id").eq("user_email", email).single().execute()
        if c.data:
            sb().table("historial_previo").upsert({
                "cliente_id": c.data["id"],
                "anio": datetime.date.today().year,
                "monto_acumulado": datos["historial_monto"]
            }).execute()
    return jsonify({"ok": True})

@app.route("/api/certificado/upload", methods=["POST"])
def upload_certificado():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    datos = request.json or {}
    cuit  = datos.get("cuit", "").replace("-", "").replace(" ", "")
    key_b64  = datos.get("key_b64", "")
    cert_b64 = datos.get("cert_b64", "")
    if not all([cuit, key_b64, cert_b64]):
        return jsonify({"error": "Faltan datos"}), 400
    try:
        s = sb()
        s.storage.from_("certificados").upload(f"{cuit}/privada.key",
            base64.b64decode(key_b64),
            {"content-type": "application/octet-stream", "upsert": "true"})
        s.storage.from_("certificados").upload(f"{cuit}/certificado.crt",
            base64.b64decode(cert_b64),
            {"content-type": "application/octet-stream", "upsert": "true"})
        s.table("clientes").update({"cuit": cuit}).eq("user_email", email).execute()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/emitir", methods=["POST"])
def emitir():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    datos = request.json or {}
    cuit  = datos.get("cuit_emisor", "").replace("-", "").replace(" ", "")
    pv    = datos.get("punto_venta", "2")
    kp = cp = None
    try:
        kp, cp = get_cert_paths(cuit)
        token, sign = wsaa_token(cuit, kp, cp)
        res = wsfe_emitir(cuit, pv, token, sign, datos)
        if res["ok"]:
            c = sb().table("clientes").select("id").eq("user_email", email).single().execute()
            if c.data: guardar_factura(c.data["id"], datos, res)
        return jsonify(res)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if kp: cleanup(kp)
        if cp: cleanup(cp)

@app.route("/api/pagos/pendientes", methods=["GET"])
def pagos_pendientes():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    c = sb().table("clientes").select("id").eq("user_email", email).single().execute()
    if not c.data: return jsonify([])
    res = sb().table("pagos_pendientes").select("*").eq("cliente_id", c.data["id"]).eq("estado", "pendiente").order("created_at", desc=True).execute()
    return jsonify(res.data or [])

@app.route("/api/pagos/aprobar", methods=["POST"])
def aprobar_pago():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    datos   = request.json or {}
    pago_id = datos.get("pago_id")
    s = sb()
    cli = s.table("clientes").select("*").eq("user_email", email).single().execute()
    pago = s.table("pagos_pendientes").select("*").eq("id", pago_id).single().execute()
    if not cli.data or not pago.data:
        return jsonify({"error": "Datos no encontrados"}), 404
    c = cli.data
    kp = cp = None
    try:
        cuit = c["cuit"].replace("-", "").replace(" ", "")
        kp, cp = get_cert_paths(cuit)
        token, sign = wsaa_token(cuit, kp, cp)
        res = wsfe_emitir(cuit, c.get("punto_venta", "2"), token, sign, {
            "importe": pago.data["importe"],
            "concepto": datos.get("concepto", c.get("concepto_default", "Servicios profesionales")),
            "receptor_cuit": pago.data["remitente_cuit"],
            "receptor_nombre": pago.data["remitente_nombre"],
            "tipo_cbte": 11
        })
        if res["ok"]:
            s.table("pagos_pendientes").update({"estado": "aprobado"}).eq("id", pago_id).execute()
            guardar_factura(c["id"], {
                "importe": pago.data["importe"],
                "concepto": datos.get("concepto"),
                "receptor_nombre": pago.data["remitente_nombre"],
                "receptor_cuit": pago.data["remitente_cuit"]
            }, res)
        return jsonify(res)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if kp: cleanup(kp)
        if cp: cleanup(cp)

@app.route("/api/pagos/descartar", methods=["POST"])
def descartar_pago():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    pago_id = (request.json or {}).get("pago_id")
    sb().table("pagos_pendientes").update({"estado": "descartado"}).eq("id", pago_id).execute()
    return jsonify({"ok": True})

@app.route("/api/facturas", methods=["GET"])
def mis_facturas():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    c = sb().table("clientes").select("id").eq("user_email", email).single().execute()
    if not c.data: return jsonify([])
    res = sb().table("facturas").select("*").eq("cliente_id", c.data["id"]).order("fecha", desc=True).execute()
    return jsonify(res.data or [])

@app.route("/api/monotributo/progreso", methods=["GET"])
def monotributo_progreso():
    uid, email = verificar_token(request)
    if not uid: return jsonify({"error": "No autorizado"}), 401
    s = sb()
    c = s.table("clientes").select("*").eq("user_email", email).single().execute()
    if not c.data: return jsonify({"error": "No encontrado"}), 404
    cli = c.data
    categoria = cli.get("categoria_monotributo", "A")
    tipo_act  = cli.get("tipo_actividad", "servicios")
    cat = s.table("categorias_monotributo").select("*").eq("categoria", categoria).eq("tipo", tipo_act).order("vigencia_desde", desc=True).limit(1).execute()
    limite = cat.data[0]["limite_anual"] if cat.data else 0
    anio = datetime.date.today().year
    facts = s.table("facturas").select("importe").eq("cliente_id", cli["id"]).gte("fecha", f"{anio}-01-01").execute()
    total = sum(f["importe"] for f in (facts.data or []))
    hist  = s.table("historial_previo").select("monto_acumulado").eq("cliente_id", cli["id"]).eq("anio", anio).execute()
    total += hist.data[0]["monto_acumulado"] if hist.data else 0
    falta = limite - total
    return jsonify({
        "categoria": categoria, "limite": limite,
        "total_facturado": total,
        "porcentaje": round(total / limite * 100, 1) if limite else 0,
        "falta": falta, "alerta": 0 < falta <= 1_000_000,
        "excedido": total > limite
    })

# ── ADMIN ─────────────────────────────────────────────────────────────────────
@app.route("/api/admin/clientes", methods=["GET"])
def admin_clientes():
    uid, email = verificar_token(request)
    if not uid or not es_admin(email): return jsonify({"error": "No autorizado"}), 401
    s = sb()
    clientes = s.table("clientes").select("*").execute().data or []
    anio = datetime.date.today().year
    mes  = datetime.date.today().month
    for c in clientes:
        fs = s.table("facturas").select("importe").eq("cliente_id", c["id"]).gte("fecha", f"{anio}-{mes:02d}-01").execute()
        c["facturas_mes"] = len(fs.data or [])
        c["total_mes"]    = sum(f["importe"] for f in (fs.data or []))
    return jsonify(clientes)

@app.route("/api/admin/cliente/toggle", methods=["POST"])
def toggle_cliente():
    uid, email = verificar_token(request)
    if not uid or not es_admin(email): return jsonify({"error": "No autorizado"}), 401
    datos = request.json or {}
    sb().table("clientes").update({"activo": datos.get("activo", True)}).eq("id", datos.get("cliente_id")).execute()
    return jsonify({"ok": True})

@app.route("/api/admin/monotributo/actualizar", methods=["POST"])
def actualizar_monotributo():
    uid, email = verificar_token(request)
    if not uid or not es_admin(email): return jsonify({"error": "No autorizado"}), 401
    datos = request.json or {}
    img   = datos.get("imagen_b64")
    if not img or not ANTHROPIC_API_KEY: return jsonify({"error": "Faltan datos"}), 400
    import anthropic
    ai = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    r = ai.messages.create(model="claude-sonnet-4-20250514", max_tokens=2000,
        messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": datos.get("media_type", "image/jpeg"), "data": img}},
            {"type": "text", "text": (
                'Extraé la tabla de categorías del monotributo argentino de esta imagen. '
                'Respondé SOLO JSON válido: {"vigencia":"2025","categorias":['
                '{"categoria":"A","tipo":"servicios","limite_anual":3700000},'
                '{"categoria":"A","tipo":"bienes","limite_anual":5550000}]}'
            )}
        ]}]
    )
    texto = r.content[0].text.strip().replace("```json","").replace("```","").strip()
    try:
        res = json.loads(texto)
        s   = sb()
        vig = f"{res['vigencia']}-01-01"
        for cat in res["categorias"]:
            s.table("categorias_monotributo").upsert({
                "categoria": cat["categoria"], "tipo": cat["tipo"],
                "limite_anual": cat["limite_anual"], "vigencia_desde": vig
            }).execute()
        return jsonify({"ok": True, "categorias_cargadas": len(res["categorias"])})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "raw": texto}), 500

# ── WEBHOOKS ──────────────────────────────────────────────────────────────────
@app.route("/webhook/mercadopago", methods=["POST"])
def webhook_mp():
    data = request.json or {}
    if data.get("type") != "payment": return jsonify({"ok": True})
    payment_id = data.get("data", {}).get("id")
    if not payment_id or not MP_ACCESS_TOKEN: return jsonify({"ok": True})
    try:
        r = requests.get(f"https://api.mercadopago.com/v1/payments/{payment_id}",
                         headers={"Authorization": f"Bearer {MP_ACCESS_TOKEN}"})
        pago = r.json()
        if pago.get("status") != "approved": return jsonify({"ok": True})
        s = sb()
        mp_id = str(pago.get("collector", {}).get("id", ""))
        cli   = s.table("clientes").select("id").eq("mp_user_id", mp_id).execute()
        if not cli.data: return jsonify({"ok": True})
        payer = pago.get("payer", {})
        s.table("pagos_pendientes").insert({
            "cliente_id": cli.data[0]["id"], "origen": "mercadopago",
            "remitente_nombre": f"{payer.get('first_name','')} {payer.get('last_name','')}".strip(),
            "remitente_cuit": payer.get("identification", {}).get("number", ""),
            "importe": pago.get("transaction_amount", 0),
            "referencia": str(payment_id)
        }).execute()
    except Exception as e:
        print(f"[MP Error] {e}")
    return jsonify({"ok": True})

@app.route("/webhook/lemon", methods=["POST"])
def webhook_lemon():
    data = request.json or {}
    if data.get("event") != "transfer.received": return jsonify({"ok": True})
    try:
        s   = sb()
        cli = s.table("clientes").select("id").eq("lemon_account_id", data.get("account_id","")).execute()
        if not cli.data: return jsonify({"ok": True})
        t = data.get("transfer", {})
        s.table("pagos_pendientes").insert({
            "cliente_id": cli.data[0]["id"], "origen": "lemon",
            "remitente_nombre": t.get("sender_name", ""),
            "remitente_cuit": t.get("sender_cuit", ""),
            "importe": t.get("amount", 0),
            "referencia": t.get("id", "")
        }).execute()
    except Exception as e:
        print(f"[Lemon Error] {e}")
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
