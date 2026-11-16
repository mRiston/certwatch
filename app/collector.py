import socket, ssl, hashlib, json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def _name(n): return ', '.join(f"{a.oid._name or a.oid.dotted_string}={a.value}" for r in n.rdns for a in r)
def collect(e, timeout=10):
    host=str(e['host']).strip(); port=int(e.get('port',443)); key=f"{host.lower()}:{port}"
    base=dict(endpoint_key=key,name=str(e.get('name',key))[:200],host=host[:253],port=port,
              environment=str(e.get('environment','unknown'))[:80],service=str(e.get('service','tls'))[:80],
              scanned_at=datetime.now(timezone.utc).isoformat())
    try:
        # CERT_NONE intentionally permits inventorying expired/private-CA certificates.
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((host,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as tls: der=tls.getpeercert(binary_form=True)
        cert=x509.load_der_x509_certificate(der)
        try: sans=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound: sans=[]
        now=datetime.now(timezone.utc); na=cert.not_valid_after_utc; days=int((na-now).total_seconds()//86400)
        status='expired' if days < 0 else 'critical' if days <=14 else 'warning' if days <=60 else 'healthy'
        return {**base,'success':1,'error_code':None,'subject':_name(cert.subject)[:2000],
          'issuer':_name(cert.issuer)[:2000],'sans_json':json.dumps(sans[:200]),
          'serial_number':format(cert.serial_number,'X'),'fingerprint_sha256':cert.fingerprint(hashes.SHA256()).hex().upper(),
          'not_before':cert.not_valid_before_utc.isoformat(),'not_after':na.isoformat(),'days_remaining':days,'status':status}
    except socket.gaierror: code='dns_failure'
    except (socket.timeout, TimeoutError): code='timeout'
    except ConnectionRefusedError: code='connection_refused'
    except ssl.SSLError: code='tls_error'
    except OSError: code='network_error'
    except Exception: code='collector_error'
    # Deliberately return a bounded code only; never expose raw exceptions to UI/API.
    return {**base,'success':0,'error_code':code,'subject':None,'issuer':None,'sans_json':'[]','serial_number':None,'fingerprint_sha256':None,'not_before':None,'not_after':None,'days_remaining':None,'status':'unreachable'}
