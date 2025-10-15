import os
import io
import hashlib
import datetime as dt
import time
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file, url_for, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle

from secrets import token_urlsafe


import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod

from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# For logging purposes
import logging

# --- Security Logger Setup ---
logger = logging.getLogger("tatou-security")
handler = logging.FileHandler("/app/logs/security.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def log_event(event, user=None, status="INFO", **extra):
    """Helper for structured security logging."""
    ip = request.remote_addr if request else "N/A"
    msg = f"event={event}, user={user}, ip={ip}, status={status}"
    if extra:
        try:
            msg += f", details={extra}"
        except Exception:
            # be defensive—logging must never crash the handler
            pass
    logger.info(msg)



def create_app():
    app = Flask(__name__)

    # --- Config ---
    # app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change") # Probably still unsafe. 

    # In production: must come from env. In dev: generate ephemeral key if missing.
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        app.config["SECRET_KEY"] = env_secret
    else:
        # Dev fallback only – ephemeral; all tokens invalid on restart.
        app.config["SECRET_KEY"] = token_urlsafe(64)
        app.logger.warning("SECRET_KEY missing; generated ephemeral key (development only).")
    
    app.config["SIGNING_SALT"] = os.environ.get("TATOU_SIGNING_SALT", "tatou-auth-v1")

    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # Where the distributable PDF lives inside the container (RMAP)
    app.config["RMAP_PDF_PATH"] = os.environ.get("RMAP_PDF_PATH", "/app/storage/handout.pdf")
    # Link lifetime (seconds) (RMAP)
    app.config["RMAP_LINK_TTL"] = int(os.environ.get("RMAP_LINK_TTL", "600"))
    # In-memory token store: token -> expiry epoch (RMAP)
    app.config["RMAP_TOKENS"] = {}

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    #def _serializer():
        #return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth") # Salt
    
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt=app.config["SIGNING_SALT"])

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    # Health checks (support both paths)
    @app.get("/healthz")
    @app.get("/api/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            log_event("user-create-missing-fields", user=email or "unknown", status="FAIL")
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            log_event("user-create-duplicate", user=email, status="FAIL")
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            log_event("user-create-db-error", user=email, status="ERROR")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        log_event("user-create-success", user=email, status="OK")
        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {email, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            log_event("login-failed", user=email, status="FAIL")
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        log_event("login-success", user=email, status="OK")
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            log_event("document-upload-missing-file", user=g.user["email"], status="FAIL")
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            log_event("document-upload-empty-filename", user=g.user["email"], status="FAIL")
            return jsonify({"error": "empty filename"}), 400

        fname = file.filename

        # Ensure STORAGE_DIR is Path and use string for file.save()
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        user_dir = storage_root / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(str(stored_path))

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            log_event("document-upload-db-error", user=g.user["email"], status="ERROR", details={"filename": fname})
            return jsonify({"error": f"database error: {str(e)}"}), 503

        log_event(
            "document-upload-success",
            user=g.user["email"],
            status="OK",
            details={"filename": fname, "sha256": sha_hex, "size": size}
        )

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):

        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if str(row.link).lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<int:document_id>", methods=["DELETE"])  # force int in path
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if document_id is None:
            raw = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        else:
            raw = document_id

        # validate & cast
        try:
            doc_id = int(raw)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400

        # parameterized SELECT (no string concatenation)
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, path, ownerid FROM Documents WHERE id = :id"),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # optional: enforce ownership
        if int(row.ownerid) != int(g.user["id"]):
            return jsonify({"error": "not your document"}), 403

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # parameterized DELETE
        try:
            with get_engine().begin() as conn:
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200

    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on GET
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token = sha1(watermarked_file_name)
        link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201

    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
        storage_root = Path(app.config["STORAGE_DIR"])
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = plugins_dir / filename
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {filename}"}), 404

        # Unpickle the object (dill if available; else std pickle)
        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        # Accept: class object, or instance (we'll promote instance to its class)
        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        # Determine method name for registry
        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

        # Validate interface: either subclass of WatermarkingMethod or duck-typing
        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400

        # Register the class (not an instance) so you can instantiate as needed later
        WMUtils.METHODS[method_name] = cls()

        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201

    # GET /api/get-watermarking-methods
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []
        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document
        try:
            with get_engine().connect() as conn:
                row_doc = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()

                row_ver = conn.execute(
                    text("""
                        SELECT path
                        FROM Versions
                        WHERE documentid = :id
                        ORDER BY id DESC
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()

        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row_doc:
            return jsonify({"error": "document not found"}), 404

        # Prefer version file if present, else original document file
        file_path = Path(row_ver.path) if row_ver else Path(row_doc.path)

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400

        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

    # ====================== RMAP: setup + endpoints ======================

    app.config.setdefault("RMAP_PDF_PATH", os.environ.get("RMAP_PDF_PATH", "/app/storage/handout.pdf"))
    app.config.setdefault("RMAP_LINK_TTL", int(os.environ.get("RMAP_LINK_TTL", "600")))
    app.config.setdefault("RMAP_TOKENS", {})  # token -> expiry (epoch seconds)

    # Key paths
    SERVER_DIR = Path(__file__).resolve().parents[1]   # /app/server
    DEFAULT_KEYS_DIR = SERVER_DIR / "keys"
    rmap_keys_dir = Path(os.environ.get("RMAP_KEYS_DIR", str(DEFAULT_KEYS_DIR))).resolve()
    clients_dir = rmap_keys_dir / "clients"
    server_pub  = rmap_keys_dir / "server_public.asc"
    server_priv = rmap_keys_dir / "server_private.asc"
    server_priv_pass = os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE")

    # Initialize RMAP
    missing = [p for p in (clients_dir, server_pub, server_priv) if not p.exists()]
    if missing:
        app.logger.error("RMAP key path(s) missing: %s", ", ".join(map(str, missing)))
        app.config["RMAP"] = None
    else:
        try:
            im = IdentityManager(
                client_keys_dir=clients_dir,
                server_public_key_path=server_pub,
                server_private_key_path=server_priv,
                server_private_key_passphrase=server_priv_pass,
            )
            app.config["RMAP"] = RMAP(im)
            app.logger.info("RMAP initialized (clients dir: %s)", clients_dir)
        except Exception as e:
            app.logger.exception("Failed to initialize RMAP: %s", e)
            app.config["RMAP"] = None

    # Helper: mint a one-time, time-limited download link from RMAP result
    def _rmap_make_link(result_hex: str) -> dict:
        token = result_hex.lower()
        expires = int(time.time()) + app.config["RMAP_LINK_TTL"]
        app.config["RMAP_TOKENS"][token] = expires
        return {
            "link": url_for("rmap_download", token=token, _external=True),
            "expires": expires,
        }

    # Message 1 -> Response 1
    @app.post("/rmap-initiate")
    def rmap_initiate():
        rmap = app.config.get("RMAP")
        if rmap is None:
            return jsonify({"error": "RMAP not initialized"}), 503
        body = request.get_json(silent=True) or {}
        if "payload" not in body:
            return jsonify({"error": "payload is required"}), 400
        try:
            out = rmap.handle_message1(body)  # {"payload": "..."} or {"error": "..."}
            return jsonify(out), (200 if "payload" in out else 400)
        except Exception as e:
            app.logger.exception("rmap-initiate failed: %s", e)
            return jsonify({"error": "server error"}), 500

    # Message 2 -> one-time link
    @app.post("/rmap-get-link")
    def rmap_get_link():
        rmap = app.config.get("RMAP")
        if rmap is None:
            return jsonify({"error": "RMAP not initialized"}), 503
        body = request.get_json(silent=True) or {}
        if "payload" not in body:
            return jsonify({"error": "payload is required"}), 400
        try:
            out = rmap.handle_message2(body)  # {"result": "<32-hex>"} or {"error": "..."}
            if "result" not in out:
                return jsonify(out), 400
            return jsonify(_rmap_make_link(out["result"])), 200
        except Exception as e:
            app.logger.exception("rmap-get-link failed: %s", e)
            return jsonify({"error": "server error"}), 500

    # One-time download endpoint
    @app.get("/rmap-download/<token>")
    def rmap_download(token: str):
        tokens = app.config.get("RMAP_TOKENS", {})
        expires = tokens.pop(token, None)  # one-time use
        if not expires or time.time() > expires:
            abort(404)

        pdf_path = Path(app.config["RMAP_PDF_PATH"])
        if not pdf_path.exists():
            app.logger.error("RMAP_PDF_PATH missing: %s", pdf_path)
            abort(500)

        return send_file(
            str(pdf_path),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="Group_5.pdf",
            max_age=0,
            conditional=False,
            etag=False,
            last_modified=None,
        )

    # ====================== end RMAP section ======================

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
