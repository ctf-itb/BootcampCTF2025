import secrets
from pathlib import Path
from flask import Blueprint, jsonify, request, current_app, send_from_directory
from db import get_conn
from pg8000.native import literal
from werkzeug.utils import secure_filename

api_bp = Blueprint("api", __name__)

ALLOWED_EXTS = {"png", "jpg", "jpeg", "gif", "webp"}

# for compatibility with JavaScript
def get_param(name, default=None):
    values = request.args.getlist(name)
    if not values:
        return default
    if len(values) == 1:
        return values[0]
    return values

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS


@api_bp.post("/images")
def upload_image():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "missing file"}), 400
    file = request.files["file"]
    title = request.form.get("title")

    if file.filename == "" or not allowed_file(file.filename):
        return jsonify({"ok": False, "error": "invalid filename or type"}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    rand = secrets.token_hex(8)
    stored = f"{rand}.{ext}"

    upload_dir = Path(current_app.config["UPLOAD_DIR"])
    path = upload_dir / stored
    file.save(path)

    size_bytes = path.stat().st_size
    content_type = file.mimetype or "image/png"

    conn = get_conn()
    try:
        res = conn.run(
            f"INSERT INTO images (filename, title, content_type, size_bytes) VALUES ({literal(stored)}, {literal(title)}, {literal(content_type)}, {literal(size_bytes)}) RETURNING id",
        )
        image_id = res[0][0]
    finally:
        conn.close()

    return jsonify({"ok": True, "id": image_id}), 201

#TODO: Implement pagination and filtering in UI/UX
@api_bp.get("/images")
def list_images():
    page = int(get_param("page", 1))
    limit = int(get_param("limit", 50))
    title = get_param("title", None)
    
    conn = get_conn()
    try:
        total_row = conn.run("SELECT COUNT(*) FROM images")
        total = total_row[0][0]
        rows = conn.run(
            f"SELECT id, filename, title, content_type, size_bytes, created_at FROM images WHERE title={literal(title)} OR {literal(title)} IS NULL ORDER BY id DESC LIMIT {literal(limit)} OFFSET {literal((page - 1) * limit)}",
        )
    finally:
        conn.close()


    items = [
        {
            "id": r[0],
            "filename": r[1],
            "title": r[2],
            "content_type": r[3],
            "size_bytes": r[4],
            "created_at": r[5].isoformat() if r[5] else None,
        }
        for r in rows
    ]
    return jsonify({"ok": True, "items": items, "page": page, "limit": limit, "total": total})


@api_bp.get("/images/<int:image_id>")
def serve_image_by_id(image_id: int):
    conn = get_conn()
    try:
        rows = conn.run(f"SELECT filename, content_type FROM images WHERE id = {literal(image_id)}")
    finally:
        conn.close()
    if not rows:
        return jsonify({"ok": False, "error": "not found"}), 404
    filename, content_type = rows[0][0], rows[0][1]

    if "." not in filename or filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTS:
        return jsonify({"ok": False, "error": "unsupported file type"}), 400
    
    path = Path(current_app.config["UPLOAD_DIR"]) / filename 

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "not found"}), 404
    
    return send_from_directory(current_app.config["UPLOAD_DIR"], filename)
